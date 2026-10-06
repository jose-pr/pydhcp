"""A capture hook that runs a program: `command_hook`.

The program gets the captured packet on standard input and four `PYDHCP_CAPTURE_*`
variables in a copy of the environment; nothing a sender chose is an argument or
reaches a shell. Every run is bounded, and when it runs past the bound the program
and the processes it started are killed.
"""

from __future__ import annotations

import logging as _logging
import os as _os
import pathlib as _pathlib
import shutil as _shutil
import signal as _signal
import subprocess as _subprocess
import sys
import time as _time
import typing as _ty

from ..exceptions import DHCPHookError, DHCPTimeoutError
from ..listener._limit import _brief, _LogLimit
from ._events import CaptureEvent, CaptureHook, serialize_event

LOGGER = _logging.getLogger(__name__)

#: How long a command hook may run, in seconds, before it is killed and the run
#: is a `DHCPTimeoutError`. The hook runs on the receive thread, so without a
#: bound a hanging one (a network export, say) stops packets being read at all.
HOOK_TIMEOUT_SECONDS = 10.0

#: Seconds to wait for a killed program's pipes to drain.
_REAP_SECONDS = 5.0

#: Longest stretch of a failed program's standard error an error or a log line carries.
_STDERR_OCTETS = 400


def resolve_command(command: str) -> _pathlib.Path:
    """The absolute path of a hook command, found once, when it is loaded.

    A name with a directory part (`./hook`, `/usr/bin/hook`, `sub/hook`) is that
    file, taken relative to the working directory *now*; a name with none (`hook`)
    is looked up on PATH, as a shell would. Running the absolute path means
    `./hook` is never handed to the system as the bare `hook`, which POSIX
    searches on PATH alone, and survives a later change of working directory.
    `ValueError` for a command that does not exist, is not a file, or is not
    executable (POSIX).
    """
    if "/" in command or "\\" in command:
        path = _pathlib.Path(_os.path.abspath(command))
        if not path.exists():
            raise ValueError(f"Capture hook command does not exist: {command}")
    else:
        found = _shutil.which(command)
        if found is None:
            raise ValueError(
                f"Capture hook command {command!r} is not on PATH; a file in the "
                f"working directory is named with a path, e.g. ./{command}"
            )
        path = _pathlib.Path(_os.path.abspath(found))
    if not path.is_file():
        raise ValueError(f"Capture hook command is not a file: {command}")
    if _os.name == "posix" and not _os.access(path, _os.X_OK):
        raise ValueError(f"Capture hook command is not executable: {command}")
    return path


def _kill_tree(process: "_subprocess.Popen[bytes]") -> None:
    """Kill `process` and everything it started."""
    if sys.platform == "win32":
        root = _os.environ.get("SystemRoot", r"C:\Windows")
        taskkill = _os.path.join(root, "System32", "taskkill.exe")
        try:
            _subprocess.run(
                [taskkill, "/F", "/T", "/PID", str(process.pid)],
                stdin=_subprocess.DEVNULL,
                stdout=_subprocess.DEVNULL,
                stderr=_subprocess.DEVNULL,
                timeout=_REAP_SECONDS,
                check=False,
            )
        except (OSError, _subprocess.TimeoutExpired):
            pass
    else:
        try:
            # The program leads its own session (see `_run`), so its group is
            # exactly the tree to kill.
            _os.killpg(process.pid, _signal.SIGKILL)
        except OSError:
            pass
    try:
        process.kill()
    except OSError:
        pass


def _run(
    path: _pathlib.Path, payload: bytes, env: "_ty.Mapping[str, str]", timeout: float
) -> "tuple[int, str, str]":
    """Run `path` with `payload` on standard input; its status and both streams.

    An argument list with no arguments, never a shell. The streams are decoded as
    UTF-8 with `errors="replace"`, whatever the platform's own encoding is.
    `DHCPTimeoutError` once `timeout` seconds have passed, after the program and its
    children are killed.
    """
    # `sys.platform` is tested here, not through a variable, so a type checker
    # narrows each branch to the platform that has the option.
    if sys.platform == "win32":
        process = _subprocess.Popen(
            [str(path)],
            stdin=_subprocess.PIPE,
            stdout=_subprocess.PIPE,
            stderr=_subprocess.PIPE,
            env=dict(env),
            creationflags=_subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    else:
        process = _subprocess.Popen(
            [str(path)],
            stdin=_subprocess.PIPE,
            stdout=_subprocess.PIPE,
            stderr=_subprocess.PIPE,
            env=dict(env),
            start_new_session=True,
        )
    try:
        out, err = process.communicate(payload, timeout=timeout)
    except _subprocess.TimeoutExpired:
        _kill_tree(process)
        try:
            process.communicate(timeout=_REAP_SECONDS)
        except _subprocess.TimeoutExpired:  # pragma: no cover - a pipe held open
            pass
        raise DHCPTimeoutError(
            f"capture hook command {path} ran past {timeout:g} seconds and was killed"
        ) from None
    except BaseException:
        _kill_tree(process)
        process.wait()
        raise
    return (
        process.returncode,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
    )


def command_hook(
    command: str,
    *,
    packet_format: str = "json",
    timeout: float = HOOK_TIMEOUT_SECONDS,
    fail_fast: bool = False,
) -> CaptureHook:
    """A capture hook that runs `command` once for each captured packet.

    `command` is found now (`resolve_command`: a name with a directory is that
    file, a bare name is looked up on PATH) and run by its absolute path, with no
    arguments and no shell. It reads the packet on standard input in
    `packet_format` (`json` is one compact line; `yaml`, `toml` and `ini` are
    `DHCPMessage.to_text`), and its environment is a copy of this process's plus
    `PYDHCP_CAPTURE_CLIENT_ID` (colon-separated upper-case hex, or `UNKNOWN`),
    `PYDHCP_CAPTURE_MSG_TYPE`, `PYDHCP_CAPTURE_XID` (eight hex digits) and
    `PYDHCP_CAPTURE_FORMAT`.

    Each run is bounded by `timeout` seconds (`ValueError` unless positive): past
    it the program and its children are killed and the hook raises
    `DHCPTimeoutError`. A non-zero exit is logged at ERROR, at most once a minute
    however often it happens, with the status and the tail of standard error; with
    `fail_fast` it also raises `DHCPHookError`. The sizes of the two streams are
    logged at DEBUG, never their contents.
    """
    if not timeout > 0:
        raise ValueError(f"timeout must be above 0 seconds, got {timeout!r}")
    path = resolve_command(command)
    failures = _LogLimit()

    def hook(event: CaptureEvent) -> None:
        payload = serialize_event(event, packet_format).encode("utf-8", "replace")
        env = _os.environ.copy()
        env.update(
            {
                "PYDHCP_CAPTURE_CLIENT_ID": event.client_id,
                "PYDHCP_CAPTURE_MSG_TYPE": event.message_type,
                "PYDHCP_CAPTURE_XID": event.xid,
                "PYDHCP_CAPTURE_FORMAT": packet_format,
            }
        )
        status, out, err = _run(path, payload, env, timeout)
        LOGGER.debug(
            "Capture hook command wrote %d characters to stdout and %d to stderr",
            len(out),
            len(err),
        )
        if status == 0:
            return
        tail = err.strip()[-_STDERR_OCTETS:]
        failures.log(
            LOGGER,
            _logging.ERROR,
            "command hook failed",
            "Capture hook command failed (%s): %s",
            status,
            _brief(tail, _STDERR_OCTETS),
            now=_time.monotonic(),
        )
        if fail_fast:
            raise DHCPHookError(
                f"capture hook command {path} failed with exit code {status}: "
                f"{_brief(tail, _STDERR_OCTETS)}"
            )

    return hook
