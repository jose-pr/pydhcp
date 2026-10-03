"""Loading a `pydhcp capture --hook`: a Python callable or an executable."""

from __future__ import annotations

import contextlib
import importlib
import json as _json
import pathlib
import os
import subprocess
import sys
import typing as _ty

from ..capture import CaptureEvent
from ..packet.structured import dump_message
from ._common import LOGGER


def _serialize_capture_event(event: CaptureEvent, packet_format: str) -> str:
    """One captured message in `packet_format` -- what a record file holds and
    what a command hook reads on stdin. Lives here, not in `capture`, so the
    two modules import in one direction only."""
    if packet_format == "json":
        return _json.dumps(event.message.to_mapping()) + "\n"
    return dump_message(event.message, packet_format)


#: How long a command hook may run before it is treated as a failure. The hook
#: runs on the receive thread, so without a bound a hanging one (a network
#: export, say) stops packets being read at all, with nothing logged.
HOOK_TIMEOUT_SECONDS = 10.0


@contextlib.contextmanager
def _cwd_on_sys_path() -> "_ty.Iterator[None]":
    """Make `--hook myhooks:on_capture` work from the installed console script.

    A console script's `sys.path[0]` is its own Scripts directory, not the
    working directory, so the form the docs show could not import a module
    sitting next to the user.
    """
    cwd = os.getcwd()
    added = cwd not in sys.path
    if added:
        sys.path.insert(0, cwd)
    try:
        yield
    finally:
        if added:
            try:
                sys.path.remove(cwd)
            except ValueError:  # pragma: no cover - someone else removed it
                pass


def _load_capture_hook(
    hook: "str | None", packet_format: str, fail_fast: bool
) -> "_ty.Callable[[CaptureEvent], None] | None":
    if not hook:
        return None
    hook_path = pathlib.Path(hook)
    # A module reference is `package.module:function` -- never contains a path
    # separator. Deciding on the separator rather than on ':' alone keeps
    # "C:\hooks\export.exe" a path on every platform: it has exactly one ':', so
    # it used to be read as module "C" and reported as "No module named 'C'",
    # and splitdrive alone would only have fixed that on Windows.
    looks_like_path = "/" in hook or "\\" in hook or hook_path.exists()
    if not looks_like_path and hook.count(":") == 1:
        module_name, function_name = hook.split(":", 1)
        with _cwd_on_sys_path():
            module = importlib.import_module(module_name)
        function = getattr(module, function_name, None)
        if not callable(function):
            raise ValueError(f"Capture hook {hook!r} does not resolve to a callable")
        return _ty.cast(_ty.Callable[[CaptureEvent], None], function)
    if not hook_path.exists():
        raise ValueError(f"Capture hook command does not exist: {hook}")
    if not hook_path.is_file():
        raise ValueError(f"Capture hook command is not a file: {hook}")

    def command_hook(event: CaptureEvent) -> None:
        payload = _serialize_capture_event(event, packet_format)
        env = os.environ.copy()
        env.update(
            {
                "PYDHCP_CAPTURE_CLIENT_ID": event.client_id,
                "PYDHCP_CAPTURE_MSG_TYPE": event.message_type,
                "PYDHCP_CAPTURE_XID": event.xid,
                "PYDHCP_CAPTURE_FORMAT": packet_format,
            }
        )
        try:
            result = subprocess.run(
                [str(hook_path)],
                input=payload,
                text=True,
                capture_output=True,
                env=env,
                timeout=HOOK_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as expired:
            # The hook runs on the receive thread, so without this a hanging one
            # stops packets being read at all and nothing says why.
            raise RuntimeError(
                f"Capture hook command timed out after {HOOK_TIMEOUT_SECONDS}s: "
                f"{hook_path}"
            ) from expired
        if result.stdout:
            LOGGER.debug("Capture hook command output: %s", result.stdout.strip())
        if result.returncode != 0:
            LOGGER.error(
                "Capture hook command failed (%s): %s",
                result.returncode,
                result.stderr.strip(),
            )
            if fail_fast:
                raise RuntimeError(
                    f"Capture hook command failed with exit code {result.returncode}"
                )

    return command_hook
