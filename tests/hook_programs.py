"""Real programs to run as capture hooks, and a way to tell whether a process lives.

A hook is a file the system can start by path: a `#!/bin/sh` launcher on POSIX
and a `.cmd` file on Windows, either one running a Python script from the same
directory. Nothing here replaces `subprocess`.
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import pathlib
import subprocess
import sys
import textwrap
import time
import typing as _ty
from datetime import datetime, timezone
from unittest.mock import MagicMock

from pydhcp import CaptureEvent, DHCPRequestContext, NetworkInterface, SocketAddress
from pydhcp.options import DHCPOptionCode
from helpers import build_request


def python_hook(directory: pathlib.Path, name: str, source: str) -> pathlib.Path:
    """A hook program that runs `source` with this interpreter; the launcher's path.

    `source` runs with its own directory as `HERE` (a `pathlib.Path`), so it can
    leave files where the test looks.
    """
    script = directory / (name + ".py")
    script.write_bytes(
        (
            "import pathlib\nHERE = pathlib.Path(__file__).resolve().parent\n"
            + textwrap.dedent(source)
        ).encode("utf-8")
    )
    if os.name == "nt":
        launcher = directory / (name + ".cmd")
        launcher.write_bytes(f'@"{sys.executable}" "{script}"\r\n'.encode("utf-8"))
    else:
        launcher = directory / name
        launcher.write_bytes(
            f'#!/bin/sh\nexec "{sys.executable}" "{script}"\n'.encode("utf-8")
        )
        launcher.chmod(0o755)
    return launcher


def capture_event(client_id: "_ty.Optional[bytes]" = None, xid: int = 0x12345678):
    """A captured DHCPDISCOVER, with option 61 set when `client_id` is given."""
    message = build_request(xid=xid)
    if client_id is not None:
        message.options[DHCPOptionCode.CLIENT_IDENTIFIER] = client_id
    return CaptureEvent(
        message=message,
        context=DHCPRequestContext(
            transport=MagicMock(),
            interface=NetworkInterface("lo", ipaddress.IPv4Interface("127.0.0.1/24")),
            client=SocketAddress("127.0.0.1", 68),
            client_mac=b"\x00\x11\x22\x33\x44\x55",
            local_ip=ipaddress.IPv4Address("127.0.0.1"),
        ),
        captured_at=datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc),
    )


def alive(pid: int) -> bool:
    """Whether the process `pid` is running (a zombie is not)."""
    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - alive, and not ours
        return True
    state = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)],
        capture_output=True,
        text=True,
    ).stdout.strip()
    return bool(state) and not state.startswith("Z")


def wait_until_dead(pid: int, seconds: float = 15.0) -> bool:
    """Whether `pid` ended within `seconds`."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.1)
    return not alive(pid)


def kill(pid: int) -> None:
    """End `pid` and its children, a test's last resort."""
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, check=False
        )
    else:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


class CliHook(_ty.NamedTuple):
    """A hook program for a `pydhcp capture` process: the command, and the environment it needs."""

    command: str
    #: Extra environment for the process that runs the command; empty on POSIX.
    env: "dict[str, str]"


_SITECUSTOMIZE = """\
import os
import runpy
import sys

# Started with no arguments and nothing else: the program the capture runs as a hook.
# The capture that starts it has arguments and leaves the variable for the hook.
_script = os.environ.get("PYDHCP_TEST_HOOK_SCRIPT") if sys.argv in ([""], []) else None
if _script:
    os.environ.pop("PYDHCP_TEST_HOOK_SCRIPT", None)
    try:
        runpy.run_path(_script, run_name="__main__")
        _code = 0
    except SystemExit as _stop:
        _code = _stop.code if isinstance(_stop.code, int) else int(bool(_stop.code))
    except BaseException:
        import traceback

        traceback.print_exc()
        _code = 1
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_code)
"""


def cli_hook(directory: pathlib.Path, name: str, source: str) -> CliHook:
    """A hook program that runs `source`, for `--hook`; its command and environment.

    pktcap starts a hook by path with no argument and refuses a `.cmd` file. On POSIX
    that is a `#!/bin/sh` launcher beside the script; on Windows there is no such
    launcher, so the program is this interpreter, which with no argument would read
    its script from standard input: a `sitecustomize` module, found through
    `PYTHONPATH`, runs the script first and exits. Either way the script has its own
    directory as `HERE`, a `pathlib.Path`.
    """
    from cli_process import SRC

    script = directory / (name + ".py")
    script.write_bytes(
        (
            "import pathlib\nHERE = pathlib.Path(__file__).resolve().parent\n"
            + textwrap.dedent(source)
        ).encode("utf-8")
    )
    if os.name == "nt":
        site = directory / ("site-" + name)
        site.mkdir(exist_ok=True)
        (site / "sitecustomize.py").write_bytes(_SITECUSTOMIZE.encode("utf-8"))
        return CliHook(
            sys.executable,
            {
                "PYTHONPATH": os.pathsep.join([str(site), SRC]),
                "PYDHCP_TEST_HOOK_SCRIPT": str(script),
            },
        )
    launcher = directory / name
    launcher.write_bytes(
        f'#!/bin/sh\nexec "{sys.executable}" "{script}"\n'.encode("utf-8")
    )
    launcher.chmod(0o755)
    return CliHook(str(launcher), {})
