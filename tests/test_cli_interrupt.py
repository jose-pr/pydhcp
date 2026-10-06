"""Ctrl-C ends the three serving commands cleanly.

The library installs no signal handler, so the interrupt reaches the command as
`KeyboardInterrupt` out of `serve_forever()` and the command closes what it
opened. Each command runs in its own process with a real signal: SIGINT on
POSIX, and on Windows a console break event delivered to a new process group,
which the child turns into the same `KeyboardInterrupt` Ctrl-C raises.
"""

from __future__ import annotations

import signal
import subprocess
import sys
import textwrap
import threading
import typing as _ty

import pytest

_WRAPPER = """
import signal
import sys

import pydhcp.listener._sync as sync

serve = sync.DHCPListener.serve_forever


def announced(self):
    print("serving", flush=True)
    serve(self)


sync.DHCPListener.serve_forever = announced
if sys.platform == "win32":
    signal.signal(signal.SIGBREAK, signal.default_int_handler)
sys.argv[0] = "pydhcp"
from pydhcp.cli import main

raise SystemExit(main())
"""

COMMANDS = {
    "server": ["server", "-v", "--listen", "127.0.0.1:0"],
    "relay": ["relay", "-v", "-l", "127.0.0.1:0", "-s", "127.0.0.1:6767"],
    "capture": ["capture", "-v", "-l", "127.0.0.1:0"],
}


def _interrupt(proc: "subprocess.Popen[str]") -> None:
    if sys.platform == "win32":
        proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
    else:
        proc.send_signal(signal.SIGINT)


@pytest.mark.parametrize("command", sorted(COMMANDS))
def test_ctrl_c_stops_the_command_with_status_zero_and_no_traceback(
    command: str, tmp_path: _ty.Any
) -> None:
    script = tmp_path / "run.py"
    script.write_bytes(textwrap.dedent(_WRAPPER).encode("utf-8"))
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0  # type: ignore[attr-defined]
    proc = subprocess.Popen(
        [sys.executable, str(script), *COMMANDS[command]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=flags,
    )
    try:
        # A watchdog, so a command that never prints cannot hang the suite.
        watchdog = threading.Timer(30.0, proc.kill)
        watchdog.start()
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "serving", "the command did not start"
        try:
            _interrupt(proc)
        except (OSError, ValueError) as error:  # pragma: no cover - no console
            pytest.skip(f"cannot deliver a console signal here: {error}")
        stdout, stderr = proc.communicate(timeout=20)
        watchdog.cancel()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert proc.returncode == 0, (proc.returncode, stdout, stderr)
    assert "Traceback" not in stderr, stderr
    assert "Stopped listening due to Ctrl-C" in stderr + stdout
