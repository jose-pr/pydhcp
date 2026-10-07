"""`pydhcp.capture.command_hook`: a capture hook that runs a program.

Each test runs a real program from `tmp_path`: it prints bytes that are not
UTF-8, outlives its time limit with a child of its own, reads what it is given.
What a hook is given comes from datagrams any sender can craft, so it is
passed on standard input and in the environment, never as an argument and never
through a shell.
"""

from __future__ import annotations

import inspect
import json
import logging
import pathlib
import re
import time

import pytest

from hook_programs import capture_event, kill, python_hook, wait_until_dead
from pydhcp import DHCPError, DHCPHookError, DHCPTimeoutError
from pydhcp.capture import HOOK_TIMEOUT_SECONDS, command_hook

NOISE = r"""
import sys
sys.stdout.buffer.write(b"\x81\xff\xfe out\n")
sys.stderr.buffer.write(b"\x81\xff\xfe err\n")
sys.exit(3)
"""

RECORD = r"""
import json, os, sys
(HERE / "argv.json").write_text(json.dumps(sys.argv[1:]))
(HERE / "stdin.txt").write_bytes(sys.stdin.buffer.read())
(HERE / "env.json").write_text(json.dumps({k: v for k, v in os.environ.items() if k.startswith("PYDHCP_CAPTURE_")}))
"""

CHILD = r"""
import os, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
(HERE / "child.pid").write_text(str(child.pid))
(HERE / "parent.pid").write_text(str(os.getpid()))
time.sleep(120)
"""


def test_a_program_that_prints_bytes_outside_utf8_does_not_break_the_hook(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    program = python_hook(tmp_path, "noise", NOISE)

    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        command_hook(str(program))(capture_event())

    failure = [r for r in caplog.records if "command failed" in r.getMessage()]
    assert len(failure) == 1
    assert "(3)" in failure[0].getMessage()
    assert "\\ufffd" in failure[0].getMessage()  # replaced, then escaped for the log


def test_a_failing_hook_with_fail_fast_raises_the_packages_error(
    tmp_path: pathlib.Path,
) -> None:
    program = python_hook(tmp_path, "noise", NOISE)

    with pytest.raises(DHCPHookError) as raised:
        command_hook(str(program), fail_fast=True)(capture_event())

    assert isinstance(raised.value, DHCPError)
    assert not isinstance(raised.value, RuntimeError)
    assert "exit code 3" in str(raised.value) and "noise" in str(raised.value)


def test_standard_error_is_bounded_in_the_error_and_the_log(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    program = python_hook(
        tmp_path,
        "loud",
        'import sys\nsys.stderr.write("x" * 100000 + "TAIL")\nsys.exit(1)\n',
    )

    with caplog.at_level(logging.ERROR, logger="pydhcp"):
        with pytest.raises(DHCPHookError) as raised:
            command_hook(str(program), fail_fast=True)(capture_event())

    assert len(str(raised.value)) < 1000
    assert str(raised.value).endswith("TAIL") or "TAIL" in str(raised.value)
    assert all(len(r.getMessage()) < 1000 for r in caplog.records)


def test_the_streams_are_logged_by_size_never_by_content(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    program = python_hook(
        tmp_path, "secret", 'print("SECRET-PAYLOAD")\nimport sys\nsys.stdin.read()\n'
    )

    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        command_hook(str(program))(capture_event())

    text = " ".join(r.getMessage() for r in caplog.records)
    assert "SECRET-PAYLOAD" not in text
    assert re.search(r"wrote \d+ characters to stdout and 0 to stderr", text)


def test_a_failure_is_logged_once_per_interval_with_a_bounded_line(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    program = python_hook(
        tmp_path,
        "boom",
        'import sys\nsys.stderr.write("boom\\n" * 200)\nsys.exit(3)\n',
    )
    hook = command_hook(str(program))

    with caplog.at_level(logging.ERROR, logger="pydhcp"):
        for _ in range(3):
            hook(capture_event())

    failures = [r for r in caplog.records if "command failed" in r.getMessage()]
    assert len(failures) == 1
    assert "\n" not in failures[0].getMessage()
    assert len(failures[0].getMessage()) < 600
    assert failures[0].name == "pydhcp.capture._command"


def test_a_program_that_outlives_the_limit_is_killed_with_its_children(
    tmp_path: pathlib.Path,
) -> None:
    program = python_hook(tmp_path, "sleeper", CHILD)
    hook = command_hook(str(program), timeout=5.0)
    pids: "list[int]" = []
    started = time.monotonic()
    try:
        with pytest.raises(DHCPTimeoutError) as raised:
            hook(capture_event())
        # The limit, then the kill: not however long the program's children live.
        assert time.monotonic() - started < 30
        pids = [
            int((tmp_path / name).read_text())
            for name in ("child.pid", "parent.pid")
            if (tmp_path / name).exists()
        ]
        assert len(pids) == 2, "the hook had not started its child in time"
        for pid in pids:
            assert wait_until_dead(pid), f"process {pid} outlived its hook"
    finally:
        for pid in pids:
            kill(pid)

    assert isinstance(raised.value, TimeoutError)
    assert not isinstance(raised.value, RuntimeError)
    assert "killed" in str(raised.value)


def test_a_hook_is_given_the_packet_on_stdin_and_nothing_as_an_argument(
    tmp_path: pathlib.Path,
) -> None:
    program = python_hook(tmp_path, "record", RECORD)

    command_hook(str(program), packet_format="json")(capture_event())

    assert json.loads((tmp_path / "argv.json").read_text()) == []
    assert json.loads((tmp_path / "stdin.txt").read_text())["xid"] == 0x12345678
    env = json.loads((tmp_path / "env.json").read_text())
    assert env == {
        "PYDHCP_CAPTURE_CLIENT_ID": "01:00:11:22:33:44:55",
        "PYDHCP_CAPTURE_MSG_TYPE": "DHCPDISCOVER",
        "PYDHCP_CAPTURE_XID": "12345678",
        "PYDHCP_CAPTURE_FORMAT": "json",
    }


def test_a_client_identifier_holding_shell_metacharacters_reaches_no_shell(
    tmp_path: pathlib.Path,
) -> None:
    """The identifier is chosen by the sender. It is rendered as hex in the
    environment and reaches the program by no other route than standard input."""
    canary = tmp_path / "pwned"
    nasty = b"$(touch " + str(canary).encode() + b"); `touch " + str(canary).encode()
    nasty += b"` | & > < ; \n\"'"
    directory = tmp_path / "dir with spaces & more"
    directory.mkdir()
    program = python_hook(directory, "record", RECORD)

    command_hook(str(program))(capture_event(client_id=nasty))

    assert not canary.exists()
    assert json.loads((directory / "argv.json").read_text()) == []
    env = json.loads((directory / "env.json").read_text())
    assert re.fullmatch(r"[0-9A-F:]+", env["PYDHCP_CAPTURE_CLIENT_ID"])
    assert bytes.fromhex(env["PYDHCP_CAPTURE_CLIENT_ID"].replace(":", "")) == nasty


def test_the_time_limit_is_an_argument_whose_default_is_the_documented_constant() -> (
    None
):
    parameters = inspect.signature(command_hook).parameters
    assert parameters["timeout"].default == HOOK_TIMEOUT_SECONDS == 10.0
    assert parameters["timeout"].kind is inspect.Parameter.KEYWORD_ONLY


@pytest.mark.parametrize("timeout", [0, -1, float("nan")])
def test_a_time_limit_that_is_not_positive_is_refused(
    tmp_path: pathlib.Path, timeout: float
) -> None:
    program = python_hook(tmp_path, "noop", "pass\n")
    with pytest.raises(ValueError, match="timeout"):
        command_hook(str(program), timeout=timeout)


def test_the_command_is_found_before_anything_runs(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        command_hook(str(tmp_path / "absent"))
    with pytest.raises(ValueError, match="not on PATH"):
        command_hook("pydhcp-no-such-program-anywhere")


def test_the_timeout_constant_is_in_the_shipped_header() -> None:
    header = pathlib.Path(__file__).resolve().parents[2] / "src" / "pydhcp"
    text = (header / "AGENTS.md").read_text(encoding="utf-8")
    assert "HOOK_TIMEOUT_SECONDS" in text and "command_hook" in text
