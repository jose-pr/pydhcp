"""Every command line the documentation shows runs as written.

`--help` is no check: argparse exits 0 on it before it reports an unknown flag, so
each documented line goes through the real parser first. The README's lines then
run as processes against loopback, with only the example addresses, ports and
files substituted, each with a timeout.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import socket
import subprocess
import sys
import time
import typing as _ty

import pktcap
import pytest

from cli_process import Running, free_port, run_cli
from conftest import build_request
from pydhcp.cli import App
from pydhcp.options import DHCPOptionCode

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DOCUMENTS = [
    README,
    *sorted((ROOT / "docs").glob("*.md")),
    *sorted((ROOT / "src" / "pydhcp").rglob("AGENTS.md")),
]


def _commands(path: pathlib.Path) -> "list[str]":
    """Each `pydhcp ...` line inside a fenced block of `path`."""
    lines = []
    inside = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        text = raw.strip()
        if text.startswith("```"):
            inside = not inside
        elif inside and text.startswith("pydhcp "):
            lines.append(text)
    return lines


DOCUMENTED = [
    pytest.param(line, id=f"{path.name}:{line}")
    for path in DOCUMENTS
    for line in _commands(path)
]


def test_the_documents_have_command_lines_to_check() -> None:
    assert len(DOCUMENTED) >= 30
    verbs = {
        shlex.split(p.values[0], comments=True)[1]  # type: ignore[union-attr]
        for p in DOCUMENTED
    }
    assert {"interfaces", "packet", "server", "relay", "capture"} <= verbs


@pytest.mark.parametrize("line", DOCUMENTED)
def test_a_documented_command_line_is_accepted_by_the_parser(
    line: str, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = shlex.split(line, comments=True)[1:]
    if "--help" in argv or "-h" in argv:
        pytest.skip("--help exits before the parser reports what it does not know")

    try:
        App._parser_().parse_args(argv)
    except SystemExit as stop:
        pytest.fail(f"rejected ({stop.code}): {line}\n{capsys.readouterr().err}")


def test_no_document_spells_the_loglevel_option_with_an_equals_sign() -> None:
    """`--loglevel` takes `[NAME:]LEVEL`; the `KEY=VALUE` form is refused."""
    offenders = [
        f"{path.name}: {text.strip()}"
        for path in DOCUMENTS
        for text in path.read_text(encoding="utf-8").splitlines()
        if re.search(r"--loglevel\s+[\w.]+=", text)
    ]
    assert offenders == []


# -- the README's lines, as processes ------------------------------------------------

README_LINES = _commands(README)
SERVING = ("server", "capture")


def _packet_hex() -> str:
    return bytes(build_request(xid=0x1234ABCD).encode()).hex()


def _discover(client_id: bytes = b"\x01\xaa\xbb") -> bytes:
    message = build_request(xid=0x1234ABCD)
    message.options[DHCPOptionCode.CLIENT_IDENTIFIER] = client_id
    return bytes(message.encode())


def _prepare(directory: pathlib.Path, ports: "dict[str, int]") -> None:
    """The files the README's lines name, in the working directory."""
    (directory / "config.json").write_text(
        json.dumps({"server": {"listen": "127.0.0.1:%d" % ports["config"]}}),
        encoding="utf-8",
    )
    (directory / "packet.json").write_text(
        build_request(xid=0x1234ABCD).to_text("json"), encoding="utf-8"
    )
    marker = "hook-ran.txt"
    if os.name == "nt":
        (directory / "on-dhcp-capture.cmd").write_bytes(
            f'@echo off\r\nfindstr "^" > {marker}\r\n'.encode()
        )
    else:
        hook = directory / "on-dhcp-capture"
        hook.write_bytes(f"#!/bin/sh\ncat > {marker}\n".encode())
        hook.chmod(0o755)


def _arguments(line: str, ports: "dict[str, int]") -> "list[str]":
    """The line's arguments with the example ports pointed at free ones.

    Only substitutions: each `127.0.0.1:<port>` becomes a port nothing holds, and
    on Windows the hook file the README calls `./on-dhcp-capture` is a `.cmd`
    file, because Windows starts a program by its extension.
    """
    text = line.split("pydhcp", 1)[1]
    seen: "dict[str, str]" = {}

    def point(found: "re.Match[str]") -> str:
        return seen.setdefault(found.group(1), "127.0.0.1:%d" % free_port())

    text = re.sub(r"127\.0\.0\.1:(\d+)", point, text)
    for name, value in zip(("first", "second"), seen.values()):
        ports[name] = int(value.rsplit(":", 1)[1])
    arguments = shlex.split(text, comments=True)
    if os.name == "nt":
        arguments = [a + ".cmd" if a == "./on-dhcp-capture" else a for a in arguments]
    return arguments


def _wait_for(check: "_ty.Callable[[], bool]", seconds: float = 15.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.1)
    return check()


@pytest.mark.parametrize("line", README_LINES)
def test_a_readme_command_line_runs_as_written(
    line: str, tmp_path: pathlib.Path
) -> None:
    ports: "dict[str, int]" = {"config": free_port()}
    _prepare(tmp_path, ports)
    arguments = _arguments(line, ports)
    if "--help" in arguments:
        pytest.skip("--help is not a run")
    verb = arguments[0]

    if verb not in SERVING:
        stdin = _packet_hex() if "--decode" in arguments else ""
        done = run_cli(*arguments, input=stdin, cwd=tmp_path, timeout=60)
        assert done.returncode == 0, done.stderr
        assert "Traceback" not in done.stderr and "error:" not in done.stderr
        if "--output" in arguments:
            assert (tmp_path / arguments[arguments.index("--output") + 1]).exists()
        elif verb == "packet" and "--decode" in arguments:
            assert done.stdout.strip(), "a decoded packet prints something"
        return

    command = Running(*arguments, cwd=tmp_path)
    try:
        command.listening()
        assert command.process.poll() is None, "\n".join(command.stderr)
        if verb == "capture":
            port = ports.get("first") or ports["config"]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
                out.sendto(_discover(), ("127.0.0.1", port))
            if "--hook" in arguments:
                assert _wait_for(lambda: (tmp_path / "hook-ran.txt").exists())
            elif "--per-capture" in arguments:
                assert _wait_for(
                    lambda: any(p.is_file() for p in (tmp_path / "output").rglob("*"))
                )
            elif arguments[arguments.index("--output") + 1].endswith(".pcap"):
                target = tmp_path / arguments[arguments.index("--output") + 1]
                assert _wait_for(
                    lambda: target.exists() and len(list(pktcap.read_datagrams(target)))
                )
                assert [d.payload for d in pktcap.read_datagrams(target)] == [
                    _discover()
                ]
            else:
                assert _wait_for(lambda: any(l.startswith("{") for l in command.stdout))
                assert json.loads(command.stdout[0])["xid"] == 0x1234ABCD
        assert command.process.poll() is None, "\n".join(command.stderr)
    finally:
        command.kill()
        for thread in command._threads:
            thread.join(10)
    text = "\n".join(command.stderr)
    assert "Traceback" not in text and "error:" not in text, text


def test_the_python_dash_m_form_is_the_one_the_lines_are_run_with() -> None:
    done = subprocess.run(
        [sys.executable, "-m", "pydhcp", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0 and "usage: pydhcp" in done.stdout
