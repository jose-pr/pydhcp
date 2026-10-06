"""What `pydhcp capture` does at its bounds and when a record cannot be written.

A capture that silently stops recording and exits 0 is the defect: a full file
budget ends the run with status 1 and says how many records were refused, and a
record that cannot be written ends it with status 1 and one line. Each case runs
the command as a process against a loopback port nothing else holds and
sends it real datagrams.
"""

from __future__ import annotations

import os
import pathlib
import socket
import stat

import pytest

from cli_process import Running, free_port, run_cli
from conftest import build_request
from pydhcp.capture._events import _sanitize_filename_value
from pydhcp.options import DHCPOptionCode


def _discover(client_id: bytes, xid: int) -> bytes:
    message = build_request(xid=xid)
    message.options[DHCPOptionCode.CLIENT_IDENTIFIER] = client_id
    return bytes(message.encode())


def _send(port: int, *datagrams: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
        for datagram in datagrams:
            out.sendto(datagram, ("127.0.0.1", port))


def _files(directory: pathlib.Path) -> "list[pathlib.Path]":
    return sorted(p for p in directory.rglob("*") if p.is_file())


# -- a value in a filename is bounded ------------------------------------------------


def test_a_long_value_is_cut_and_keeps_a_hash_so_two_long_values_differ() -> None:
    first = _sanitize_filename_value("a" * 300)
    second = _sanitize_filename_value("a" * 299 + "b")

    assert len(first) == len(second) == 64
    assert first != second
    assert first == _sanitize_filename_value("a" * 300)


@pytest.mark.parametrize(
    "value, cleaned",
    [
        ("", "unknown"),
        ("..", "unknown"),
        ("x", "x"),
        ("01:AA:BB", "01_AA_BB"),
        ("a" * 64, "a" * 64),
    ],
)
def test_a_short_value_is_unchanged_by_the_bound(value: str, cleaned: str) -> None:
    assert _sanitize_filename_value(value) == cleaned


def test_a_long_client_identifier_is_recorded(tmp_path: pathlib.Path) -> None:
    """255 octets render as 765 characters, which no filesystem takes as a name."""
    long_id = bytes([1]) + bytes(range(1, 255))
    port = free_port()
    command = Running(
        "capture",
        "-v",
        "--listen",
        "127.0.0.1:%d" % port,
        "--output",
        str(tmp_path / "{client_id}_{xid}.{format}"),
        "--output-mode",
        "per-capture",
        "--format",
        "json",
        "--count",
        "2",
    )
    command.listening()
    _send(port, _discover(long_id, 1), _discover(long_id, 2))

    assert command.finish() == 0, "\n".join(command.stderr)
    names = [p.name for p in _files(tmp_path)]
    assert len(names) == 2
    assert all(len(name) < 100 for name in names), names


# -- a full file budget ends the run -------------------------------------------------


def test_a_full_file_budget_ends_the_capture_with_status_one_and_says_so(
    tmp_path: pathlib.Path,
) -> None:
    port = free_port()
    command = Running(
        "capture",
        "-v",
        "--listen",
        "127.0.0.1:%d" % port,
        "--output",
        str(tmp_path / "{client_id}.{format}"),
        "--output-mode",
        "per-capture",
        "--format",
        "json",
        "--max-files",
        "2",
    )
    command.listening()
    _send(port, *(_discover(bytes([1, n]), n) for n in range(1, 5)))

    assert command.finish() == 1, "\n".join(command.stderr)
    assert len(_files(tmp_path)) == 2
    last = command.stderr[-1]
    assert last.startswith("pydhcp: error: capture stopped:")
    assert "--max-files" in last and "2 files" in last
    assert "refused" in last and "Traceback" not in "\n".join(command.stderr)


def test_the_file_budget_defaults_to_the_documented_constant() -> None:
    from pydhcp.cli import MAX_PER_CAPTURE_FILES, App

    parsed = App._parser_().parse_args(["capture"])
    assert parsed.max_files is None
    assert MAX_PER_CAPTURE_FILES == 1000


@pytest.mark.parametrize("value", ["0", "-1"])
def test_a_budget_that_is_not_positive_is_a_wrong_invocation(
    tmp_path: pathlib.Path, value: str
) -> None:
    done = run_cli(
        "capture",
        "--output",
        str(tmp_path / "{xid}.{format}"),
        "--output-mode",
        "per-capture",
        "--max-files",
        value,
    )
    assert done.returncode == 2
    assert "--max-files" in done.stderr


def test_the_budget_only_applies_to_one_file_per_packet(tmp_path: pathlib.Path) -> None:
    done = run_cli(
        "capture", "--output", str(tmp_path / "all.json"), "--max-files", "5"
    )

    assert done.returncode == 2
    assert "--max-files" in done.stderr and "per-capture" in done.stderr


def test_the_help_names_the_limit() -> None:
    done = run_cli("capture", "--help")
    assert "--max-files" in done.stdout
    assert "1000" in done.stdout


# -- a target that cannot be written ---------------------------------------------------


def test_an_output_that_is_a_directory_is_refused_before_binding(
    tmp_path: pathlib.Path,
) -> None:
    target = tmp_path / "adir"
    target.mkdir()

    done = run_cli("capture", "-v", "--listen", "127.0.0.1:0", "--output", str(target))

    assert done.returncode == 2
    assert "Listening on" not in done.stderr
    lines = done.stderr.splitlines()
    assert len(lines) == 1 and "adir" in lines[0], done.stderr
    assert "Traceback" not in done.stderr


def test_an_output_that_is_a_read_only_file_is_refused_before_binding(
    tmp_path: pathlib.Path,
) -> None:
    target = tmp_path / "locked.json"
    target.write_text("", encoding="utf-8")
    os.chmod(target, stat.S_IREAD)
    try:
        if os.access(target, os.W_OK):
            pytest.skip("the file is writable anyway (running as root)")
        done = run_cli(
            "capture", "-v", "--listen", "127.0.0.1:0", "--output", str(target)
        )
    finally:
        os.chmod(target, stat.S_IREAD | stat.S_IWRITE)

    assert done.returncode == 2
    assert "Listening on" not in done.stderr
    assert "locked.json" in done.stderr and "Traceback" not in done.stderr


def test_a_record_that_cannot_be_written_ends_the_capture_with_one_line(
    tmp_path: pathlib.Path,
) -> None:
    """The directory the pattern names is a file: the first record cannot be written,
    and the run used to carry on forever, a traceback per packet, never reaching
    `--count`."""
    (tmp_path / "blocked").write_text("a file, not a directory", encoding="utf-8")
    port = free_port()
    command = Running(
        "capture",
        "-v",
        "--listen",
        "127.0.0.1:%d" % port,
        "--output",
        str(tmp_path / "blocked" / "{xid}.{format}"),
        "--output-mode",
        "per-capture",
        "--format",
        "json",
        "--count",
        "5",
    )
    command.listening()
    _send(port, _discover(b"\x01\xaa", 1))

    assert command.finish() == 1, "\n".join(command.stderr)
    text = "\n".join(command.stderr)
    assert "Traceback" not in text
    last = command.stderr[-1]
    assert last.startswith("pydhcp: error: capture stopped: cannot write")
    assert "blocked" in last


def test_a_stream_to_a_closed_file_ends_the_capture_too(
    tmp_path: pathlib.Path,
) -> None:
    """A single file that stops being writable after the probe is the same failure."""
    target = tmp_path / "all.json"
    port = free_port()
    command = Running(
        "capture",
        "-v",
        "--listen",
        "127.0.0.1:%d" % port,
        "--output",
        str(target),
        "--count",
        "3",
    )
    command.listening()
    target.unlink()
    target.mkdir()
    _send(port, _discover(b"\x01\xbb", 1))

    assert command.finish() == 1, "\n".join(command.stderr)
    assert command.stderr[-1].startswith("pydhcp: error: capture stopped: cannot write")


def test_a_capture_that_reaches_its_count_still_exits_zero(
    tmp_path: pathlib.Path,
) -> None:
    port = free_port()
    command = Running(
        "capture",
        "-v",
        "--listen",
        "127.0.0.1:%d" % port,
        "--output",
        str(tmp_path / "all.json"),
        "--count",
        "2",
    )
    command.listening()
    _send(port, _discover(b"\x01\xcc", 1), _discover(b"\x01\xcd", 2))

    assert command.finish() == 0, "\n".join(command.stderr)
    assert len((tmp_path / "all.json").read_text(encoding="utf-8").splitlines()) == 2
