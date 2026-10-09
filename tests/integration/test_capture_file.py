"""Reading a capture file through the DHCP dissector, and the commands that read one.

The input is the fixed set of `tests/data/capture_output/build.py`, written to a pcap
with pktcap's own writer, so what a test expects is the octets it wrote.
"""

from __future__ import annotations

import io
import pathlib
import subprocess
import sys
import typing as _ty

import pytest

pktcap = pytest.importorskip("pktcap")

from capture_input import build, datagrams
from cli_process import environment, free_port, run_cli
from pydhcp import DHCPMessage
from pydhcp.capture import DHCPLayer, capture_dissector

CLIENT = ("10.0.0.2", 68)
SERVER = ("10.0.0.1", 67)
START = 1_700_000_000.0


def _is_request(data: bytes) -> bool:
    return data[0] == 1


def _write(
    path: pathlib.Path, sent: "_ty.Sequence[bytes]", *, extra: bool = False
) -> "list[_ty.Tuple[float, _ty.Tuple[str, int], _ty.Tuple[str, int], bytes]]":
    """A pcap of `sent`: requests client to server, replies server to client."""
    items = []
    for number, data in enumerate(sent):
        src, dst = (CLIENT, SERVER) if _is_request(data) else (SERVER, CLIENT)
        items.append((START + number * 0.5, src, dst, data))
    with pktcap.PcapWriter(path) as writer:
        for item in items:
            writer.write(*item)
    return items


@pytest.fixture
def pcap(tmp_path: pathlib.Path) -> pathlib.Path:
    _write(tmp_path / "all.pcap", datagrams())
    return tmp_path / "all.pcap"


@pytest.fixture
def recorded(tmp_path: pathlib.Path) -> pathlib.Path:
    """The capture file the recorded output was made from."""
    build.capture_file(tmp_path / "recorded.pcap", datagrams())
    return tmp_path / "recorded.pcap"


# -- a capture file read through the dissector of the DHCP plugin --------------------


def _frames(
    source: _ty.Any, dissector: "pktcap.FrameDissector"
) -> "list[pktcap.DissectedFrame]":
    return list(pktcap.read_dissected(source, dissector=dissector))


def test_every_message_of_a_capture_is_a_dhcp_frame_in_file_order(
    pcap: pathlib.Path,
) -> None:
    sent = datagrams()

    frames = _frames(pcap, capture_dissector())

    assert [f.datagram().payload for f in frames] == sent  # type: ignore[union-attr]
    for number, frame in enumerate(frames):
        layer = frame.layers[-1]
        assert isinstance(layer, DHCPLayer)
        assert layer.xid == DHCPMessage.decode(sent[number]).xid
        assert frame.time == pytest.approx(START + number * 0.5)
        datagram = frame.datagram()
        assert datagram is not None
        request = _is_request(sent[number])
        assert datagram.source == (CLIENT if request else SERVER)
        assert datagram.destination == (SERVER if request else CLIENT)


def test_a_port_the_capture_does_not_use_reads_no_message(pcap: pathlib.Path) -> None:
    frames = _frames(pcap, capture_dissector(ports=(6767,)))

    assert len(frames) == 53
    assert all(f.layer(DHCPLayer) is None for f in frames)


def test_what_could_not_be_read_is_the_dissectors_counters(
    tmp_path: pathlib.Path,
) -> None:
    target = tmp_path / "mixed.pcap"
    good = datagrams()[0]
    with pktcap.PcapWriter(target) as writer:
        writer.write(1.0, CLIENT, SERVER, good)
        writer.write(2.0, CLIENT, SERVER, b"not dhcp at all")
        writer.write(3.0, ("10.0.0.2", 4000), ("10.0.0.1", 9999), good)  # no DHCP port
        writer.write(4.0, CLIENT, SERVER, good[:100])
    reader = capture_dissector()

    frames = _frames(target, reader)

    messages = [f.datagram().payload for f in frames if isinstance(f.layers[-1], DHCPLayer)]  # type: ignore[union-attr]
    assert messages == [good]
    assert reader.stats.frames == 4 and reader.stats.malformed == 2
    assert reader.stats.failed == 0


def test_a_frame_of_a_link_type_nothing_reads_is_counted_not_hidden(
    tmp_path: pathlib.Path,
) -> None:
    target = tmp_path / "odd.pcap"
    with pktcap.PcapWriter(target) as writer:
        writer.write_frame(pktcap.CapturedFrame(1.0, 105, b"\x00" * 40))
    reader = capture_dissector()

    frames = _frames(target, reader)

    assert all(f.layer(DHCPLayer) is None for f in frames)
    assert reader.unsupported_linktypes == {105: 1}


def test_a_capture_cut_in_the_middle_gives_the_frames_before_the_cut_then_raises(
    pcap: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    whole = pcap.read_bytes()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(whole[: len(whole) // 2])
    seen: "list[pktcap.DissectedFrame]" = []

    with pytest.raises(pktcap.CaptureFormatError):
        for frame in pktcap.read_dissected(cut, dissector=capture_dissector()):
            seen.append(frame)

    assert 0 < len(seen) < 53
    assert [f.datagram().payload for f in seen] == datagrams()[: len(seen)]  # type: ignore[union-attr]


def test_a_stream_is_read_like_a_path(pcap: pathlib.Path) -> None:
    frames = _frames(io.BytesIO(pcap.read_bytes()), capture_dissector())

    assert [f.datagram().payload for f in frames] == datagrams()  # type: ignore[union-attr]


# -- the command ---------------------------------------------------------------------


def _command(
    *argv: str, env: "_ty.Optional[_ty.Mapping[str, str]]" = None
) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(
        [sys.executable, "-m", "pydhcp", *argv],
        capture_output=True,
        env=environment(env),
        stdin=subprocess.DEVNULL,
        timeout=120,
    )


def test_capture_read_prints_the_recorded_octets(recorded: pathlib.Path) -> None:
    expected = (build.EXPECTED / "stdout_json.out").read_bytes()

    done = _command("capture", "--read", str(recorded), "--format", "json")

    assert done.returncode == 0, done.stderr
    assert done.stdout == expected
    assert done.stderr.decode().splitlines() == ["53 frames read, 53 written"]


def test_capture_read_writes_a_capture_file_with_the_same_datagrams(
    pcap: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    out = tmp_path / "out.pcapng"

    done = _command("capture", "--read", str(pcap), "--output", str(out))

    assert done.returncode == 0, done.stderr
    assert [d.payload for d in pktcap.read_datagrams(out)] == datagrams()
    assert [d.source for d in pktcap.read_datagrams(out)] == [
        CLIENT if _is_request(d) else SERVER for d in datagrams()
    ]


def test_capture_read_takes_the_filter_and_the_count(pcap: pathlib.Path) -> None:
    done = _command(
        "capture", "--read", str(pcap), "--filter", "sport=68", "--count", "3"
    )

    assert done.returncode == 0, done.stderr
    assert len(done.stdout.splitlines()) == 3


def test_capture_read_reads_standard_input(pcap: pathlib.Path) -> None:
    done = subprocess.run(
        [sys.executable, "-m", "pydhcp", "capture", "--read", "-"],
        input=pcap.read_bytes(),
        capture_output=True,
        env=environment(),
        timeout=120,
    )

    assert done.returncode == 0, done.stderr
    assert len(done.stdout.splitlines()) == 53


def test_capture_read_does_not_listen(pcap: pathlib.Path) -> None:
    done = run_cli("capture", "--read", str(pcap), "--listen", "127.0.0.1:6767")

    assert done.returncode == 2
    assert "--read" in done.stderr and "--listen" in done.stderr
    assert "not allowed" in done.stderr


def test_a_capture_cut_in_the_middle_prints_the_records_before_it_and_exits_2(
    recorded: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    whole = recorded.read_bytes()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(whole[: len(whole) // 2])

    done = _command("capture", "--read", str(cut))

    assert done.returncode == 2
    lines = done.stdout.splitlines()
    assert 0 < len(lines) < 53
    assert (
        lines
        == (build.EXPECTED / "stdout_json.out").read_bytes().splitlines()[: len(lines)]
    )
    assert str(cut).encode() in done.stderr


def test_a_capture_that_is_not_one_exits_2_naming_the_file(
    tmp_path: pathlib.Path,
) -> None:
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture file at all, not even a little")

    done = _command("capture", "--read", str(junk))

    assert done.returncode == 2 and done.stdout == b""
    assert str(junk).encode() in done.stderr


def test_a_read_that_missed_frames_says_so_in_one_line(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "mixed.pcapng"
    with pktcap.PcapngWriter(target) as writer:
        writer.write(1.0, CLIENT, SERVER, datagrams()[0])
        writer.write(2.0, CLIENT, SERVER, b"not dhcp at all")
        writer.write_frame(pktcap.CapturedFrame(3.0, 105, b"\x00" * 40))

    done = _command("capture", "--read", str(target))

    assert done.returncode == 0
    assert len(done.stdout.splitlines()) == 1
    (note,) = done.stderr.decode().splitlines()
    assert note == (
        "3 frames read, 1 written, 2 skipped, 1 malformed, "
        "1 of an unsupported link type (105)"
    )


def test_a_hook_runs_for_each_event_of_a_file(
    pcap: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    from hook_programs import cli_hook

    hook = cli_hook(
        tmp_path,
        "count",
        """
        import sys
        sys.stdin.buffer.read()
        with open(HERE / "runs.txt", "a") as out:
            out.write("x")
        """,
    )

    done = _command(
        "capture",
        "--read",
        str(pcap),
        "--hook",
        hook.command,
        "--count",
        "4",
        env=hook.env,
    )

    assert done.returncode == 0, done.stderr
    assert (tmp_path / "runs.txt").read_text() == "xxxx"


def _failing_hook(directory: pathlib.Path) -> "_ty.Any":
    from hook_programs import cli_hook

    return cli_hook(
        directory,
        "fails",
        """
        import sys
        sys.stdin.buffer.read()
        sys.stderr.write("refused")
        raise SystemExit(3)
        """,
    )


def test_a_failing_hook_is_logged_and_the_read_goes_on(
    pcap: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    hook = _failing_hook(tmp_path)

    done = _command(
        "capture",
        "--read",
        str(pcap),
        "--hook",
        hook.command,
        "--count",
        "3",
        env=hook.env,
    )

    assert done.returncode == 0, done.stderr
    assert len(done.stdout.splitlines()) == 3
    assert b"3 hook failures" in done.stderr


def test_a_failing_hook_ends_the_read_under_fail_fast(
    pcap: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    hook = _failing_hook(tmp_path)

    done = _command(
        "capture",
        "--read",
        str(pcap),
        "--hook",
        hook.command,
        "--hook-fail-fast",
        env=hook.env,
    )

    assert done.returncode == 1
    assert len(done.stdout.splitlines()) == 1
    assert b"refused" in done.stderr


# -- replay ---------------------------------------------------------------------


def test_the_command_needs_a_destination(pcap: pathlib.Path) -> None:
    done = run_cli("replay", "--input", str(pcap))

    assert done.returncode == 2 and "--to" in done.stderr


def test_the_command_needs_a_capture() -> None:
    done = run_cli("replay", "--to", "127.0.0.1:6767")

    assert done.returncode == 2 and "--input" in done.stderr


def test_the_command_names_a_file_that_is_not_a_capture(tmp_path: pathlib.Path) -> None:
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture file at all, not even a little")

    done = run_cli("replay", "--input", str(junk), "--to", f"127.0.0.1:{free_port()}")

    assert done.returncode == 2 and str(junk) in done.stderr
