"""Reading a capture file as events, and sending its requests again.

The input is the fixed set of `tests/data/capture_output/build.py`, written to a pcap
with pktcap's own writer, so what a test expects is the octets it wrote.
"""

from __future__ import annotations

import io
import pathlib
import subprocess
import sys
import typing as _ty

import pktcap
import pytest

from capture_input import build, datagrams
from cli_process import environment, free_port, run_cli
from driving import serve, wait_for
from pydhcp import CaptureEvent, DHCPCapture, DHCPMessage
from pydhcp.capture import capture_dissector, read_capture, replay_capture

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


# -- read_capture --------------------------------------------------------------------


def test_every_message_of_a_capture_is_an_event_in_file_order(
    pcap: pathlib.Path,
) -> None:
    sent = datagrams()

    events = list(read_capture(pcap))

    assert [e.payload for e in events] == sent
    assert [e.message.xid for e in events] == [DHCPMessage.decode(d).xid for d in sent]
    for number, event in enumerate(events):
        assert event.context is None
        assert event.captured_at.timestamp() == pytest.approx(START + number * 0.5)
        request = _is_request(sent[number])
        assert (str(event.source.ip), event.source.port) == (
            CLIENT if request else SERVER
        )
        assert (str(event.destination.ip), event.destination.port) == (
            SERVER if request else CLIENT
        )


def test_the_filter_selects_by_what_the_message_and_the_datagram_say(
    pcap: pathlib.Path,
) -> None:
    sent = datagrams()
    discovers = [
        d for d in sent if DHCPMessage.decode(d).message_type.name == "DHCPDISCOVER"
    ]

    found = [
        e.payload for e in read_capture(pcap, packet_filter="msg_type=DHCPDISCOVER")
    ]
    replies = [e for e in read_capture(pcap, packet_filter="src_port=67")]

    assert found == discovers
    assert replies and all(e.source.port == 67 for e in replies)
    assert list(read_capture(pcap, packet_filter=lambda event: False)) == []


def test_the_interface_key_fails_for_an_event_that_heard_nothing(
    pcap: pathlib.Path,
) -> None:
    assert list(read_capture(pcap, packet_filter="interface=eth0")) == []
    assert len(list(read_capture(pcap, packet_filter="interface!=eth0"))) == 53


def test_a_port_the_capture_does_not_use_selects_nothing(pcap: pathlib.Path) -> None:
    assert list(read_capture(pcap, ports=(6767,))) == []


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
    frames = capture_dissector()

    events = list(read_capture(target, dissector=frames))

    assert [e.payload for e in events] == [good]
    assert frames.stats.frames == 4 and frames.stats.malformed == 2
    assert frames.stats.failed == 0


def test_a_frame_of_a_link_type_nothing_reads_is_counted_not_hidden(
    tmp_path: pathlib.Path,
) -> None:
    target = tmp_path / "odd.pcap"
    with pktcap.PcapWriter(target) as writer:
        writer.write_frame(pktcap.CapturedFrame(1.0, 105, b"\x00" * 40))
    frames = capture_dissector()

    assert list(read_capture(target, dissector=frames)) == []
    assert frames.unsupported_linktypes == {105: 1}


def test_a_capture_cut_in_the_middle_gives_the_events_before_the_cut_then_raises(
    pcap: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    whole = pcap.read_bytes()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(whole[: len(whole) // 2])
    seen: "list[CaptureEvent]" = []

    with pytest.raises(pktcap.CaptureFormatError):
        for event in read_capture(cut):
            seen.append(event)

    assert 0 < len(seen) < 53
    assert [e.payload for e in seen] == datagrams()[: len(seen)]


def test_a_stream_is_read_like_a_path(pcap: pathlib.Path) -> None:
    events = list(read_capture(io.BytesIO(pcap.read_bytes())))
    assert [e.payload for e in events] == datagrams()


def test_a_time_that_is_no_time_is_the_epoch(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "t.pcap"
    with pktcap.PcapWriter(target) as writer:
        writer.write(0.0, CLIENT, SERVER, datagrams()[0])

    (event,) = read_capture(target)

    assert event.captured_at.timestamp() == 0.0


# -- the command ---------------------------------------------------------------------


def _command(*argv: str) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(
        [sys.executable, "-m", "pydhcp", *argv],
        capture_output=True,
        env=environment(),
        stdin=subprocess.DEVNULL,
        timeout=120,
    )


def test_capture_read_prints_what_listening_printed_octet_for_octet(
    pcap: pathlib.Path,
) -> None:
    expected = (build.EXPECTED / "stdout_json.out").read_bytes()

    done = _command("capture", "--read", str(pcap), "--format", "json")

    assert done.returncode == 0, done.stderr
    assert done.stdout == expected
    assert done.stderr == b""


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
        "capture", "--read", str(pcap), "--filter", "src_port=68", "--count", "3"
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


def test_a_capture_cut_in_the_middle_prints_the_records_before_it_and_exits_2(
    pcap: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    whole = pcap.read_bytes()
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
    assert "1 cut short or damaged" in note and "105" in note and str(target) in note


def test_a_hook_runs_for_each_event_of_a_file(
    pcap: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    from hook_programs import python_hook

    hook = python_hook(
        tmp_path,
        "count",
        """
        import sys
        sys.stdin.buffer.read()
        with open(HERE / "runs.txt", "a") as out:
            out.write("x")
        """,
    )

    done = _command("capture", "--read", str(pcap), "--hook", str(hook), "--count", "4")

    assert done.returncode == 0, done.stderr
    assert (tmp_path / "runs.txt").read_text() == "xxxx"


def _failing_hook(directory: pathlib.Path) -> pathlib.Path:
    from hook_programs import python_hook

    return python_hook(
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
    done = _command(
        "capture",
        "--read",
        str(pcap),
        "--hook",
        str(_failing_hook(tmp_path)),
        "--count",
        "3",
    )

    assert done.returncode == 0, done.stderr
    assert len(done.stdout.splitlines()) == 3


def test_a_failing_hook_ends_the_read_under_fail_fast(
    pcap: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    done = _command(
        "capture",
        "--read",
        str(pcap),
        "--hook",
        str(_failing_hook(tmp_path)),
        "--hook-fail-fast",
    )

    assert done.returncode == 1
    assert len(done.stdout.splitlines()) == 1
    assert b"hook failed" in done.stderr


# -- replay --------------------------------------------------------------------------


def _receive(count: int, send: "_ty.Callable[[int], object]") -> "list[bytes]":
    """What a capture on a loopback port hears while `send(port)` runs."""
    heard: "list[CaptureEvent]" = []
    capture = DHCPCapture(listen=("127.0.0.1", 0), sink=heard.append)

    def exercise(port: int) -> None:
        send(port)
        wait_for(lambda: len(heard) >= count, f"{count} datagrams to be heard")

    serve(capture, exercise, None)
    return [e.payload or b"" for e in heard]


def test_a_replay_sends_the_requests_in_order_and_no_reply(
    pcap: pathlib.Path,
) -> None:
    sent = datagrams()
    requests = [d for d in sent if _is_request(d)]
    assert 0 < len(requests) < len(sent)
    results: "list[pktcap.ReplayResult]" = []

    heard = _receive(
        len(requests),
        lambda port: results.append(
            replay_capture(pcap, "127.0.0.1", port, speed=None)
        ),
    )

    assert heard == requests
    assert results[0].sent == len(requests) and results[0].partial == 0


def test_the_addresses_in_the_capture_are_never_sent_to(tmp_path: pathlib.Path) -> None:
    """The capture says 10.0.0.1, which a loopback test host cannot reach: what arrives
    on the caller's address proves where the datagram went."""
    target = tmp_path / "one.pcap"
    _write(target, datagrams()[:1])
    results: "list[pktcap.ReplayResult]" = []
    heard = _receive(
        1,
        lambda port: results.append(
            replay_capture(target, "127.0.0.1", port, speed=None)
        ),
    )

    assert len(heard) == 1 and results[0].sent == 1


def test_a_limit_ends_the_replay(pcap: pathlib.Path) -> None:
    results: "list[pktcap.ReplayResult]" = []

    heard = _receive(
        2,
        lambda port: results.append(
            replay_capture(pcap, "127.0.0.1", port, speed=None, limit=2)
        ),
    )

    assert len(heard) == 2 and results[0].sent == 2


def test_the_recorded_waits_are_kept_unless_removed(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "slow.pcap"
    with pktcap.PcapWriter(target) as writer:
        for number in range(3):
            writer.write(START + number, CLIENT, SERVER, datagrams()[0])
    import time

    results: "list[pktcap.ReplayResult]" = []
    took: "list[float]" = []

    def send(port: int) -> None:
        began = time.monotonic()
        results.append(replay_capture(target, "127.0.0.1", port, speed=10.0))
        took.append(time.monotonic() - began)

    _receive(3, send)

    assert results[0].sent == 3 and 0.15 <= took[0] < 5


def test_the_command_replays_and_prints_the_counts(pcap: pathlib.Path) -> None:
    requests = [d for d in datagrams() if _is_request(d)]
    heard: "list[CaptureEvent]" = []
    capture = DHCPCapture(listen=("127.0.0.1", 0), sink=heard.append)
    outcome: "list[_ty.Any]" = []

    def exercise(port: int) -> None:
        outcome.append(
            run_cli(
                "replay",
                "--input",
                str(pcap),
                "--server",
                f"127.0.0.1:{port}",
                "--no-delay",
            )
        )
        wait_for(lambda: len(heard) >= len(requests), "the requests to be heard")

    serve(capture, exercise, None)

    done = outcome[0]
    assert done.returncode == 0, done.stderr
    assert (
        done.stdout.strip() == f"{len(requests)} datagrams sent, 0 partial passed over"
    )
    assert [e.payload for e in heard] == requests


def test_the_command_needs_a_server(pcap: pathlib.Path) -> None:
    done = run_cli("replay", "--input", str(pcap))

    assert done.returncode == 2 and "--server" in done.stderr


def test_the_command_names_a_file_that_is_not_a_capture(tmp_path: pathlib.Path) -> None:
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture file at all, not even a little")

    done = run_cli(
        "replay", "--input", str(junk), "--server", f"127.0.0.1:{free_port()}"
    )

    assert done.returncode == 2 and str(junk) in done.stderr
