"""`pydhcp capture` writing a capture file: the datagrams, octet for octet.

Each case runs the command as a process on a loopback port, sends it the fixed
input of `tests/data/capture_output/build.py` and reads the file back with
pktcap's own reader.
"""

from __future__ import annotations

import io
import json
import pathlib

import pktcap
import pytest

from capture_input import build, datagrams, short_datagram
from hook_programs import python_hook
from pydhcp import DHCPMessage


def _input() -> "list[bytes]":
    """The 53 fixed datagrams, with one that has no padding after its end option."""
    return [*datagrams(), short_datagram()]


@pytest.mark.parametrize("name", ["pcap", "pcapng"])
def test_the_file_holds_the_datagrams_the_client_sent(
    tmp_path: pathlib.Path, name: str
) -> None:
    sent = _input()
    target = tmp_path / ("heard." + name)

    done = build.run(
        ["--format", name, "--output", str(target), "--count", str(len(sent))], sent
    )

    assert done.status == 0, done.stderr
    read = list(pktcap.read_datagrams(target))
    assert [d.payload for d in read] == sent
    assert min(len(d.payload) for d in read) == len(short_datagram()) < 300
    assert {d.source[0] for d in read} == {"127.0.0.1"}
    assert {d.destination[1] for d in read} == {read[0].destination[1]} != {0}


@pytest.mark.parametrize("ending, name", [(".pcap", "pcap"), (".pcapng", "pcapng")])
def test_the_ending_of_the_file_names_the_format(
    tmp_path: pathlib.Path, ending: str, name: str
) -> None:
    sent = _input()[:3]
    target = tmp_path / "nested" / ("heard" + ending)

    done = build.run(["--output", str(target), "--count", "3"], sent)

    assert done.status == 0, done.stderr
    assert [d.payload for d in pktcap.read_datagrams(target)] == sent
    magic = target.read_bytes()[:4]
    assert (magic == b"\n\r\r\n") is (name == "pcapng")


def test_standard_output_is_a_capture_file() -> None:
    sent = _input()[:4]

    done = build.run(["--format", "pcap", "--count", "4"], sent)

    assert done.status == 0, done.stderr
    assert [d.payload for d in pktcap.read_datagrams(io.BytesIO(done.stdout))] == sent


def test_a_file_for_each_datagram(tmp_path: pathlib.Path) -> None:
    sent = _input()[:3]
    pattern = tmp_path / "{index}_{xid}.{format}"

    done = build.run(
        [
            "--output",
            str(pattern),
            *build.PER_CAPTURE,
            "--format",
            "pcap",
            "--count",
            "3",
        ],
        sent,
    )

    assert done.status == 0, done.stderr
    files = sorted(tmp_path.iterdir())
    assert len(files) == 3
    assert [[d.payload for d in pktcap.read_datagrams(path)] for path in files] == [
        [data] for data in sent
    ]


def test_a_hook_is_given_json_and_told_so(tmp_path: pathlib.Path) -> None:
    hook = python_hook(
        tmp_path,
        "keep",
        """
        import os
        import sys

        (HERE / "stdin.txt").write_bytes(sys.stdin.buffer.read())
        (HERE / "format.txt").write_text(os.environ["PYDHCP_CAPTURE_FORMAT"])
        """,
    )
    sent = _input()[:1]

    done = build.run(
        [
            "--format",
            "pcap",
            "--output",
            str(tmp_path / "heard.pcap"),
            "--hook",
            str(hook),
            "--count",
            "1",
        ],
        sent,
    )

    assert done.status == 0, done.stderr
    assert (tmp_path / "format.txt").read_text() == "json"
    record = json.loads((tmp_path / "stdin.txt").read_text(encoding="utf-8"))
    assert record["xid"] == DHCPMessage.decode(sent[0]).xid
