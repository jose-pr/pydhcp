"""`DHCPCaptureWriter`: one growing file, or one file per record, from the library alone.

Nothing here imports the command line. The octets a record file holds, and the
names the command gives its files, are pinned from the outside by
`tests/test_capture_output.py`.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import logging
import pathlib
import re
import typing as _ty
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pktcap
import pytest

from pydhcp import (
    AsyncDHCPCapture,
    CaptureEvent,
    DHCPCapture,
    DHCPMessage,
    DHCPOptions,
    DHCPRequestContext,
    NetworkInterface,
    SocketAddress,
)
from pydhcp.capture import (
    FILENAME_FIELDS,
    MAX_CAPTURE_FILES,
    UNIQUE_FILENAME_FIELDS,
    DHCPCaptureWriter,
)
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
from ipaddress import IPv4Address as IPv4

from capture_input import short_datagram
from conftest import build_request

HEARD = datetime(2026, 7, 14, 12, 30, 15, tzinfo=timezone.utc)


def _context() -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=MagicMock(),
        interface=NetworkInterface("eth-test", ipaddress.IPv4Interface("192.0.2.1/24")),
        client=SocketAddress("192.0.2.55", 68),
        client_mac=bytes.fromhex("001122334455"),
        local_ip=IPv4("192.0.2.1"),
    )


def _message(
    client_id: bytes = b"\x01\x00\x11\x22\x33\x44\x55",
    xid: int = 0x1234ABCD,
    kind: DHCPMessageType = DHCPMessageType.DHCPDISCOVER,
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = kind
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray(client_id)
    return build_request(options=options, xid=xid)


def _event(
    client_id: bytes = b"\x01\x00\x11\x22\x33\x44\x55",
    xid: int = 0x1234ABCD,
    at: datetime = HEARD,
) -> CaptureEvent:
    return CaptureEvent(_message(client_id, xid), _context(), at)


def _text(event: CaptureEvent, name: str) -> str:
    """What a record of `event` holds: a line of compact JSON, or the message's own text."""
    if name == "json":
        return json.dumps(event.message.to_mapping()) + "\n"
    return event.message.to_text(name)


def _files(directory: pathlib.Path) -> "list[pathlib.Path]":
    return sorted(p for p in directory.rglob("*") if p.is_file())


# -- a stream ------------------------------------------------------------------------


def test_a_stream_gets_one_json_line_a_record() -> None:
    stream = io.BytesIO()

    with DHCPCaptureWriter(stream, "json") as writer:
        writer(_event(xid=1))
        writer(_event(xid=2))

    lines = stream.getvalue().split(b"\n")
    assert lines[2] == b"" and len(lines) == 3
    assert [json.loads(line)["xid"] for line in lines[:2]] == [1, 2]
    assert writer.written == 2 and writer.refused == 0 and writer.format == "json"
    assert b"\r" not in stream.getvalue()


def test_each_record_is_flushed_as_it_is_written() -> None:
    """Piped into `jq` or `tee`, a block-buffered stream showed nothing for ~8 KB or
    until the capture ended, and lost what was buffered when it was killed."""

    class Counting(io.BytesIO):
        flushes = 0

        def flush(self) -> None:
            type(self).flushes += 1

    stream = Counting()
    with DHCPCaptureWriter(stream, "json") as writer:
        for _ in range(3):
            writer(_event())

    assert Counting.flushes >= 3


def test_a_stream_is_the_callers_to_close() -> None:
    stream = io.BytesIO()
    DHCPCaptureWriter(stream, "json").close()
    assert not stream.closed


def test_a_stream_names_no_format_so_one_is_asked_for() -> None:
    with pytest.raises(pktcap.UnsupportedFormatError):
        DHCPCaptureWriter(io.BytesIO())


def test_a_stream_cannot_be_one_file_per_record() -> None:
    with pytest.raises(ValueError):
        DHCPCaptureWriter(io.BytesIO(), "json", per_capture=True)


# -- the format ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "ending, name",
    [
        (".json", "json"),
        (".JSON", "json"),
        (".jsonl", "json"),
        (".ndjson", "json"),
        (".yaml", "yaml"),
        (".yml", "yaml"),
    ],
)
def test_the_ending_of_a_file_names_its_format(
    tmp_path: pathlib.Path, ending: str, name: str
) -> None:
    assert DHCPCaptureWriter(tmp_path / ("caps" + ending)).format == name


@pytest.mark.parametrize("ending, name", [(".toml", "toml"), (".ini", "ini")])
def test_the_ending_names_the_one_file_per_record_formats(
    tmp_path: pathlib.Path, ending: str, name: str
) -> None:
    if name == "toml":
        pytest.importorskip("tomli_w")
    writer = DHCPCaptureWriter(tmp_path / ("{xid}" + ending), per_capture=True)
    assert writer.format == name


def test_an_ending_that_names_no_format_is_refused(tmp_path: pathlib.Path) -> None:
    with pytest.raises(pktcap.UnsupportedFormatError):
        DHCPCaptureWriter(tmp_path / "caps.txt")
    with pytest.raises(pktcap.UnsupportedFormatError):
        DHCPCaptureWriter(tmp_path / "{xid}.{format}", per_capture=True)


@pytest.mark.parametrize("name", ["toml", "ini"])
def test_toml_and_ini_hold_one_record_a_file(name: str, tmp_path: pathlib.Path) -> None:
    """Concatenated records are unreadable in both: TOML has no document separator
    and `configparser` raises on a second section of the same name."""
    if name == "toml":
        pytest.importorskip("tomli_w")
    with pytest.raises(ValueError) as refused:
        DHCPCaptureWriter(tmp_path / ("caps." + name), name)
    assert "per-capture" in str(refused.value) and name in str(refused.value)


def test_toml_without_its_extra_names_the_extra_of_this_library(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(__import__("sys").modules, "tomli_w", None)

    with pytest.raises(ImportError, match=r"pydhcp\[toml\]"):
        DHCPCaptureWriter(tmp_path / "{xid}.toml", "toml", per_capture=True)


# -- a growing file ------------------------------------------------------------------


def test_a_file_is_appended_to_and_its_directories_are_made(
    tmp_path: pathlib.Path,
) -> None:
    target = tmp_path / "deep" / "er" / "caps.json"

    for run in range(2):
        with DHCPCaptureWriter(target) as writer:
            assert run or not target.parent.exists(), "built, so nothing is made yet"
            writer(_event(xid=10 * run + 1))
            writer(_event(xid=10 * run + 2))

    lines = target.read_bytes().split(b"\n")
    assert [json.loads(line)["xid"] for line in lines[:-1]] == [1, 2, 11, 12]
    assert lines[-1] == b""


def test_a_yaml_file_survives_a_second_run(tmp_path: pathlib.Path) -> None:
    """Every document, the first of a run included, is led by `---`: a second run's
    first record used to be written onto the last record of the first, YAML merged
    the two mappings and the earlier record disappeared on load."""
    import yaml

    target = tmp_path / "caps.yaml"
    for _run in range(2):
        with DHCPCaptureWriter(target) as writer:
            writer(_event())
            writer(_event())

    text = target.read_text(encoding="utf-8")
    assert text.startswith("---\n") and text.count("\n---\n") == 3
    assert len([d for d in yaml.safe_load_all(text) if d]) == 4


def test_a_record_is_what_the_message_renders_as(tmp_path: pathlib.Path) -> None:
    event = _event()

    for name, separator in (("json", ""), ("yaml", "---\n")):
        target = tmp_path / ("caps." + name)
        with DHCPCaptureWriter(target) as writer:
            writer(event)
        assert target.read_bytes() == (separator + _text(event, name)).encode("utf-8")


# -- one file per record -------------------------------------------------------------


def test_a_file_per_record_is_named_by_the_pattern(tmp_path: pathlib.Path) -> None:
    pattern = tmp_path / "{client_id}" / "{timestamp}_{msg_type}_{xid}_{index}.{format}"

    with DHCPCaptureWriter(pattern, "json", per_capture=True) as writer:
        writer(_event())
        writer(_event(xid=2, at=HEARD + timedelta(microseconds=123456)))

    names = [p.relative_to(tmp_path).as_posix() for p in _files(tmp_path)]
    assert names == [
        "01_00_11_22_33_44_55/20260714T123015.000000Z_DHCPDISCOVER_1234ABCD_0.json",
        "01_00_11_22_33_44_55/20260714T123015.123456Z_DHCPDISCOVER_00000002_1.json",
    ]
    first = _files(tmp_path)[0].read_bytes()
    assert first == _text(_event(), "json").encode("utf-8")


def test_a_naive_time_is_read_as_utc(tmp_path: pathlib.Path) -> None:
    with DHCPCaptureWriter(
        tmp_path / "{timestamp}.{format}", "json", per_capture=True
    ) as writer:
        writer(_event(at=datetime(2026, 7, 14, 12, 30, 15)))

    assert [p.name for p in _files(tmp_path)] == ["20260714T123015.000000Z.json"]


@pytest.mark.parametrize("name", ["json", "yaml", "toml", "ini"])
def test_a_record_file_holds_the_text_of_the_message(
    tmp_path: pathlib.Path, name: str
) -> None:
    if name == "toml":
        pytest.importorskip("tomli_w")
    event = _event()

    with DHCPCaptureWriter(
        tmp_path / "{xid}.{format}", name, per_capture=True
    ) as writer:
        writer(event)

    (written,) = _files(tmp_path)
    assert written.name == "1234ABCD." + name
    assert written.read_bytes() == _text(event, name).encode("utf-8")


# -- the pattern is checked when the writer is built ---------------------------------


def test_every_documented_field_is_accepted(tmp_path: pathlib.Path) -> None:
    pattern = "_".join("{" + name + "}" for name in FILENAME_FIELDS)
    DHCPCaptureWriter(tmp_path / pattern, "json", per_capture=True).close()


def test_a_format_spec_and_doubled_braces_are_not_fields(
    tmp_path: pathlib.Path,
) -> None:
    DHCPCaptureWriter(
        tmp_path / "{{literal}}-{client_id:>12}.{format}", "json", per_capture=True
    ).close()


@pytest.mark.parametrize(
    "pattern",
    [
        "cap_{mac}.json",  # the measured one: plausible, and not a field
        "cap_{}.json",  # positional
        "cap_{0}.json",
        "cap_{xid.real}.json",  # attribute access
        "cap_{xid:{mac}}.json",  # one level of nesting is resolved too
        "cap_{xid.json",  # malformed
    ],
)
def test_a_placeholder_that_cannot_be_filled_is_refused_before_any_write(
    pattern: str, tmp_path: pathlib.Path
) -> None:
    """With no check each of these built, and raised `KeyError` or `IndexError` from
    the receive handler once for every packet on the segment."""
    with pytest.raises(ValueError):
        DHCPCaptureWriter(tmp_path / pattern, per_capture=True)


def test_the_refusal_names_the_field_and_lists_the_fields(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(ValueError) as refused:
        DHCPCaptureWriter(tmp_path / "cap_{mac}.json", per_capture=True)

    message = str(refused.value)
    assert "{mac}" in message and "not a field" in message
    for name in FILENAME_FIELDS:
        assert "{" + name + "}" in message


def test_a_pattern_naming_no_unique_field_warns_once(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        DHCPCaptureWriter(tmp_path / "{client_id}.{format}", "json", per_capture=True)

    warned = [
        r for r in caplog.records if "only the last one is kept" in r.getMessage()
    ]
    assert len(warned) == 1, caplog.text


@pytest.mark.parametrize("unique", sorted(UNIQUE_FILENAME_FIELDS))
def test_a_pattern_that_tells_packets_apart_does_not_warn(
    unique: str, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        DHCPCaptureWriter(
            tmp_path / ("{" + unique + "}.{format}"), "json", per_capture=True
        )

    assert not caplog.records, caplog.text


def test_a_pattern_naming_no_unique_field_overwrites(tmp_path: pathlib.Path) -> None:
    """The behaviour the warning describes, measured: two packets differing only in
    xid, one file left on disk."""
    with DHCPCaptureWriter(
        tmp_path / "capture.{format}", "json", per_capture=True
    ) as writer:
        writer(_event(xid=0xAAAAAAAA))
        writer(_event(xid=0xBBBBBBBB))

    (only,) = _files(tmp_path)
    assert json.loads(only.read_text(encoding="utf-8"))["xid"] == 0xBBBBBBBB


# -- a value the client chose cannot decide where a file lands ------------------------


class _ForgedIdentityMessage(DHCPMessage):
    """A message whose rendered client identity is attacker-chosen text.

    `DHCPMessage.get_client_id()` hex-encodes option 61, so a real client cannot
    get a `/` or a `..` into it however it crafts the option. This supplies one
    directly, so the guard is tested at the layer that has to hold if the
    identity rendering ever changes.
    """

    forged = ""

    def get_client_id(self, func: _ty.Any = None) -> str:
        return self.forged


def _forged_event(identity: str) -> CaptureEvent:
    message = _ForgedIdentityMessage(**vars(_message()))
    message.forged = identity
    return CaptureEvent(message, _context(), HEARD)


@pytest.mark.parametrize(
    "identity",
    [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "/etc/shadow",
        "a/b/c",
        "....//....//x",
        "..",
        ".",
        "con:aux",
        "\x00nul",
    ],
)
def test_a_client_identity_cannot_escape_the_pattern_directory(
    identity: str, tmp_path: pathlib.Path
) -> None:
    """A client-supplied identity must land in one path segment, never above it."""
    with DHCPCaptureWriter(
        tmp_path / "out" / "id-{client_id}" / "{xid}.{format}",
        "json",
        per_capture=True,
    ) as writer:
        writer(_forged_event(identity))

    (written,) = _files(tmp_path)
    parts = written.relative_to(tmp_path).parts
    assert len(parts) == 3 and parts[0] == "out" and parts[2] == "1234ABCD.json"
    segment = parts[1]
    assert segment.startswith("id-") and "\x00" not in segment
    assert "/" not in segment and "\\" not in segment and ".." not in segment[3:]


def test_a_name_windows_opens_as_a_device_gets_a_leading_underscore(
    tmp_path: pathlib.Path,
) -> None:
    with DHCPCaptureWriter(
        tmp_path / "{client_id}.{format}", "json", per_capture=True
    ) as writer:
        writer(_forged_event("nul"))

    assert [p.name for p in _files(tmp_path)] == ["_nul.json"]


def test_distinct_identities_keep_distinct_names(tmp_path: pathlib.Path) -> None:
    """Without this a sanitizer that returned a constant would satisfy the test above
    and every capture would overwrite the last."""
    with DHCPCaptureWriter(
        tmp_path / "{client_id}.{format}", "json", per_capture=True
    ) as writer:
        writer(_forged_event("../../etc/passwd"))
        writer(_forged_event("../../etc/group"))

    assert [p.name for p in _files(tmp_path)] == ["etc_group.json", "etc_passwd.json"]


def test_a_long_identity_is_cut_and_keeps_a_digest_of_the_whole(
    tmp_path: pathlib.Path,
) -> None:
    """255 octets render as 765 characters, which no filesystem takes as a name."""
    first = bytes([1]) + bytes(range(1, 255))
    second = first[:-1] + bytes([first[-1] ^ 1])
    with DHCPCaptureWriter(
        tmp_path / "{client_id}.{format}", "json", per_capture=True
    ) as writer:
        writer(_event(client_id=first))
        writer(_event(client_id=second))

    names = [p.stem for p in _files(tmp_path)]
    assert len(names) == 2 and all(len(name) == 64 for name in names)
    text = _event(client_id=first).client_id
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    assert f"{cleaned[:55]}-{digest}" in names


# -- the file budget -----------------------------------------------------------------


def test_the_budget_defaults_to_the_documented_constant() -> None:
    assert MAX_CAPTURE_FILES == 1000


def test_a_record_that_needs_a_file_past_the_budget_is_refused_and_counted(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Measured before the bound: 5,000 forged client identifiers produced 5,000
    files, an unauthenticated sender deciding how much of the disk to use."""
    with caplog.at_level(logging.WARNING):
        with DHCPCaptureWriter(
            tmp_path / "{client_id}.{format}", "json", per_capture=True, max_files=20
        ) as writer:
            for index in range(25):
                writer(_event(client_id=b"\xff" + index.to_bytes(4, "big")))

    assert len(_files(tmp_path)) == 20
    assert writer.written == 20 and writer.refused == 5


def test_a_pattern_the_client_cannot_influence_is_not_limited(
    tmp_path: pathlib.Path,
) -> None:
    """A fixed pattern rewrites one file, so the budget must not apply to it: it
    counts distinct paths, not writes."""
    with DHCPCaptureWriter(
        tmp_path / "capture.{format}", "json", per_capture=True
    ) as writer:
        for index in range(MAX_CAPTURE_FILES + 200):
            writer(_event(client_id=b"\xff" + index.to_bytes(4, "big")))

    assert [p.name for p in _files(tmp_path)] == ["capture.json"]
    assert writer.refused == 0


def test_a_budget_below_one_is_refused(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ValueError):
        DHCPCaptureWriter(
            tmp_path / "{xid}.{format}", "json", per_capture=True, max_files=0
        )


# -- as a sink -----------------------------------------------------------------------


@pytest.mark.parametrize("capture_class", [DHCPCapture, AsyncDHCPCapture])
def test_the_writer_is_the_sink_of_a_capture(
    capture_class: _ty.Any, tmp_path: pathlib.Path
) -> None:
    target = tmp_path / "caps.json"
    per_record = tmp_path / "each" / "{xid}.{format}"
    with (
        DHCPCaptureWriter(target) as growing,
        DHCPCaptureWriter(per_record, "json", per_capture=True) as each,
    ):
        for sink in (growing, each):
            capture = capture_class(
                listen=("127.0.0.1", 6767),
                packet_filter="msg_type=DHCPDISCOVER",
                sink=sink,
            )
            capture.handle(_message(), _context())
            capture.handle(_message(kind=DHCPMessageType.DHCPOFFER), _context())

    assert growing.written == each.written == 1
    assert len(target.read_bytes().splitlines()) == 1
    assert [p.name for p in _files(tmp_path / "each")] == ["1234ABCD.json"]


# -- a capture file ------------------------------------------------------------------


def _heard(
    payload: "_ty.Optional[bytes]", xid: int = 0x1234ABCD, at: datetime = HEARD
) -> CaptureEvent:
    context = _context()._replace(payload=payload)
    return CaptureEvent(_message(xid=xid), context, at)


@pytest.mark.parametrize("name", ["pcap", "pcapng"])
def test_a_capture_file_holds_the_datagrams_as_they_arrived(
    tmp_path: pathlib.Path, name: str
) -> None:
    """A datagram is written as the client sent it, not as the message encodes: the
    short one is below the 300 octets `encode` pads to."""
    short = short_datagram()
    padded = bytes(_message().encode())
    assert len(short) < len(padded)
    target = tmp_path / ("caps." + name)

    with DHCPCaptureWriter(target, name) as writer:
        writer(_heard(short, xid=1))
        writer(_heard(padded, xid=2, at=HEARD + timedelta(seconds=2)))

    assert writer.format == name and writer.written == 2 and writer.refused == 0
    read = list(pktcap.read_datagrams(target))
    assert [d.payload for d in read] == [short, padded]
    assert [d.source for d in read] == [("192.0.2.55", 68)] * 2
    assert [d.time for d in read] == [
        HEARD.timestamp(),
        (HEARD + timedelta(seconds=2)).timestamp(),
    ]


@pytest.mark.parametrize(
    "ending, name", [(".pcap", "pcap"), (".CAP", "pcap"), (".pcapng", "pcapng")]
)
def test_the_ending_of_a_file_names_a_capture_format(
    tmp_path: pathlib.Path, ending: str, name: str
) -> None:
    assert DHCPCaptureWriter(tmp_path / ("caps" + ending)).format == name


def test_a_capture_file_goes_to_a_stream() -> None:
    stream = io.BytesIO()

    with DHCPCaptureWriter(stream, "pcap") as writer:
        writer(_heard(short_datagram()))

    (read,) = pktcap.read_datagrams(io.BytesIO(stream.getvalue()))
    assert read.payload == short_datagram()
    assert not stream.closed


def test_a_capture_file_replaces_what_it_finds(tmp_path: pathlib.Path) -> None:
    """A capture cannot be appended to: a second run starts a new file."""
    target = tmp_path / "caps.pcap"
    for _run in range(2):
        with DHCPCaptureWriter(target) as writer:
            writer(_heard(short_datagram()))

    assert len(list(pktcap.read_datagrams(target))) == 1


def test_a_capture_file_per_record(tmp_path: pathlib.Path) -> None:
    pattern = tmp_path / "{xid}.{format}"

    with DHCPCaptureWriter(pattern, "pcapng", per_capture=True) as writer:
        writer(_heard(short_datagram(), xid=1))
        writer(_heard(short_datagram(), xid=2))

    names = [p.name for p in _files(tmp_path)]
    assert names == ["00000001.pcapng", "00000002.pcapng"]
    for path in _files(tmp_path):
        (read,) = pktcap.read_datagrams(path)
        assert read.payload == short_datagram()


@pytest.mark.parametrize("name", ["pcap", "pcapng"])
def test_a_capture_file_refuses_an_event_that_has_no_octets(
    tmp_path: pathlib.Path, name: str
) -> None:
    """A message put back together is not the packet that arrived, so there is
    nothing true to write."""
    target = tmp_path / ("caps." + name)

    with DHCPCaptureWriter(target, name) as writer:
        with pytest.raises(ValueError, match="payload"):
            writer(_event())

    assert writer.written == 0 and not target.exists()


def test_a_record_file_needs_no_octets(tmp_path: pathlib.Path) -> None:
    with DHCPCaptureWriter(tmp_path / "caps.json") as writer:
        writer(_event())
        writer(_heard(short_datagram()))

    assert writer.written == 2
