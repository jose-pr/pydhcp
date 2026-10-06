"""DHCP as a pktcap layer: the dissector keeps pktcap's contract and reads a capture.

The expected values come from the octets of the recorded datagrams, read here with a
few lines of option walking, not from `DHCPMessage`.
"""

from __future__ import annotations

import json
import pathlib
import typing as _ty

import pktcap
import pytest

from capture_input import build
from pydhcp.capture import (
    DHCPLayer,
    compile_capture_filter,
    dissect_dhcp,
    register_dhcp_dissector,
)

CASES = pathlib.Path(__file__).parent / "conformance" / "cases"


def _recorded() -> "list[_ty.Tuple[str, str, bytes]]":
    """Every recorded datagram as (source, destination, octets), in order."""
    found = []
    for path in sorted(CASES.glob("*/case.json")):
        for d in json.loads(path.read_text(encoding="utf-8"))["datagrams"]:
            found.append((d["src"], d["dst"], bytes.fromhex(d["payload"])))
    return found


def _option(data: bytes, wanted: int) -> "_ty.Optional[bytes]":
    """The value of option `wanted`, walked from the octets after the magic cookie."""
    at = 240
    while at < len(data) and data[at] != 255:
        if data[at] == 0:
            at += 1
            continue
        code, length = data[at], data[at + 1]
        if code == wanted:
            return data[at + 2 : at + 2 + length]
        at += 2 + length
    return None


def _split(address: str) -> "_ty.Tuple[str, int]":
    host, port = address.rsplit(":", 1)
    return host, int(port)


SAMPLES = [data for _src, _dst, data in _recorded()]


def test_there_are_fifty_recorded_datagrams() -> None:
    assert len(SAMPLES) == 50


def test_the_dissector_keeps_the_contract() -> None:
    pktcap.check_dissector(dissect_dhcp, SAMPLES, rounds=300)


@pytest.mark.parametrize("data", SAMPLES, ids=range(len(SAMPLES)))
def test_the_layer_holds_what_the_octets_say(data: bytes) -> None:
    kinds = {
        1: "DHCPDISCOVER",
        2: "DHCPOFFER",
        3: "DHCPREQUEST",
        4: "DHCPDECLINE",
        5: "DHCPACK",
        6: "DHCPNAK",
        7: "DHCPRELEASE",
        8: "DHCPINFORM",
    }
    kind = _option(data, 53)
    identity = _option(data, 61)

    result = dissect_dhcp(data)

    layer = result.layer
    assert isinstance(layer, DHCPLayer)
    assert layer.op == {1: "BOOTREQUEST", 2: "BOOTREPLY"}[data[0]]
    assert layer.xid == int.from_bytes(data[4:8], "big")
    assert kind is not None
    assert layer.message_type == kinds[kind[0]]
    # No option 61: the identity is the hardware type and address (RFC 2131 s4.2).
    if identity is None:
        identity = data[1:2] + data[28 : 28 + data[2]]
    assert layer.client_id == ":".join(f"{b:02X}" for b in identity)
    assert layer.message["xid"] == layer.xid
    assert result.payload == b"" and result.next == ()


def test_octets_that_are_not_a_message_are_refused_without_quoting_them() -> None:
    data = bytearray(SAMPLES[0])
    data[236:240] = b"\xde\xad\xbe\xef"  # the magic cookie

    with pytest.raises(pktcap.DissectError) as refused:
        dissect_dhcp(bytes(data))

    assert str(refused.value) == "not a DHCP message"
    for short in (b"", b"\x01", bytes(data[:100])):
        with pytest.raises(ValueError):
            dissect_dhcp(short)


def test_registering_takes_both_ports_and_only_where_asked() -> None:
    mine = pktcap.DissectorRegistry()
    other = pktcap.DissectorRegistry()

    register_dhcp_dissector(mine)

    assert mine.get("udp", 67) is dissect_dhcp
    assert mine.get("udp", 68) is dissect_dhcp
    assert other.get("udp", 67) is None
    assert (
        pktcap.default_registry().get("udp", 67) is None
    ), "nothing registers on import"


def test_a_port_already_taken_leaves_nothing_registered() -> None:
    registry = pktcap.DissectorRegistry()
    registry.register("udp", 68, lambda data: pktcap.Dissected(None, data))

    with pytest.raises(ValueError):
        register_dhcp_dissector(registry)

    assert registry.get("udp", 67) is None


def test_a_capture_is_read_with_a_layer_on_every_frame(tmp_path: pathlib.Path) -> None:
    recorded = _recorded()
    target = tmp_path / "recorded.pcap"
    with pktcap.PcapWriter(target) as writer:
        for number, (src, dst, data) in enumerate(recorded):
            writer.write(1_700_000_000.0 + number, _split(src), _split(dst), data)
    registry = pktcap.DissectorRegistry()
    register_dhcp_dissector(registry)
    dissector = pktcap.FrameDissector(registry)

    frames = list(pktcap.read_dissected(target, dissector=dissector))

    assert len(frames) == len(recorded)
    layers = [frame.layer(DHCPLayer) for frame in frames]
    assert all(layer is not None for layer in layers)
    assert [layer.xid for layer in layers if layer] == [
        int.from_bytes(data[4:8], "big") for _s, _d, data in recorded
    ]
    select = compile_capture_filter_for_frames("proto=dhcp")
    assert all(select(frame) for frame in frames)
    assert not any(compile_capture_filter_for_frames("proto=tftp")(f) for f in frames)
    assert dissector.stats.malformed == 0 and dissector.stats.failed == 0


def compile_capture_filter_for_frames(
    text: str,
) -> "_ty.Callable[[pktcap.DissectedFrame], bool]":
    return pktcap.compile_capture_filter(text, pktcap.frame_filter)


def test_a_frame_that_is_not_dhcp_is_malformed_not_fatal(
    tmp_path: pathlib.Path,
) -> None:
    target = tmp_path / "bad.pcap"
    with pktcap.PcapWriter(target) as writer:
        writer.write(1.0, ("10.0.0.1", 68), ("10.0.0.2", 67), b"not dhcp at all")
        writer.write(2.0, ("10.0.0.1", 68), ("10.0.0.2", 67), SAMPLES[0])
    registry = pktcap.DissectorRegistry()
    register_dhcp_dissector(registry)
    dissector = pktcap.FrameDissector(registry)

    frames = list(pktcap.read_dissected(target, dissector=dissector))

    assert [f.layer(DHCPLayer) is not None for f in frames] == [False, True]
    assert "not a DHCP message" in (frames[0].error or "")
    assert dissector.stats.malformed == 1


def test_the_builder_of_the_fixture_is_the_recorded_cases() -> None:
    assert build.recorded() == SAMPLES
