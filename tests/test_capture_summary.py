"""`DHCPLayer.summary()` and the filter keys `capture_dissector()` compiles.

The summary is the line pktcap's `text` format shows for a frame whose innermost layer
is DHCP; the expected strings here are written out by hand from the fields of the
message a test builds, not computed from the layer.
"""

from __future__ import annotations

import json
import pathlib
import typing as _ty
from ipaddress import IPv4Address as IPv4

import pytest

pktcap = pytest.importorskip("pktcap")

from helpers import build_request
from pydhcp import DHCPMessage
from pydhcp.capture import DHCPLayer, capture_dissector, dissect_dhcp
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType

TRANSCRIPTS = pathlib.Path(__file__).parent / "conformance" / "transcripts"
CHADDR = b"\x02\x00\x00\x99\x00\x02"


def _layer(message: DHCPMessage) -> DHCPLayer:
    layer = dissect_dhcp(bytes(message.encode())).layer
    assert isinstance(layer, DHCPLayer)
    return layer


@pytest.mark.parametrize(
    "kind",
    [
        DHCPMessageType.DHCPDISCOVER,
        DHCPMessageType.DHCPREQUEST,
        DHCPMessageType.DHCPDECLINE,
        DHCPMessageType.DHCPRELEASE,
        DHCPMessageType.DHCPINFORM,
    ],
)
def test_the_summary_of_a_client_message_is_its_type_its_xid_and_its_client(
    kind: DHCPMessageType,
) -> None:
    message = build_request(kind, xid=0x1A52B52E, chaddr=CHADDR)

    assert _layer(message).summary() == (
        f"{kind.name} xid=1A52B52E client=01:02:00:00:99:00:02"
    )


@pytest.mark.parametrize(
    "kind",
    [
        DHCPMessageType.DHCPOFFER,
        DHCPMessageType.DHCPACK,
        DHCPMessageType.DHCPNAK,
    ],
)
def test_the_summary_of_a_reply_adds_the_addresses_that_are_not_zero(
    kind: DHCPMessageType,
) -> None:
    message = build_request(
        kind,
        xid=0x0000002A,
        chaddr=CHADDR,
        yiaddr=IPv4("10.99.0.100"),
        giaddr=IPv4("10.99.0.1"),
    )

    assert _layer(message).summary() == (
        f"{kind.name} xid=0000002A client=01:02:00:00:99:00:02 "
        "yiaddr=10.99.0.100 giaddr=10.99.0.1"
    )


def test_a_zero_address_is_left_out_and_a_nonzero_one_is_kept() -> None:
    only_giaddr = build_request(xid=1, chaddr=CHADDR, giaddr=IPv4("192.0.2.9"))
    only_yiaddr = build_request(xid=1, chaddr=CHADDR, yiaddr=IPv4("192.0.2.77"))

    assert (
        _layer(only_giaddr)
        .summary()
        .endswith("client=01:02:00:00:99:00:02 giaddr=192.0.2.9")
    )
    assert (
        _layer(only_yiaddr)
        .summary()
        .endswith("client=01:02:00:00:99:00:02 yiaddr=192.0.2.77")
    )


def test_the_client_is_option_61_when_there_is_one() -> None:
    message = build_request(xid=7, chaddr=CHADDR)
    message.options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytes([1, 0xAA, 0xBB])

    assert _layer(message).summary() == "DHCPDISCOVER xid=00000007 client=01:AA:BB"


def test_a_message_with_no_type_and_no_identity_still_has_a_summary() -> None:
    message = build_request(None, xid=9, chaddr=b"", hlen=0)

    assert _layer(message).summary() == "UNKNOWN xid=00000009 client=UNKNOWN"


def _recorded() -> "_ty.List[bytes]":
    found = []
    for path in sorted(TRANSCRIPTS.glob("*/transcript.json")):
        for d in json.loads(path.read_text(encoding="utf-8"))["datagrams"]:
            found.append(bytes.fromhex(d["payload"]))
    return found


def test_the_summary_of_every_recorded_message_is_one_line_naming_its_xid() -> None:
    samples = _recorded()
    assert len(samples) == 50

    for data in samples:
        layer = dissect_dhcp(data).layer
        line = layer.summary()
        assert "\n" not in line and "\r" not in line
        assert line.startswith(layer.message_type + " xid=")
        assert f"xid={layer.xid:08X} " in line + " "
        assert f"client={layer.client_id}" in line


def test_the_text_format_shows_the_summary_for_a_frame_whose_innermost_layer_is_dhcp() -> (
    None
):
    message = build_request(
        DHCPMessageType.DHCPOFFER,
        xid=0x0A0B0C0D,
        chaddr=CHADDR,
        yiaddr=IPv4("10.0.0.7"),
    )
    datagram = pktcap.CapturedDatagram(
        1700000000.0, ("10.0.0.1", 67), ("10.0.0.7", 68), bytes(message.encode())
    )
    frame = capture_dissector().dissect(pktcap.datagram_frame(datagram))

    line = pktcap.frame_summary(frame)

    assert line.endswith(
        "dhcp: DHCPOFFER xid=0A0B0C0D client=01:02:00:00:99:00:02 yiaddr=10.0.0.7"
    )


def _frames() -> "_ty.List[pktcap.DissectedFrame]":
    dissector = capture_dissector()
    sent = [
        build_request(DHCPMessageType.DHCPDISCOVER, xid=1, chaddr=CHADDR),
        build_request(
            DHCPMessageType.DHCPOFFER, xid=2, chaddr=CHADDR, yiaddr=IPv4("10.0.0.7")
        ),
    ]
    ends = [(("10.0.0.5", 68), ("10.0.0.1", 67)), (("10.0.0.1", 67), ("10.0.0.5", 68))]
    return [
        dissector.dissect(
            pktcap.datagram_frame(
                pktcap.CapturedDatagram(
                    float(number), *ends[number], bytes(message.encode())
                )
            )
        )
        for number, message in enumerate(sent)
    ]


@pytest.mark.parametrize(
    "expression, selected",
    [
        ("msg_type=DHCPOFFER", [1]),
        ("msg_type=DHCPDISCOVER,DHCPOFFER", [0, 1]),
        ("proto=dhcp and xid=1", [0]),
        ("dhcp.message_type=DHCPDISCOVER", [0]),
        ("client_id=01:02:00:00:99:00:02 and msg_type!=DHCPOFFER", [0]),
        ("option.DHCP_MESSAGE_TYPE=DHCPOFFER", [1]),
    ],
)
def test_the_registry_of_capture_dissector_compiles_the_dhcp_keys(
    expression: str, selected: "_ty.List[int]"
) -> None:
    registry = capture_dissector().registry
    test = pktcap.compile_capture_filter(expression, pktcap.frame_filter_for(registry))
    frames = _frames()

    assert [i for i, frame in enumerate(frames) if test(frame)] == selected


def test_capture_dissector_changes_no_registry_but_its_own() -> None:
    before = dict(pktcap.default_registry().layers())

    capture_dissector()

    assert dict(pktcap.default_registry().layers()) == before


def test_a_bad_value_of_a_dhcp_key_is_refused_when_the_filter_is_compiled() -> None:
    registry = capture_dissector().registry

    with pytest.raises(pktcap.CaptureFilterError, match="msg_type"):
        pktcap.compile_capture_filter(
            "msg_type=NOTATYPE", pktcap.frame_filter_for(registry)
        )
