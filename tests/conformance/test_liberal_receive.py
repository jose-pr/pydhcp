"""What a real peer sends is read; what the RFC forbids is still not sent.

PROTOCOL.md, "Wire encoding": decode is liberal and encode is strict, and a
value on the wire is never rewritten. Each case names the RFC allowance or the
peer behind the reading, and where the encoder refuses the same value it says
so beside it.
"""

from __future__ import annotations

import json

import pytest

from pydhcp import DHCPMessage
from pydhcp.exceptions import DHCPDecodeError, DHCPValueError
from pydhcp.options import (
    ClasslessRoute,
    DHCPOptionCode,
    List,
    RDNSSSelection,
    RelayAgentInformation,
    SIPServers,
    StaticRoute,
    VIVendorClass,
)
from pydhcp.packet import DHCPOpcode

# the name reader's bounds are not public
from pydhcp.options._codecs._domains import MAX_POINTER_HOPS


def _label(text: str) -> bytes:
    return bytes([len(text)]) + text.encode()


# --- option 120: compression is read, never sent (RFC 3361 s3.1) ------------


def _sip_chain(names: int) -> bytes:
    """The encoding octet, a root name, then `names` names that are one pointer
    to the name before; offsets count from the encoding octet."""
    out = bytearray(b"\x00\x00")
    previous = 1
    for _ in range(names):
        start = len(out)
        out += (0xC000 | previous).to_bytes(2, "big")
        previous = start
    return bytes(out)


def test_option_120_resolves_a_pointer_to_an_earlier_name() -> None:
    wire = b"\x00" + _label("example") + _label("com") + b"\x00" + _label("sip")
    wire += b"\xc0\x01"
    assert list(SIPServers.unpack(bytearray(wire)).values) == [
        "example.com",
        "sip.example.com",
    ]


def test_option_120_is_sent_uncompressed() -> None:
    value = SIPServers(["example.com", "sip.example.com"])
    assert b"\xc0" not in bytes(value.pack())


def test_option_120_follows_as_many_pointers_as_the_limit_allows() -> None:
    names = SIPServers.unpack(bytearray(_sip_chain(MAX_POINTER_HOPS))).values
    assert list(names) == [""] * (MAX_POINTER_HOPS + 1)


def test_option_120_refuses_a_name_that_follows_more_pointers() -> None:
    with pytest.raises(DHCPDecodeError, match="more than 127 compression pointers"):
        SIPServers.unpack(bytearray(_sip_chain(MAX_POINTER_HOPS + 1)))


def test_option_120_refuses_a_name_over_255_octets() -> None:
    """Names that each extend the one before grow past the bound at the fifth."""
    label = _label("a" * 63)
    wire = bytearray(b"\x00" + label + b"\x00")
    previous = 1
    for _ in range(5):
        start = len(wire)
        wire += label + (0xC000 | previous).to_bytes(2, "big")
        previous = start
    with pytest.raises(DHCPDecodeError, match="255 octets"):
        SIPServers.unpack(wire)


@pytest.mark.parametrize(
    "names",
    [
        b"\x01a\xc0\x01",  # a pointer to the start of its own name
        b"\x01a\x00\x01b\xc0\x50",  # a pointer past the end
        b"\x01a\x00\x01b\xc0\x00",  # a pointer to the encoding octet
        b"\x03foo",  # a name that never ends
    ],
)
def test_option_120_refuses_a_pointer_or_name_that_does_not_hold(names: bytes) -> None:
    with pytest.raises(DHCPDecodeError):
        SIPServers.unpack(bytearray(b"\x00" + names))


# --- option 121: host bits are masked (RFC 3442 s3) ---------------------------


@pytest.mark.parametrize(
    "descriptor, network",
    [
        (bytes([25, 129, 210, 177, 132]), "129.210.177.128/25"),
        (bytes([20, 10, 0, 17]), "10.0.16.0/20"),
        (bytes([8, 10]), "10.0.0.0/8"),
        (bytes([1, 255]), "128.0.0.0/1"),
    ],
)
def test_a_route_destination_has_its_host_bits_zeroed(
    descriptor: bytes, network: str
) -> None:
    routes = List[ClasslessRoute].unpack(bytearray(descriptor + bytes([192, 0, 2, 1])))
    assert [str(route.network) for route in routes] == [network]


def test_a_route_with_host_bits_does_not_cost_the_others() -> None:
    wire = (
        bytes([24, 10, 1, 2, 192, 0, 2, 1])
        + bytes([20, 10, 0, 17, 192, 0, 2, 2])
        + bytes([16, 172, 16, 192, 0, 2, 3])
    )
    routes = List[ClasslessRoute].unpack(bytearray(wire))
    assert [str(route.network) for route in routes] == [
        "10.1.2.0/24",
        "10.0.16.0/20",
        "172.16.0.0/16",
    ]


def test_a_route_is_still_built_strictly() -> None:
    with pytest.raises(ValueError):
        ClasslessRoute("192.0.2.1", "10.0.17.0/20")


# --- option 33: a default destination is read and refused on write -----------


def test_a_static_route_to_0_0_0_0_is_read() -> None:
    wire = bytes(4) + bytes([192, 0, 2, 1]) + bytes([10, 1, 0, 0, 192, 0, 2, 1])
    routes = StaticRoute.unpack(bytearray(wire))
    assert [(str(a), str(b)) for a, b in routes] == [
        ("0.0.0.0", "192.0.2.1"),
        ("10.1.0.0", "192.0.2.1"),
    ]


def test_a_static_route_to_0_0_0_0_is_not_sent() -> None:
    routes = StaticRoute.unpack(bytearray(bytes(4) + bytes([192, 0, 2, 1])))
    with pytest.raises(DHCPValueError, match="default-route"):
        routes.pack()
    with pytest.raises(DHCPValueError, match="default-route"):
        StaticRoute([("0.0.0.0", "192.0.2.1")])


# --- option 146: the root name, the reserved bits, the structured form --------

_RDNSS_ADDRESSES = bytes([192, 0, 2, 1, 192, 0, 2, 2])


def test_the_root_domain_of_option_146_is_kept() -> None:
    wire = b"\x01" + _RDNSS_ADDRESSES + _label("example") + _label("com") + b"\x00\x00"
    value = RDNSSSelection.unpack(bytearray(wire))
    assert list(value.domains) == ["example.com", ""]
    assert bytes(value.pack()) == wire


def test_a_dot_spells_the_root_domain() -> None:
    value = RDNSSSelection(0, "192.0.2.1", "192.0.2.2", ["."])
    assert bytes(value.pack()) == b"\x00" + _RDNSS_ADDRESSES + b"\x00"


def test_the_reserved_bits_of_option_146_are_ignored_on_receipt() -> None:
    value = RDNSSSelection.unpack(bytearray(b"\xfe" + _RDNSS_ADDRESSES + b"\x00"))
    assert value.flags == 2


def test_option_146_is_built_from_the_form_it_emits() -> None:
    value = RDNSSSelection(1, "192.0.2.1", "192.0.2.2", ["example.com", "."])
    assert RDNSSSelection(json.loads(json.dumps(value.to_json()))) == value
    assert RDNSSSelection(value) == value


def test_a_message_with_option_146_survives_the_structured_form() -> None:
    message = DHCPMessage(DHCPOpcode.BOOTREPLY)
    message.options[DHCPOptionCode.RDNSS_SELECTION] = RDNSSSelection(
        1, "192.0.2.1", "192.0.2.2", ["example.com", "."]
    )
    mapping = message.to_mapping()
    assert "hex" not in json.dumps(mapping["options"])
    restored = DHCPMessage.from_mapping(json.loads(json.dumps(mapping)))
    assert restored.options.get(146, decode=False) == message.options.get(
        146, decode=False
    )


# --- option 124: the form it emits is the form it accepts ----------------------


def test_option_124_is_built_from_the_form_it_emits() -> None:
    value = VIVendorClass([(311, [b"ab", b"cde"]), (9, [b"\x00\xff"])])
    assert VIVendorClass(json.loads(json.dumps(value.to_json()))) == value


def test_a_message_with_option_124_survives_the_structured_form() -> None:
    message = DHCPMessage(DHCPOpcode.BOOTREQUEST)
    message.options[DHCPOptionCode.VI_VENDOR_CLASS] = VIVendorClass(
        [(311, [b"ab", b"cde"])]
    )
    mapping = message.to_mapping()
    assert "hex" not in json.dumps(mapping["options"])
    restored = DHCPMessage.from_mapping(json.loads(json.dumps(mapping)))
    assert restored.options.get(124) == message.options.get(124)


# --- option 82: sub-options are plain (RFC 3046 s2.0) --------------------------


def test_option_82_has_no_pad_and_no_end() -> None:
    wire = bytes([0, 1, 9, 255, 2, 7, 8, 1, 0])
    value = RelayAgentInformation.unpack(bytearray(wire))
    assert [(item.code, bytes(item.value)) for item in value] == [
        (0, b"\x09"),
        (255, b"\x07\x08"),
        (1, b""),
    ]
    assert bytes(value.pack()) == wire


@pytest.mark.parametrize("wire", [bytes([1]), bytes([1, 5, 1, 2]), bytes([1, 1, 7, 2])])
def test_option_82_refuses_a_cut_short_sub_option(wire: bytes) -> None:
    with pytest.raises(DHCPDecodeError, match="truncated"):
        RelayAgentInformation.unpack(bytearray(wire))
