"""`DHCPMessage` header defaults, the derived `hlen`, and `message_type`."""

from __future__ import annotations

import datetime
import inspect
from ipaddress import IPv4Address

import pytest

from pydhcp import DHCPMessage, DHCPOptions, DHCPValueError
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import (
    DHCPFlags,
    DHCPMessageType,
    DHCPOpcode,
    HardwareAddressType,
)
from conftest import CHADDR, build_request


def _wire(chaddr_len: int, htype: int = 1, *, hlen: "int | None" = None) -> bytes:
    """A DHCPDISCOVER written octet by octet, with an `hlen` of the caller's choosing."""
    header = bytearray(240)
    header[0] = 1
    header[1] = htype
    header[2] = chaddr_len if hlen is None else hlen
    header[4:8] = (0x01020304).to_bytes(4, "big")
    header[28 : 28 + chaddr_len] = bytes(range(1, chaddr_len + 1))
    header[236:240] = bytes([0x63, 0x82, 0x53, 0x63])
    return bytes(header) + bytes([53, 1, 1, 255]) + bytes(60)


def test_a_message_needs_only_an_op() -> None:
    message = DHCPMessage(DHCPOpcode.BOOTREQUEST)
    assert message.htype is HardwareAddressType.ETHERNET
    assert (message.hlen, message.hops, message.xid) == (0, 0, 0)
    assert message.secs == datetime.timedelta(0)
    assert message.flags is DHCPFlags.UNICAST
    assert {message.ciaddr, message.yiaddr, message.siaddr, message.giaddr} == {
        IPv4Address("0.0.0.0")
    }
    assert (message.chaddr, message.sname, message.file) == (b"", "", "")
    assert len(message.options) == 0


def test_the_bare_message_encodes_to_a_legal_300_octet_message() -> None:
    wire = DHCPMessage(DHCPOpcode.BOOTREQUEST).encode()
    assert len(wire) == 300
    assert wire[236:240] == bytes([0x63, 0x82, 0x53, 0x63])
    assert wire[240] == 255
    assert DHCPMessage.decode(wire) == DHCPMessage(DHCPOpcode.BOOTREQUEST)


def test_every_field_after_the_op_is_keyword_only() -> None:
    parameters = list(inspect.signature(DHCPMessage).parameters.values())
    assert parameters[0].name == "op"
    assert parameters[0].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters[1:])
    assert [p.name for p in parameters[1:]] == [
        "htype",
        "hlen",
        "hops",
        "xid",
        "secs",
        "flags",
        "ciaddr",
        "yiaddr",
        "siaddr",
        "giaddr",
        "chaddr",
        "sname",
        "file",
        "options",
    ]
    with pytest.raises(TypeError):
        DHCPMessage(DHCPOpcode.BOOTREQUEST, HardwareAddressType.ETHERNET)  # type: ignore[misc]


def test_each_message_gets_its_own_options() -> None:
    first = DHCPMessage(DHCPOpcode.BOOTREQUEST)
    second = DHCPMessage(DHCPOpcode.BOOTREQUEST)
    first.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    assert len(second.options) == 0


def test_hlen_is_the_length_of_the_hardware_address_when_left_out() -> None:
    assert DHCPMessage(DHCPOpcode.BOOTREQUEST, chaddr=CHADDR).hlen == 6
    assert DHCPMessage(DHCPOpcode.BOOTREQUEST, chaddr=bytes(16)).hlen == 16
    assert DHCPMessage(DHCPOpcode.BOOTREQUEST, chaddr=b"").hlen == 0


def test_an_hlen_that_agrees_with_the_hardware_address_is_accepted() -> None:
    assert DHCPMessage(DHCPOpcode.BOOTREQUEST, hlen=6, chaddr=CHADDR).hlen == 6
    assert DHCPMessage(DHCPOpcode.BOOTREQUEST, hlen=0).hlen == 0


@pytest.mark.parametrize(
    "hlen,chaddr", [(6, b""), (0, CHADDR), (4, CHADDR), (16, CHADDR)]
)
def test_an_hlen_that_disagrees_with_the_hardware_address_is_refused(
    hlen: int, chaddr: bytes
) -> None:
    with pytest.raises(DHCPValueError, match="hlen"):
        DHCPMessage(DHCPOpcode.BOOTREQUEST, hlen=hlen, chaddr=chaddr)


def test_encoding_refuses_an_hlen_that_no_longer_agrees() -> None:
    message = build_request()
    message.hlen = 3
    with pytest.raises(DHCPValueError, match="hlen"):
        message.encode()
    message = build_request()
    message.chaddr = b"\x01\x02"
    with pytest.raises(DHCPValueError, match="hlen"):
        message.encode()


@pytest.mark.parametrize(
    "wire",
    [
        pytest.param(_wire(4), id="ethernet type with a 4-octet address"),
        pytest.param(_wire(0), id="ethernet type with no address"),
        pytest.param(_wire(16, htype=32), id="16 octets under infiniband"),
        pytest.param(_wire(6, htype=200), id="an unassigned hardware type"),
    ],
)
def test_a_received_hlen_that_does_not_fit_the_hardware_type_still_decodes(
    wire: bytes,
) -> None:
    """Liberal on receive: `hlen` is what the sender wrote, whatever `htype` says."""
    message = DHCPMessage.decode(wire)
    assert message.hlen == len(message.chaddr)
    assert message.encode()[:44] == wire[:44]


def test_a_received_hlen_above_the_field_is_still_refused() -> None:
    from pydhcp import DHCPDecodeError

    with pytest.raises(DHCPDecodeError):
        DHCPMessage.decode(_wire(0, hlen=17))


def test_message_type_is_the_member_or_none() -> None:
    assert build_request(DHCPMessageType.DHCPOFFER).message_type is (
        DHCPMessageType.DHCPOFFER
    )
    assert DHCPMessage(DHCPOpcode.BOOTREQUEST).message_type is None
    assert build_request(None).message_type is None


@pytest.mark.parametrize("payload", [b"", b"\x01\x02", b"\x00", b"\x63"])
def test_message_type_is_none_for_a_payload_that_is_not_a_known_type(
    payload: bytes,
) -> None:
    message = DHCPMessage(DHCPOpcode.BOOTREQUEST)
    message.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = payload
    assert message.message_type is None


def test_message_type_is_read_only() -> None:
    message = build_request()
    with pytest.raises(AttributeError):
        message.message_type = DHCPMessageType.DHCPACK  # type: ignore[misc]


def test_options_can_be_given_and_are_kept_by_reference() -> None:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    message = DHCPMessage(DHCPOpcode.BOOTREQUEST, options=options)
    assert message.options is options
    assert message.message_type is DHCPMessageType.DHCPDISCOVER
