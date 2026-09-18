import pytest
from datetime import timedelta
import logging
from pydhcp.packet.message import DhcpMessage
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4
from pydhcp.options import DhcpOptions


def get_valid_packet_bytes() -> bytearray:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER.value]
    )
    msg = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x3903F326,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        sname="",
        file="",
        options=options,
    )
    return bytearray(msg.encode())


def test_invalid_hlen():
    packet = get_valid_packet_bytes()
    # Modify hlen (offset 2) to 17 (> 16)
    packet[2] = 17
    with pytest.raises(
        ValueError, match="Hardware address length 17 exceeds maximum of 16"
    ):
        DhcpMessage.decode(packet)


def test_packet_shorter_than_fixed_header():
    with pytest.raises(
        ValueError,
        match="too short for DHCP fixed header: got 10 bytes, need at least 236",
    ):
        DhcpMessage.decode(bytearray(10))


def test_packet_shorter_than_magic_cookie():
    with pytest.raises(
        ValueError,
        match="too short for DHCP magic cookie at offset 236: got 238 bytes, need at least 240",
    ):
        DhcpMessage.decode(bytearray(238))


def test_unnamed_htype_decodes_without_warning_noise(caplog):
    """An unnamed hardware type is data, not a fault.

    Warning per packet let one client flood the log, and the value it warned
    about was then discarded anyway. It is now kept, and says nothing.
    """
    packet = get_valid_packet_bytes()
    # Modify htype (offset 1) to a value with no IANA name, e.g. 99
    packet[1] = 99
    with caplog.at_level(logging.WARNING):
        decoded = DhcpMessage.decode(packet)

    assert decoded.htype == 99
    assert "Unknown hardware type" not in caplog.text
    assert bytes(decoded.encode())[1] == 99


def test_invalid_magic_cookie():
    packet = get_valid_packet_bytes()
    # Magic cookie is at offset 236 to 240. Let's modify it.
    packet[236:240] = b"\x00\x00\x00\x00"
    with pytest.raises(ValueError, match="Invalid magic cookie at offset 236"):
        DhcpMessage.decode(packet)


def test_truncated_options(caplog):
    packet = get_valid_packet_bytes()
    # Find options start (offset 240)
    # Let's append a truncated option at the end.
    # An option with code 1 (Subnet mask), claiming length 4 but no data.
    # We remove the end-of-options marker (255) first if it's there.
    # Actually, let's just make the packet end with option header but no payload.
    # Cut back to the end of the options the message actually carries, rather
    # than assuming encode() stops there: outgoing messages are padded to the
    # 300-octet BOOTP minimum, so the tail is PAD octets, not the END marker.
    end = packet.index(0xFF, 240)
    truncated_option = bytearray([1, 4])
    packet = packet[:end] + truncated_option

    with caplog.at_level(logging.WARNING):
        decoded = DhcpMessage.decode(packet)

    assert f"Option 1 at offset {end} claims 4 bytes but only 0 available" in (
        caplog.text
    )
