"""Malformed input is contained inside handle() (`server-21`)."""

import ipaddress
import logging
from datetime import timedelta
from unittest.mock import Mock

import pytest

from pydhcp import DhcpMessage, DhcpOptions, NetworkInterface, RequestContext
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.network import IPv4, SocketAddress
from pydhcp.options import DhcpOptionCode
from pydhcp.packet import Flags, HardwareAddressType, OpCode
from pydhcp.server import DhcpServer

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])


def _message_with_raw_type(raw: int) -> DhcpMessage:
    options = DhcpOptions()
    # Written past the codec, which is the only way to build the packet a
    # hostile or broken sender puts on the wire.
    options._options[int(DhcpOptionCode.DHCP_MESSAGE_TYPE)] = bytearray([raw])
    options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray(b"\x01" + CHADDR)
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0xDEADBEEF,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=CHADDR,
        sname="",
        file="",
        options=options,
    )


def _context() -> RequestContext:
    return RequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


def test_an_unknown_message_type_does_not_escape_handle(caplog) -> None:
    """Measured before: option 53 = 99 raised ValueError out of handle()."""
    server = DhcpServer(lease_backend=InMemoryLeaseBackend())
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        server.handle(_message_with_raw_type(99), _context())  # must not raise

    assert caplog.records, "dropped silently"
    line = caplog.text
    # The whole point of the fix: the line identifies the packet.
    assert "deadbeef" in line.lower(), "log line carries no XID"
    assert "10.0.0.50" in line, "log line does not name the client"
    assert "63" in line, "log line does not say what the bad value was"


@pytest.mark.parametrize("raw", [0, 99, 128, 255])
def test_the_loop_keeps_running_for_any_unassigned_type(raw) -> None:
    server = DhcpServer(lease_backend=InMemoryLeaseBackend())
    server.handle(_message_with_raw_type(raw), _context())
