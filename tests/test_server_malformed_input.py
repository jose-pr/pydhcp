"""Malformed input is contained inside handle() (`server-21`)."""

import ipaddress
import logging
from unittest.mock import Mock

import pytest

from pydhcp import DHCPMessage, DHCPOptions, NetworkInterface, DHCPRequestContext
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp import SocketAddress
from pydhcp.options import DHCPOptionCode
from pydhcp.server import DHCPServer
from conftest import build_request

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])


def _message_with_raw_type(raw: int) -> DHCPMessage:
    options = DHCPOptions()
    # Written past the codec, which is the only way to build the packet a
    # hostile or broken sender puts on the wire.
    options._options[int(DHCPOptionCode.DHCP_MESSAGE_TYPE)] = bytearray([raw])
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray(b"\x01" + CHADDR)
    return build_request(None, options=options, xid=0xDEADBEEF)


def _context() -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


def test_an_unknown_message_type_does_not_escape_handle(caplog) -> None:
    """Measured before: option 53 = 99 raised ValueError out of handle()."""
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        server.handle(_message_with_raw_type(99), _context())  # must not raise

    assert caplog.records, "dropped silently"
    line = caplog.text
    # The whole point of the fix: the line identifies the packet.
    assert "deadbeef" in line.lower(), "log line carries no XID"
    assert "10.0.0.50" in line, "log line does not name the client"
    assert "TYPE_99" in line, "log line does not say what the bad value was"


def test_an_option_53_of_the_wrong_size_is_dropped_with_its_octets(caplog) -> None:
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())
    message = _message_with_raw_type(1)
    message.options._options[int(DHCPOptionCode.DHCP_MESSAGE_TYPE)] = bytearray()
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        server.handle(message, _context())
    assert "unusable DHCP message type" in caplog.text
    assert "<empty>" in caplog.text


@pytest.mark.parametrize("raw", [0, 99, 128, 255])
def test_the_loop_keeps_running_for_any_unassigned_type(raw) -> None:
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())
    server.handle(_message_with_raw_type(raw), _context())
