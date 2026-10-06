"""Malformed input is contained inside handle() (`server-21`)."""

import ipaddress
import logging
import socket
from unittest.mock import Mock

import pytest

from driving import WAIT_SECONDS, driver_params, serve
from pydhcp import (
    AsyncDHCPServer,
    DHCPLease,
    DHCPMessage,
    DHCPOptions,
    NetworkInterface,
    DHCPRequestContext,
)
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp import SocketAddress
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
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


# --- options 50, 51, 54 and 57 of the wrong length -----------------------------

SERVED = ipaddress.IPv4Interface("10.0.0.1/24")

#: (option, octets that make it unusable). The right length is 4, 4, 4 and 2.
WRONG_LENGTHS = [
    (DHCPOptionCode.SERVER_IDENTIFIER, 0),
    (DHCPOptionCode.SERVER_IDENTIFIER, 3),
    (DHCPOptionCode.SERVER_IDENTIFIER, 8),
    (DHCPOptionCode.REQUESTED_IP, 0),
    (DHCPOptionCode.REQUESTED_IP, 5),
    (DHCPOptionCode.REQUESTED_IP, 8),
    (DHCPOptionCode.IP_ADDRESS_LEASE_TIME, 0),
    (DHCPOptionCode.IP_ADDRESS_LEASE_TIME, 2),
    (DHCPOptionCode.IP_ADDRESS_LEASE_TIME, 5),
    (DHCPOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE, 0),
    (DHCPOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE, 1),
    (DHCPOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE, 3),
]
#: Options whose message cannot be answered without them.
DROPS = (DHCPOptionCode.SERVER_IDENTIFIER, DHCPOptionCode.REQUESTED_IP)


def _wire(kind: DHCPMessageType, code: DHCPOptionCode, octets: int, xid: int):
    """The datagram a sender could put on the wire, as the listener decodes it."""
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = kind
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray(b"\x01" + CHADDR)
    if kind is DHCPMessageType.DHCPREQUEST:
        options[DHCPOptionCode.REQUESTED_IP] = ipaddress.IPv4Address("10.0.0.50")
        options[DHCPOptionCode.SERVER_IDENTIFIER] = SERVED.ip
    else:
        options[DHCPOptionCode.REQUESTED_IP] = ipaddress.IPv4Address("10.0.0.50")
    # Past the codec, which refuses to build a value of the wrong length.
    options._options[int(code)] = bytearray(octets)
    message = build_request(None, options=options, xid=xid)
    return DHCPMessage.decode(memoryview(bytes(message.encode())))


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pydhcp.server._policy._servable_interface",
        lambda _ip: NetworkInterface("eth0", SERVED),
    )


def _served_context() -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", SERVED),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


@pytest.mark.parametrize(
    "kind", [DHCPMessageType.DHCPDISCOVER, DHCPMessageType.DHCPREQUEST]
)
@pytest.mark.parametrize("code, octets", WRONG_LENGTHS)
def test_an_option_of_the_wrong_length_does_not_escape_handle(
    served, caplog, code, octets, kind
) -> None:
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())
    message = _wire(kind, code, octets, xid=0xFEEDF00D)
    client_id = message.get_client_id()
    server.lease_backend.offer(client_id, ipaddress.IPv4Address("10.0.0.50"), 120.0)
    context = _served_context()
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        server.handle(message, context)  # must not raise

    assert caplog.records, "dropped silently"
    line = caplog.text
    assert "feedf00d" in line.lower(), "log line carries no XID"
    assert "10.0.0.50" in line, "log line does not name the client"
    assert f"option {int(code)}" in line
    sent = context.transport.send.call_count
    if code in DROPS:
        assert sent == 0
        assert server.metrics.packets_dropped_malformed_option == 1
        assert server.metrics.options_ignored_malformed == 0
    else:
        # A hint the server has a default for: answered as if it were absent.
        assert sent == 1
        assert server.metrics.packets_dropped_malformed_option == 0
        assert server.metrics.options_ignored_malformed == 1


def test_an_unusable_lease_time_is_answered_with_the_default() -> None:
    """Option 51 of two octets reads as absent, so the lease is the server's own."""
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())
    message = _wire(
        DHCPMessageType.DHCPDISCOVER, DHCPOptionCode.IP_ADDRESS_LEASE_TIME, 2, 1
    )
    server.handle(message, _served_context())
    assert DHCPOptionCode.IP_ADDRESS_LEASE_TIME not in message.options
    assert server.get_lease_seconds(message) == server.DEFAULT_LEASE_SECONDS


def test_a_malformed_option_is_logged_through_the_rate_limit(served, caplog) -> None:
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        for xid in range(50):
            server.handle(
                _wire(
                    DHCPMessageType.DHCPDISCOVER,
                    DHCPOptionCode.SERVER_IDENTIFIER,
                    3,
                    xid,
                ),
                _served_context(),
            )
    assert len(caplog.records) == 1
    assert server.metrics.packets_dropped_malformed_option == 50


# --- through a real socket, on each driver --------------------------------------

LOOPBACK = ipaddress.IPv4Address("127.0.0.1")


class _OnePool:
    """Gives every client 127.0.0.1 and stores nothing; the parsing is under test."""

    def acquire_lease(self, client_id, server_id, msg, *, commit=True):  # type: ignore[no-untyped-def]
        return DHCPLease(LOOPBACK)


class _OnePoolSync(_OnePool, DHCPServer):
    pass


class _OnePoolAsync(_OnePool, AsyncDHCPServer):
    pass


@pytest.mark.parametrize(
    "server_class, loop_type", driver_params(_OnePoolSync, _OnePoolAsync)
)
def test_the_next_well_formed_client_is_answered_after_every_wrong_length(
    server_class, loop_type, caplog
) -> None:
    server = server_class(listen=("127.0.0.1", 0))
    dropped = [w for w in WRONG_LENGTHS if w[0] in DROPS]
    ignored = [w for w in WRONG_LENGTHS if w[0] not in DROPS]

    def exercise(port: int) -> "list[int]":
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(WAIT_SECONDS)
        try:
            for index, (code, octets) in enumerate(WRONG_LENGTHS):
                message = _wire(
                    DHCPMessageType.DHCPDISCOVER, code, octets, 0x100 + index
                )
                client.sendto(bytes(message.encode()), ("127.0.0.1", port))
            good = _wire(
                DHCPMessageType.DHCPDISCOVER,
                DHCPOptionCode.HOSTNAME,
                1,
                0x900,
            )
            client.sendto(bytes(good.encode()), ("127.0.0.1", port))
            return [
                DHCPMessage.decode(client.recvfrom(2048)[0]).xid
                for _ in range(len(ignored) + 1)
            ]
        finally:
            client.close()

    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        xids = serve(server, exercise, loop_type)

    assert xids[-1] == 0x900
    assert len(xids) == len(ignored) + 1
    assert server.metrics.packets_dropped_malformed_option == len(dropped)
    assert server.metrics.options_ignored_malformed == len(ignored)
    assert server.metrics.packets_dropped_error == 0
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
