"""Option 57 clamping and unservable leases (`server-20`, `server-11`)."""

import ipaddress
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from pydhcp import DhcpMessage, DhcpOptions, NetworkInterface, RequestContext
from pydhcp import constants as const
from pydhcp.lease import DhcpLease, InMemoryLeaseBackend
from pydhcp.network import IPv4, SocketAddress
from pydhcp.options import DhcpOptionCode
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.server import DhcpServer

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
SERVED = ipaddress.IPv4Interface("10.0.0.1/24")


def _message(
    message_type: DhcpMessageType, max_size: "int | None" = None
) -> DhcpMessage:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = message_type
    if max_size is not None:
        options[DhcpOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE] = max_size
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x12345678,
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


def _context(transport: Mock) -> RequestContext:
    return RequestContext(
        transport=transport,
        interface=NetworkInterface("eth0", SERVED),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


class _FixedLeaseServer(DhcpServer):
    """Returns a lease with a caller-chosen expiry, bypassing the allocator.

    `lease_seconds` enforces MIN_LEASE_SECONDS, so the base server can never
    produce an almost-expired lease. An override can -- which is the population
    `server-11` is about.
    """

    def __init__(self, expires) -> None:
        super().__init__(lease_backend=InMemoryLeaseBackend())
        self._expires = expires

    def acquire_lease(self, client_id, server_id, msg):
        return DhcpLease(IPv4("10.0.0.50"), self._expires, DhcpOptions())


def _sent(transport: Mock) -> bytes:
    assert transport.send.called, "no reply was sent"
    return transport.send.call_args[0][0]


@pytest.mark.parametrize("advertised", [1, 100, 200, 267, 300, 575])
def test_a_max_size_below_the_rfc_minimum_still_gets_a_reply(advertised) -> None:
    """Measured before the clamp: option 57 = 200 raised out of encode().

    `encode` refuses anything below 268 outright, so the client got nothing at
    all and the listener logged an error with no XID for every such packet.
    """
    server = _FixedLeaseServer(datetime.now() + timedelta(seconds=3600))
    transport = Mock(send=Mock(return_value=1))
    server.handle_discover(
        _message(DhcpMessageType.DHCPDISCOVER, max_size=advertised), _context(transport)
    )
    data = _sent(transport)
    assert len(data) >= const.BOOTP_MIN_PACKET_SIZE
    # Decodes as a real OFFER rather than whatever fit in the tiny budget.
    assert (
        DhcpMessage.decode(bytearray(data)).options.get(
            DhcpOptionCode.DHCP_MESSAGE_TYPE
        )
        is DhcpMessageType.DHCPOFFER
    )


def test_a_large_advertised_size_is_left_alone() -> None:
    """No upper clamp: reply size is set by what the server has to say."""
    server = _FixedLeaseServer(datetime.now() + timedelta(seconds=3600))
    transport = Mock(send=Mock(return_value=1))
    server.handle_discover(
        _message(DhcpMessageType.DHCPDISCOVER, max_size=9000), _context(transport)
    )
    assert _sent(transport)


def test_lease_time_is_rounded_up_not_truncated() -> None:
    """A 3600-second lease went out as 3599 -- a different number than granted."""
    server = _FixedLeaseServer(datetime.now() + timedelta(seconds=3600))
    transport = Mock(send=Mock(return_value=1))
    server.handle_discover(_message(DhcpMessageType.DHCPDISCOVER), _context(transport))
    offer = DhcpMessage.decode(bytearray(_sent(transport)))
    assert int(offer.options.get(DhcpOptionCode.IP_ADDRESS_LEASE_TIME)) == 3600


def test_an_expired_lease_produces_no_offer() -> None:
    server = _FixedLeaseServer(datetime.now() - timedelta(seconds=1))
    transport = Mock(send=Mock(return_value=1))
    server.handle_discover(_message(DhcpMessageType.DHCPDISCOVER), _context(transport))
    assert not transport.send.called, "offered a lease with no time left"


def test_an_expired_lease_naks_a_request_instead_of_acking_nothing() -> None:
    """Measured before: a DHCPACK with yiaddr 0.0.0.0 and no option 51."""
    server = _FixedLeaseServer(datetime.now() - timedelta(seconds=1))
    transport = Mock(send=Mock(return_value=1))
    request = _message(DhcpMessageType.DHCPREQUEST)
    request.options[DhcpOptionCode.REQUESTED_IP] = IPv4("10.0.0.50")
    # With no server identifier this is INIT-REBOOT, and a server with no
    # record of the client MUST stay silent (RFC 2131 4.3.2) -- a different,
    # already-correct path. Name the server so the SELECTING branch is reached.
    request.options[DhcpOptionCode.SERVER_IDENTIFIER] = IPv4("10.0.0.1")
    server.handle_request(request, _context(transport))

    reply = DhcpMessage.decode(bytearray(_sent(transport)))
    assert reply.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) is (
        DhcpMessageType.DHCPNAK
    )
