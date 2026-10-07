"""The server sends T1 and T2 with the lease time (RFC 2131 s4.4.5), on both drivers.

The values are half and seven eighths of the lease time the same reply carries,
rounded down; 300 seconds gives 150 and 262, which is what dnsmasq 2.92 sends.
"""

import ipaddress
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from pydhcp import (
    AsyncDHCPServer,
    DHCPLease,
    DHCPMessage,
    DHCPOptions,
    DHCPRequestContext,
    NetworkInterface,
    SocketAddress,
)
from pydhcp.lease import InMemoryLeaseBackend
from ipaddress import IPv4Address as IPv4
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
from pydhcp.server import DHCPServer
from helpers import build_request

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
SERVED = ipaddress.IPv4Interface("10.0.0.1/24")
ADDRESS = IPv4("10.0.0.50")
T1 = DHCPOptionCode.RENEWAL_TIME
T2 = DHCPOptionCode.REBINDING_TIME
LEASE_TIME = DHCPOptionCode.IP_ADDRESS_LEASE_TIME
INFINITE = 0xFFFFFFFF


class _Fixed:
    """Gives every client the one lease in `lease`, and stores nothing."""

    lease: "DHCPLease | None" = None

    def acquire_lease(self, client_id, server_id, msg, *, commit=True):
        return self.lease


class _Sync(_Fixed, DHCPServer):
    pass


class _Async(_Fixed, AsyncDHCPServer):
    pass


@pytest.fixture(params=[_Sync, _Async], ids=["thread", "asyncio"])
def server(request):
    return request.param(lease_backend=InMemoryLeaseBackend())


def _message(
    message_type: DHCPMessageType,
    *,
    ciaddr: str = "0.0.0.0",
    lease_time: "int | None" = None,
    requested: "list[DHCPOptionCode] | None" = None,
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = message_type
    if lease_time is not None:
        options[LEASE_TIME] = lease_time
    if requested is not None:
        options[DHCPOptionCode.PARAMETER_REQUEST_LIST] = requested
    return build_request(options=options, ciaddr=IPv4(ciaddr))


def _context(transport: Mock) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=transport,
        interface=NetworkInterface("eth0", SERVED),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


def _reply(server, message: DHCPMessage, handler: str) -> DHCPMessage:
    transport = Mock(send=Mock(return_value=1))
    getattr(server, handler)(message, _context(transport))
    assert transport.send.called, "no reply was sent"
    return DHCPMessage.decode(bytearray(transport.send.call_args[0][0]))


def _times(reply: DHCPMessage):
    return (
        reply.options.get(LEASE_TIME),
        reply.options.get(T1),
        reply.options.get(T2),
    )


def _offer(server, seconds: int, **options) -> DHCPMessage:
    """The OFFER for a lease of `seconds`, the time the client asked for."""
    server.lease = DHCPLease(
        ADDRESS,
        datetime.now(timezone.utc) + timedelta(seconds=seconds),
        offered=True,
        options=options.get("options"),
    )
    return _reply(
        server,
        _message(
            DHCPMessageType.DHCPDISCOVER,
            lease_time=seconds,
            requested=options.get("requested"),
        ),
        "handle_discover",
    )


def _renewal(server, seconds_left: int, options=None) -> DHCPMessage:
    """The ACK to a renewal of a lease with `seconds_left` to run."""
    server.lease = DHCPLease(
        ADDRESS,
        datetime.now(timezone.utc) + timedelta(seconds=seconds_left),
        options=options,
    )
    return _reply(
        server,
        _message(DHCPMessageType.DHCPREQUEST, ciaddr=str(ADDRESS)),
        "handle_request",
    )


def test_an_offer_carries_half_and_seven_eighths_of_the_lease_time(server) -> None:
    offer = _offer(server, 300)

    assert (
        offer.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) is DHCPMessageType.DHCPOFFER
    )
    assert _times(offer) == (300, 150, 262)


def test_an_ack_carries_half_and_seven_eighths_of_the_lease_time(server) -> None:
    ack = _renewal(server, 300)

    assert ack.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) is DHCPMessageType.DHCPACK
    assert _times(ack) == (300, 150, 262)


def test_a_renewal_follows_the_time_that_is_left(server) -> None:
    """RFC 2131 s4.4.5: the values are adjusted to the time remaining on the lease."""
    assert _times(_renewal(server, 100)) == (100, 50, 87)


@pytest.mark.parametrize(
    "seconds, t1, t2", [(60, 30, 52), (61, 30, 53), (301, 150, 263), (3600, 1800, 3150)]
)
def test_the_values_are_rounded_down(server, seconds, t1, t2) -> None:
    assert _times(_offer(server, seconds)) == (seconds, t1, t2)


def test_the_values_are_whole_seconds_of_the_lease_time_in_the_same_reply(
    server,
) -> None:
    reply = _renewal(server, 1000)
    lease_time, t1, t2 = _times(reply)

    assert (t1, t2) == (lease_time // 2, lease_time * 7 // 8)
    assert t1 < t2 < lease_time


def test_an_infinite_lease_carries_neither(server) -> None:
    server.lease = DHCPLease(ADDRESS, None)
    ack = _reply(
        server,
        _message(DHCPMessageType.DHCPREQUEST, ciaddr=str(ADDRESS)),
        "handle_request",
    )

    assert _times(ack) == (INFINITE, None, None)


def test_the_ack_to_an_inform_carries_neither(server) -> None:
    ack = _reply(
        server,
        _message(DHCPMessageType.DHCPINFORM, ciaddr=str(ADDRESS)),
        "handle_inform",
    )

    assert ack.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) is DHCPMessageType.DHCPACK
    assert _times(ack) == (None, None, None)


def test_a_nak_carries_neither(server) -> None:
    server.lease = DHCPLease(
        ADDRESS, datetime.now(timezone.utc) + timedelta(seconds=300)
    )
    nak = _reply(
        server,
        _message(DHCPMessageType.DHCPREQUEST, ciaddr="10.0.0.99"),
        "handle_request",
    )

    assert nak.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) is DHCPMessageType.DHCPNAK
    assert _times(nak) == (None, None, None)


def test_a_value_the_lease_holds_is_kept_and_the_other_is_filled(server) -> None:
    held = DHCPOptions()
    held[T1] = 1000
    ack = _renewal(server, 300, options=held)

    assert _times(ack) == (300, 1000, 262)


def test_both_values_the_lease_holds_are_kept(server) -> None:
    held = DHCPOptions()
    held[T1] = 11
    held[T2] = 22
    offer = _offer(server, 300, options=held)

    assert _times(offer) == (300, 11, 22)


def test_a_request_list_without_them_does_not_remove_them(server) -> None:
    """Like the lease time, they are the server's to send, not the client's to ask for."""
    offer = _offer(server, 300, requested=[DHCPOptionCode.SUBNET_MASK])

    assert _times(offer) == (300, 150, 262)


def test_the_switch_off_sends_neither(server) -> None:
    server.RENEWAL_TIMES = False

    assert _times(_renewal(server, 300)) == (300, None, None)
    assert _times(_offer(server, 300)) == (300, None, None)


def test_the_switch_off_still_sends_what_the_lease_holds(
    server,
) -> None:
    server.RENEWAL_TIMES = False
    held = DHCPOptions()
    held[T1] = 1000

    ack = _renewal(server, 300, options=held)

    assert _times(ack) == (300, 1000, None)


def test_the_switch_is_a_class_attribute_that_is_on() -> None:
    assert DHCPServer.RENEWAL_TIMES is True
    assert AsyncDHCPServer.RENEWAL_TIMES is True


def test_the_options_follow_the_lease_time_in_the_reply(server) -> None:
    """The order of the options on the wire: lease time, then T1 and T2."""
    reply = _renewal(server, 300)
    order = [int(code) for code in reply.options.keys()]

    assert order.index(int(LEASE_TIME)) + 1 == order.index(int(T1))
    assert order.index(int(T1)) + 1 == order.index(int(T2))
