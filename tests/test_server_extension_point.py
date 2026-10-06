"""`acquire_lease` is a method of the server it is defined on.

It used to run on a throwaway copy of the server for the probe that precedes an
OFFER or an ACK, so the obvious address pool, which keeps the next free host in
an attribute, gave every client the first address. It now runs on the server
itself, and the `commit` keyword says whether the call may extend or create a
binding.
"""

from __future__ import annotations

import ipaddress
import typing as _ty
from unittest.mock import Mock

from conftest import build_request
from pydhcp import (
    DHCPLease,
    DHCPMessage,
    DHCPOptions,
    NetworkInterface,
    DHCPRequestContext,
)
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.network import IPv4, SocketAddress
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
from pydhcp.server import DHCPServer

SERVER = IPv4("10.0.0.1")


def _mac(n: int) -> bytes:
    return bytes([0x00, 0x11, 0x22, 0x33, 0x44, n])


def _context(transport: Mock, mac: bytes) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=transport,
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=mac,
    )


class CounterPool(DHCPServer):
    """The smallest pool a user would write: the next free host in an attribute."""

    def __init__(self) -> None:
        super().__init__(lease_backend=InMemoryLeaseBackend())
        self.next_host = 100
        self.calls: "list[tuple[object, bool]]" = []

    def acquire_lease(
        self,
        client_id: str,
        server_id: IPv4,
        msg: DHCPMessage,
        *,
        commit: bool = True,
    ) -> _ty.Optional[DHCPLease]:
        self.calls.append((self, commit))
        existing = self.lease_backend.lookup(client_id)
        if existing is not None:
            return existing
        ip = IPv4(f"10.0.0.{self.next_host}")
        self.next_host += 1
        return self.lease_backend.allocate(client_id, ip, 3600, DHCPOptions())


def _exchange(server: DHCPServer, n: int) -> "tuple[str, str]":
    """DISCOVER then REQUEST for client `n`; the offered and the acked address."""
    transport = Mock(send=Mock(return_value=1))
    context = _context(transport, _mac(n))
    server.handle(
        build_request(DHCPMessageType.DHCPDISCOVER, chaddr=_mac(n), xid=n), context
    )
    offer = DHCPMessage.decode(transport.send.call_args.args[0])
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPREQUEST
    options[DHCPOptionCode.REQUESTED_IP] = offer.yiaddr
    options[DHCPOptionCode.SERVER_IDENTIFIER] = SERVER
    server.handle(
        build_request(
            DHCPMessageType.DHCPREQUEST, options=options, chaddr=_mac(n), xid=n
        ),
        context,
    )
    ack = DHCPMessage.decode(transport.send.call_args.args[0])
    return str(offer.yiaddr), str(ack.yiaddr)


def test_a_pool_that_keeps_its_counter_on_the_server_gives_each_client_its_own() -> (
    None
):
    server = CounterPool()
    results = [_exchange(server, n) for n in (1, 2, 3)]

    assert [offer for offer, _ack in results] == [
        "10.0.0.100",
        "10.0.0.101",
        "10.0.0.102",
    ]
    assert results == [(ip, ip) for ip, _ in results], "an ACK changed the address"
    bound = {lease.ip for lease in server.lease_backend._leases.values()}  # type: ignore[attr-defined]
    assert len(bound) == 3
    assert server.next_host == 103


def test_the_override_runs_on_the_server_itself_and_is_told_what_kind_of_call() -> None:
    """A DISCOVER is one call that commits nothing; a REQUEST is two, the
    decision first and the commit second."""
    server = CounterPool()
    transport = Mock(send=Mock(return_value=1))
    context = _context(transport, _mac(1))

    server.handle(
        build_request(DHCPMessageType.DHCPDISCOVER, chaddr=_mac(1), xid=1), context
    )
    assert [commit for _who, commit in server.calls] == [False]

    server.calls.clear()
    offer = DHCPMessage.decode(transport.send.call_args.args[0])
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPREQUEST
    options[DHCPOptionCode.REQUESTED_IP] = offer.yiaddr
    options[DHCPOptionCode.SERVER_IDENTIFIER] = SERVER
    server.handle(
        build_request(
            DHCPMessageType.DHCPREQUEST, options=options, chaddr=_mac(1), xid=1
        ),
        context,
    )
    assert [commit for _who, commit in server.calls] == [False, True]
    assert all(who is server for who, _commit in server.calls)
