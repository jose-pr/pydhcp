"""One relay core under two sibling drivers.

`DHCPRelay` and `AsyncDHCPRelay` compose the same private core over their own
listener; neither is a subclass of the other, and a subclass of either that
overrides `handle` is the method called, on the handler thread.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import threading
import typing as _ty
from unittest.mock import Mock

import pytest

from conftest import CHADDR, build_request
from driving import WAIT_SECONDS, driver_params, serve
from pydhcp import (
    AsyncDHCPRelay,
    DHCPMessage,
    DHCPOptions,
    DHCPRelay,
    DHCPRequestContext,
    SocketAddress,
)
from pydhcp.listener import AsyncDHCPListener, DHCPListener
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType, DHCPOpcode
from pydhcp.relay._core import _RelayCore

IPv4 = ipaddress.IPv4Address
LOOPBACK = IPv4("127.0.0.1")


def test_the_drivers_are_siblings_over_one_core() -> None:
    assert issubclass(DHCPRelay, _RelayCore)
    assert issubclass(AsyncDHCPRelay, _RelayCore)
    assert not issubclass(AsyncDHCPRelay, DHCPRelay)
    assert not issubclass(DHCPRelay, AsyncDHCPRelay)
    assert not issubclass(_RelayCore, (DHCPListener, AsyncDHCPListener))
    assert issubclass(DHCPRelay, DHCPListener)
    assert issubclass(AsyncDHCPRelay, AsyncDHCPListener)


def test_an_async_relay_has_no_synchronous_lifecycle() -> None:
    relay = AsyncDHCPRelay(server_addresses=["192.0.2.1"])
    for name in ("__enter__", "__exit__", "close"):
        assert not hasattr(relay, name), name
    assert not isinstance(relay, DHCPRelay)


class _Recording:
    handled: "list[str]"

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        self.handled.append(threading.current_thread().name)
        super().handle(msg, context)  # type: ignore[misc]


class _RecordingSync(_Recording, DHCPRelay):
    pass


class _RecordingAsync(_Recording, AsyncDHCPRelay):
    pass


@pytest.mark.parametrize(
    "relay_class, loop_type", driver_params(_RecordingSync, _RecordingAsync)
)
def test_an_overridden_handle_is_called_and_the_request_is_forwarded_and_answered(
    relay_class: type, loop_type: _ty.Optional[type]
) -> None:
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.settimeout(WAIT_SECONDS)
    relay = relay_class(
        listen=("127.0.0.1", 0),
        server_addresses=[("127.0.0.1", upstream.getsockname()[1])],
    )
    relay.handled = []

    def exercise(port: int) -> "tuple[DHCPMessage, DHCPMessage]":
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(WAIT_SECONDS)
        try:
            discover = build_request(DHCPMessageType.DHCPDISCOVER, xid=0x0A0B0C0D)
            client.sendto(bytes(discover.encode()), ("127.0.0.1", port))
            data, relay_address = upstream.recvfrom(2048)
            forwarded = DHCPMessage.decode(data)
            offer = build_request(
                DHCPMessageType.DHCPOFFER,
                xid=0x0A0B0C0D,
                op=DHCPOpcode.BOOTREPLY,
                yiaddr=LOOPBACK,
                giaddr=forwarded.giaddr,
            )
            upstream.sendto(bytes(offer.encode()), relay_address)
            return forwarded, DHCPMessage.decode(client.recvfrom(2048)[0])
        finally:
            client.close()

    try:
        forwarded, answer = serve(relay, exercise, loop_type)
    finally:
        upstream.close()
    assert forwarded.hops == 1
    assert forwarded.giaddr == LOOPBACK
    assert answer.op == DHCPOpcode.BOOTREPLY
    assert answer.yiaddr == LOOPBACK
    # Both the request and the reply went through the override, on one thread.
    assert len(relay.handled) == 2
    assert len(set(relay.handled)) == 1
    assert relay.handled[0] != threading.current_thread().name
    assert relay.metrics.packets_sent == 2


# --- time arrives as an argument ---------------------------------------------


def _context(
    client_port: int, mono: _ty.Optional[float], client_ip: str = "10.0.0.5"
) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=Mock(ip=LOOPBACK),
        client=SocketAddress(IPv4(client_ip), client_port),
        client_mac=CHADDR,
        received_at=(
            None if mono is None else datetime.datetime.now(datetime.timezone.utc)
        ),
        received_monotonic=mono,
    )


def test_the_pending_table_ages_on_the_receive_time_of_each_datagram() -> None:
    """A request that reuses another client's transaction is refused until the
    first one is older than the TTL -- measured on the stamps, not on a clock."""
    relay = DHCPRelay(listen=("127.0.0.1", 0), server_addresses=["192.0.2.1"])
    request = build_request(DHCPMessageType.DHCPDISCOVER, xid=7)
    relay.handle(request, _context(68, 1000.0))
    relay.handle(
        request, _context(99, 1000.0 + relay.PENDING_TTL_SECONDS - 1, "10.0.0.6")
    )
    (entry,) = relay._pending_clients.values()
    assert entry.client.ip == IPv4("10.0.0.5")

    relay.handle(
        request, _context(99, 1000.0 + relay.PENDING_TTL_SECONDS + 1, "10.0.0.6")
    )
    (entry,) = relay._pending_clients.values()
    assert entry.client.ip == IPv4("10.0.0.6")
    assert entry.recorded_at == 1000.0 + relay.PENDING_TTL_SECONDS + 1
