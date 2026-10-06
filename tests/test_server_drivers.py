"""One server core under two sibling drivers.

`DHCPServer` and `AsyncDHCPServer` compose the same private core over their own
listener; neither is a subclass of the other. A user subclass of either driver
overrides the same hooks, and each one is the method that gets called, on the
handler thread, whichever driver received the datagram.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import socket
import sys
import threading
import time
import typing as _ty
from unittest.mock import Mock

import pytest

from conftest import CHADDR, build_request
from driving import WAIT_SECONDS, driver_params, serve
from pydhcp import (
    AsyncDHCPServer,
    DHCPLease,
    DHCPMessage,
    DHCPOptions,
    DHCPRequestContext,
    DHCPServer,
    SocketAddress,
)
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
from pydhcp.listener import AsyncDHCPListener, DHCPListener
from pydhcp.server._core import _ServerCore

IPv4 = ipaddress.IPv4Address
LOOPBACK = IPv4("127.0.0.1")


def test_the_drivers_are_siblings_over_one_core() -> None:
    assert issubclass(DHCPServer, _ServerCore)
    assert issubclass(AsyncDHCPServer, _ServerCore)
    assert not issubclass(AsyncDHCPServer, DHCPServer)
    assert not issubclass(DHCPServer, AsyncDHCPServer)
    assert issubclass(DHCPServer, DHCPListener)
    assert not issubclass(DHCPServer, AsyncDHCPListener)
    assert issubclass(AsyncDHCPServer, AsyncDHCPListener)
    assert not issubclass(AsyncDHCPServer, DHCPListener)


def test_the_core_owns_no_listener() -> None:
    assert not issubclass(_ServerCore, (DHCPListener, AsyncDHCPListener))
    for name in (
        "bind",
        "start",
        "shutdown",
        "wait_closed",
        "close",
        "serve_forever",
        "bound_addresses",
    ):
        assert not hasattr(_ServerCore, name), name


def test_an_async_server_has_the_asynchronous_lifecycle_only() -> None:
    """`async with` and `aclose()`; the blocking context manager and `close()` it
    once picked up from the sync listener raised `AttributeError` and are gone."""
    server = AsyncDHCPServer(listen=("127.0.0.1", 0))
    for name in ("__enter__", "__exit__", "close", "listen", "stop", "wait"):
        assert not hasattr(server, name), name
    for name in ("__aenter__", "__aexit__", "aclose", "start", "wait_closed"):
        assert hasattr(server, name), name
    assert not isinstance(server, DHCPServer)


# --- the hooks, through real datagrams on both drivers -----------------------


class _Recording:
    """Every override point, recording that it was the one called."""

    calls: "list[tuple[str, str]]"

    def _note(self, name: str) -> None:
        self.calls.append((name, threading.current_thread().name))

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        self._note("handle")
        super().handle(msg, context)  # type: ignore[misc]

    def handle_discover(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        self._note("handle_discover")
        super().handle_discover(msg, context)  # type: ignore[misc]

    def handle_request(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        self._note("handle_request")
        super().handle_request(msg, context)  # type: ignore[misc]

    def handle_decline(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        self._note("handle_decline")
        super().handle_decline(msg, context)  # type: ignore[misc]

    def handle_release(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        self._note("handle_release")
        super().handle_release(msg, context)  # type: ignore[misc]

    def handle_inform(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        self._note("handle_inform")
        super().handle_inform(msg, context)  # type: ignore[misc]

    def acquire_lease(
        self, client_id: str, server_id: IPv4, msg: DHCPMessage, *, commit: bool = True
    ) -> DHCPLease:
        self._note("acquire_lease")
        return DHCPLease(
            LOOPBACK,
            datetime.datetime.now() + datetime.timedelta(seconds=60),
            DHCPOptions(),
        )

    def release_lease(self, client_id: str, server_id: IPv4, msg: DHCPMessage) -> bool:
        self._note("release_lease")
        return super().release_lease(client_id, server_id, msg)  # type: ignore[misc,no-any-return]

    def get_inform_options(self, server_id: IPv4, msg: DHCPMessage) -> DHCPOptions:
        self._note("get_inform_options")
        return super().get_inform_options(server_id, msg)  # type: ignore[misc,no-any-return]

    # The one-argument form a subclass written against the documented hook has.
    def quarantine_address(self, ip: IPv4) -> None:
        self._note("quarantine_address")
        super().quarantine_address(ip)  # type: ignore[misc]


class _RecordingSync(_Recording, DHCPServer):
    pass


class _RecordingAsync(_Recording, AsyncDHCPServer):
    pass


class _BaseAllocation:
    """Does not override `acquire_lease`, so the base allocator runs."""

    calls: "list[tuple[str, str]]"

    def lease_seconds(self, msg: DHCPMessage) -> float:
        self.calls.append(("lease_seconds", threading.current_thread().name))
        return super().lease_seconds(msg)  # type: ignore[misc,no-any-return]


class _BaseAllocationSync(_BaseAllocation, DHCPServer):
    pass


class _BaseAllocationAsync(_BaseAllocation, AsyncDHCPServer):
    pass


def _datagram(kind: DHCPMessageType, **options: _ty.Any) -> bytes:
    bag = DHCPOptions()
    bag[DHCPOptionCode.DHCP_MESSAGE_TYPE] = kind
    for code, value in options.items():
        bag[DHCPOptionCode[code]] = value
    fields: "dict[str, _ty.Any]" = {}
    if kind is DHCPMessageType.DHCPINFORM:
        fields["ciaddr"] = LOOPBACK
    return bytes(build_request(options=bag, **fields).encode())


def _exchange(port: int, datagrams: "list[bytes]", replies: int) -> "list[DHCPMessage]":
    """Send each datagram in turn, then read `replies` replies, all with timeouts."""
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(WAIT_SECONDS)
    try:
        for data in datagrams:
            client.sendto(data, ("127.0.0.1", port))
        found = []
        for _ in range(replies):
            found.append(DHCPMessage.decode(client.recvfrom(2048)[0]))
        return found
    finally:
        client.close()


def _wait_for_calls(server: _ty.Any, expected: "set[str]") -> None:
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        if expected <= {name for name, _thread in server.calls}:
            return
        time.sleep(0.01)
    missing = sorted(expected - {name for name, _thread in server.calls})
    raise AssertionError(f"hooks never called: {missing}; saw {server.calls}")


DRIVERS = driver_params(_RecordingSync, _RecordingAsync)


@pytest.mark.parametrize("server_class, loop_type", DRIVERS)
def test_each_override_point_is_the_subclass_method_on_the_handler_thread(
    server_class: type, loop_type: _ty.Optional[type]
) -> None:
    server = server_class(listen=("127.0.0.1", 0))
    server.calls = []
    server_id = LOOPBACK

    def exercise(port: int) -> "list[DHCPMessage]":
        replies = _exchange(
            port,
            [
                _datagram(DHCPMessageType.DHCPDISCOVER),
                _datagram(
                    DHCPMessageType.DHCPREQUEST,
                    REQUESTED_IP=LOOPBACK,
                    SERVER_IDENTIFIER=server_id,
                ),
                _datagram(DHCPMessageType.DHCPINFORM),
            ],
            replies=3,
        )
        _exchange(
            port,
            [
                _datagram(DHCPMessageType.DHCPDECLINE, REQUESTED_IP=LOOPBACK),
                _datagram(DHCPMessageType.DHCPRELEASE),
            ],
            replies=0,
        )
        _wait_for_calls(
            server,
            {
                "handle",
                "handle_discover",
                "handle_request",
                "handle_inform",
                "handle_decline",
                "handle_release",
                "acquire_lease",
                "release_lease",
                "get_inform_options",
                "quarantine_address",
            },
        )
        return replies

    replies = serve(server, exercise, loop_type)
    kinds = [r.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) for r in replies]
    assert kinds == [
        DHCPMessageType.DHCPOFFER,
        DHCPMessageType.DHCPACK,
        DHCPMessageType.DHCPACK,
    ]
    names = {thread for _name, thread in server.calls}
    assert len(names) == 1, f"hooks ran on more than one thread: {names}"
    (handler_thread,) = names
    assert handler_thread != threading.current_thread().name
    # DISCOVER decides once; REQUEST decides, then commits.
    assert [n for n, _t in server.calls].count("acquire_lease") == 3


@pytest.mark.parametrize(
    "server_class, loop_type", driver_params(_BaseAllocationSync, _BaseAllocationAsync)
)
def test_the_lease_policy_hook_is_called_by_the_base_allocator(
    server_class: type, loop_type: _ty.Optional[type]
) -> None:
    server = server_class(listen=("127.0.0.1", 0))
    server.calls = []

    def exercise(port: int) -> None:
        _exchange(
            port,
            [_datagram(DHCPMessageType.DHCPDISCOVER, REQUESTED_IP=IPv4("127.0.0.77"))],
            replies=0,
        )
        _wait_for_calls(server, {"lease_seconds"})

    serve(server, exercise, loop_type)
    assert server.metrics.leases_allocated == 1


# --- time arrives as an argument ---------------------------------------------


def _context(received_at: _ty.Optional[datetime.datetime], mono: _ty.Optional[float]):
    interface = Mock(ip=LOOPBACK)
    return DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=interface,
        client=SocketAddress(LOOPBACK, 68),
        client_mac=CHADDR,
        received_at=received_at,
        received_monotonic=mono,
    )


class _ExpiringLease(DHCPServer):
    def acquire_lease(self, client_id, server_id, msg, *, commit=True):  # type: ignore[no-untyped-def]
        return DHCPLease(
            LOOPBACK,
            datetime.datetime.now() + datetime.timedelta(seconds=100),
            DHCPOptions(),
        )


def test_the_receive_time_of_the_datagram_decides_whether_a_lease_has_time_left() -> (
    None
):
    """The context's stamp is the clock the core reads: a datagram that arrived an
    hour from now finds a 100-second lease expired and gets no OFFER."""
    server = _ExpiringLease(listen=("127.0.0.1", 0))
    discover = build_request(DHCPMessageType.DHCPDISCOVER)

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    on_time = _context(now, time.monotonic())
    server.handle_discover(discover, on_time)
    assert on_time.transport.send.call_count == 1

    late = _context(now + datetime.timedelta(hours=1), time.monotonic())
    server.handle_discover(discover, late)
    assert late.transport.send.call_count == 0


def test_the_quarantine_runs_on_the_time_it_is_given() -> None:
    server = DHCPServer(listen=("127.0.0.1", 0))
    ip = IPv4("127.0.0.9")
    interface = Mock(network=ipaddress.IPv4Network("127.0.0.0/8"), ip=LOOPBACK)
    server.quarantine_address(ip, now=1000.0)
    held = server.DECLINE_QUARANTINE_SECONDS
    assert server._address_refusal(ip, interface, "c", now=1000.0 + held - 1)
    assert server._address_refusal(ip, interface, "c", now=1000.0 + held + 1) is None


def test_a_hook_called_without_a_stamp_gets_the_drivers_reading() -> None:
    server = DHCPServer(listen=("127.0.0.1", 0))
    instant = server._instant(_context(None, None))
    assert instant.utc.tzinfo is not None
    assert abs(instant.monotonic - time.monotonic()) < 5
