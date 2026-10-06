"""Listening on one interface: one wildcard socket, and what arrives elsewhere is dropped.

A socket bound to an address hears no broadcast on most platforms, so serving one
interface means hearing them all and ignoring the rest, before decoding, with a
count.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import typing as ty

import netimps
import pytest
from driving import LOOPS

from conftest import build_request
from pydhcp import AsyncDHCPListener, DHCPListener

# the arrival record is not public
from pydhcp.listener._receive import _Arrival
from pydhcp import SocketAddress
from ipaddress import IPv4Address as IPv4


def _loopback() -> netimps.Interface:
    found = netimps.get_interface("127.0.0.1")
    assert found is not None and found.index
    return found


def _another_adapter() -> netimps.Interface:
    """An adapter with an IPv4 address that is not the loopback."""
    for adapter in netimps.get_interfaces():
        if (
            adapter.index
            and not adapter.is_loopback
            and adapter.ipv4
            and adapter.index != _loopback().index
            and ":" not in adapter.name
            and netimps.MACAddress.try_parse(adapter.name) is None
        ):
            return adapter
    pytest.skip("this host has no second adapter with an IPv4 address")


def _arrival(ifindex: ty.Optional[int]) -> _Arrival:
    return _Arrival(b"x" * 20, SocketAddress(IPv4("192.0.2.5"), 68), ifindex)


@pytest.mark.parametrize("driver", [DHCPListener, AsyncDHCPListener])
def test_a_limited_socket_admits_only_its_interfaces_and_counts_the_rest(
    driver: type,
) -> None:
    listener = driver(listen=(_loopback(), 0))
    listener.bind()
    try:
        (sock,) = listener._sockets
        allowed = listener._allowed[sock]
        assert allowed == frozenset({_loopback().index})

        assert listener._admits(_arrival(_loopback().index), sock)
        assert listener.metrics.packets_dropped_other_interface == 0
        assert not listener._admits(_arrival(_loopback().index + 100), sock)
        assert not listener._admits(_arrival(None), sock)
        assert listener.metrics.packets_dropped_other_interface == 2
    finally:
        if driver is DHCPListener:
            listener.close()
        else:
            asyncio.run(listener.aclose())


def test_an_unlimited_socket_admits_everything() -> None:
    listener = DHCPListener(listen=("*", 0))
    listener.bind()
    try:
        (sock,) = listener._sockets
        assert listener._allowed == {}
        assert listener._admits(_arrival(12345), sock)
        assert listener.metrics.packets_dropped_other_interface == 0
    finally:
        listener.close()


def test_the_wildcard_named_plainly_beside_an_interface_has_no_limit() -> None:
    listener = DHCPListener(listen="*:0,lo:0")
    assert listener._limits == {}


def test_a_drop_is_logged_once_through_the_limiter(caplog) -> None:
    import logging

    listener = DHCPListener(listen=(_loopback(), 0))
    listener.bind()
    try:
        (sock,) = listener._sockets
        with caplog.at_level(logging.DEBUG, logger="pydhcp"):
            for _ in range(50):
                listener._admits(_arrival(_loopback().index + 100), sock)
        lines = [
            r
            for r in caplog.records
            if "Dropping a datagram that arrived" in r.getMessage()
        ]
        # Only the first of a flood is written; the exact total is the counter.
        assert len(lines) == 1
        assert listener.metrics.packets_dropped_other_interface == 50
    finally:
        listener.close()


# -- on real sockets ---------------------------------------------------------------


def _send_over_loopback(port: int) -> None:
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(build_request().encode(), ("127.0.0.1", port))
    finally:
        sender.close()


class _Counting(DHCPListener):
    def __init__(self, *args: ty.Any, **kwargs: ty.Any) -> None:
        super().__init__(*args, **kwargs)
        self.handled: list = []

    def handle(self, msg: ty.Any, context: ty.Any) -> None:
        self.handled.append(context.ifindex)


class _AsyncCounting(AsyncDHCPListener):
    def __init__(self, *args: ty.Any, **kwargs: ty.Any) -> None:
        super().__init__(*args, **kwargs)
        self.handled: list = []

    def handle(self, msg: ty.Any, context: ty.Any) -> None:
        self.handled.append(context.ifindex)


def _settle(listener: ty.Any, handled_at_least: int, quiet: float = 0.4) -> None:
    """Wait for a handled datagram, or for a quiet period when none is due."""
    end = time.monotonic() + (3 if handled_at_least else quiet)
    while time.monotonic() < end:
        if len(listener.handled) >= handled_at_least and handled_at_least:
            return
        time.sleep(0.02)


def _serve_sync(spec: ty.Any, handled_at_least: int) -> _Counting:
    listener = _Counting(listen=spec, poll_interval=0.05)
    listener.bind()
    port = listener.bound_addresses[0].port
    thread = threading.Thread(target=listener.serve_forever, daemon=True)
    thread.start()
    try:
        _send_over_loopback(port)
        _settle(listener, handled_at_least)
    finally:
        listener.shutdown()
        thread.join(5)
        listener.close()
    return listener


def _serve_async(spec: ty.Any, handled_at_least: int, loop_type: type) -> ty.Any:
    listener = _AsyncCounting(listen=spec)

    async def scenario() -> None:
        await listener.start()
        try:
            _send_over_loopback(listener.bound_addresses[0].port)
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _settle, listener, handled_at_least)
        finally:
            await listener.aclose()

    loop = loop_type()
    try:
        loop.run_until_complete(scenario())
    finally:
        loop.close()
    return listener


def test_the_sync_listener_serves_its_interface_and_drops_the_others() -> None:
    mine = _serve_sync((_loopback(), 0), handled_at_least=1)
    assert mine.handled == [_loopback().index]
    assert mine.metrics.packets_dropped_other_interface == 0

    other = _serve_sync((_another_adapter(), 0), handled_at_least=0)
    assert other.handled == []
    assert other.metrics.packets_dropped_other_interface == 1
    assert other.metrics.packets_received == 0, "a dropped datagram was decoded"


@pytest.mark.parametrize("loop_type", LOOPS, ids=lambda loop: loop.__name__)
def test_the_async_listener_serves_its_interface_and_drops_the_others(
    loop_type: type,
) -> None:
    mine = _serve_async((_loopback(), 0), 1, loop_type)
    assert mine.handled == [_loopback().index]
    assert mine.metrics.packets_dropped_other_interface == 0

    other = _serve_async((_another_adapter(), 0), 0, loop_type)
    assert other.handled == []
    assert other.metrics.packets_dropped_other_interface == 1
    assert other.metrics.packets_received == 0


def test_the_wildcard_beside_an_interface_hears_every_interface() -> None:
    listener = _serve_sync(["*:0", (_another_adapter(), 0)], handled_at_least=1)
    assert listener.handled == [_loopback().index]
