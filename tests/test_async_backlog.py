"""The async listener's hand-off to its handler thread is bounded.

Every datagram goes to one worker thread, and the event loop reads as fast as
datagrams arrive, so a handler that blocks (a lease file write, a hook) let the
queue grow without limit. The bound is `max_queued`; a datagram past it is
dropped, counted in `metrics.packets_dropped_backlog` and reported at a limited
rate. Stopping discards what is queued, and counts it, instead of turning it
into errors.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import sys
import threading
import time
import typing as _ty

import pytest

from conftest import build_request
from pydhcp import AsyncDHCPServer
from pydhcp.capture import AsyncDHCPCapture
from pydhcp.listener import AsyncDHCPListener
from pydhcp.relay import AsyncDHCPRelay

PAYLOAD = build_request().encode()


class Blocked(AsyncDHCPListener):
    """A listener whose handler waits to be released."""

    def __init__(self, *args: _ty.Any, **kwargs: _ty.Any) -> None:
        super().__init__(*args, **kwargs)
        self.release = threading.Event()
        self.handled = 0

    def handle(self, msg: _ty.Any, context: _ty.Any) -> None:
        self.release.wait(10)
        self.handled += 1


def _loop_factories() -> "list[_ty.Any]":
    factories: "list[_ty.Any]" = [pytest.param(asyncio.new_event_loop, id="default")]
    selector = getattr(asyncio, "SelectorEventLoop", None)
    if selector is not None and sys.platform == "win32":
        factories.append(pytest.param(selector, id="selector"))
        factories.append(pytest.param(asyncio.ProactorEventLoop, id="proactor"))
    return factories


def _run(factory: _ty.Any, coroutine: "_ty.Coroutine[_ty.Any, _ty.Any, None]") -> None:
    loop = factory()
    try:
        loop.run_until_complete(coroutine)
    finally:
        loop.close()


async def _until(condition: "_ty.Callable[[], bool]", seconds: float = 10.0) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "timed out waiting for the listener"
        await asyncio.sleep(0.01)


async def _flood(port: int, count: int) -> None:
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for index in range(count):
            sender.sendto(PAYLOAD, ("127.0.0.1", port))
            if index % 10 == 9:
                await asyncio.sleep(0.005)
    finally:
        sender.close()


@pytest.mark.parametrize("factory", _loop_factories())
def test_a_blocked_handler_queues_no_more_than_the_bound(factory: _ty.Any) -> None:
    async def scenario() -> None:
        listener = Blocked(listen=("127.0.0.1", 0), max_queued=8)
        await listener.start()
        try:
            await _flood(listener.bound_addresses[0].port, 100)
            await _until(lambda: listener.metrics.packets_dropped_backlog >= 92)
            assert listener.metrics.packets_dropped_backlog == 92
            listener.release.set()
            await _until(lambda: listener.handled >= 8)
            await asyncio.sleep(0.2)
            assert listener.handled == 8
        finally:
            listener.release.set()
            await listener.stop()

    _run(factory, scenario())


def test_the_drops_are_reported_at_a_limited_rate(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        listener = Blocked(listen=("127.0.0.1", 0), max_queued=2)
        await listener.start()
        try:
            await _flood(listener.bound_addresses[0].port, 60)
            await _until(lambda: listener.metrics.packets_dropped_backlog >= 58)
        finally:
            listener.release.set()
            await listener.stop()

    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        _run(asyncio.new_event_loop, scenario())
    reports = [r for r in caplog.records if "backlog" in r.getMessage()]
    assert len(reports) == 1, [r.getMessage() for r in reports]
    assert "max_queued" in reports[0].getMessage()


@pytest.mark.parametrize("factory", _loop_factories())
def test_stopping_discards_the_queue_without_errors(
    factory: _ty.Any, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> Blocked:
        listener = Blocked(listen=("127.0.0.1", 0), max_queued=64)
        await listener.start()
        await _flood(listener.bound_addresses[0].port, 30)
        await _until(lambda: listener._pending >= 30)
        await listener.stop()
        listener.release.set()
        await _until(lambda: listener.handled >= 1)
        await asyncio.sleep(0.3)
        return listener

    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        holder: "list[Blocked]" = []

        async def run() -> None:
            holder.append(await scenario())

        _run(factory, run())
    listener = holder[0]
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
    assert listener.handled == 1  # the one already running; 29 were queued
    assert listener.metrics.packets_dropped_backlog == 29
    assert listener.metrics.packets_dropped_error == 0
    assert any("discarded 29" in r.getMessage() for r in caplog.records)


def test_the_bound_has_a_default_and_is_a_constructor_option() -> None:
    assert AsyncDHCPListener.MAX_QUEUED_DATAGRAMS == 1024
    assert AsyncDHCPListener(listen=("127.0.0.1", 0))._max_queued == 1024
    for made in (
        AsyncDHCPListener(listen=("127.0.0.1", 0), max_queued=7),
        AsyncDHCPServer(listen=("127.0.0.1", 0), max_queued=7),
        AsyncDHCPRelay(
            listen=("127.0.0.1", 0), server_addresses=["127.0.0.1"], max_queued=7
        ),
        AsyncDHCPCapture(listen=("127.0.0.1", 0), max_queued=7),
    ):
        assert made._max_queued == 7


@pytest.mark.parametrize("bad", [0, -1, 1.5, True])
def test_the_bound_must_be_a_positive_integer(bad: _ty.Any) -> None:
    with pytest.raises(ValueError, match="max_queued"):
        AsyncDHCPListener(listen=("127.0.0.1", 0), max_queued=bad)
