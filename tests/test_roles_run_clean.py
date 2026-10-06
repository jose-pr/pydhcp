"""A real exchange through each role leaves no warning or error in the log.

A per-datagram `try` logs and carries on, so a hook that raises, or an attribute
that shadows a method of the same name on a base class, shows up as a logged
record while the exchange itself still looks fine. Each role here serves real
datagrams on its own driver, on each Windows loop type, with the `pydhcp` loggers
captured, and the test fails on any record at WARNING or above.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import typing as _ty

import pytest

from conftest import CHADDR, FixedLeaseServer, build_request, running
from driving import LOOPS, WAIT_SECONDS, wait_for
from pydhcp import DHCPClient
from pydhcp.capture import AsyncDHCPCapture, DHCPCapture
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
from pydhcp.relay import AsyncDHCPRelay, DHCPRelay
from pydhcp.server import AsyncDHCPServer

LOCAL = ("127.0.0.1", 0)


class _AsyncFixedLease(AsyncDHCPServer):
    LEASE_SECONDS = 60
    acquire_lease = FixedLeaseServer.acquire_lease  # type: ignore[assignment]


def _dora(port: int) -> None:
    with running(DHCPClient(listen=LOCAL)) as client:
        ack = client.dora(
            CHADDR,
            timeout=2.0,
            retries=1,
            destination="127.0.0.1",
            port=port,
            broadcast=False,
        )
    assert ack is not None, "no ACK"
    assert ack.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == DHCPMessageType.DHCPACK


def _loud(caplog: pytest.LogCaptureFixture) -> "list[str]":
    return [
        f"{r.name} {r.levelname}: {r.getMessage()}"
        for r in caplog.records
        if r.levelno >= logging.WARNING
    ]


def test_sync_server_and_relay(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        with running(FixedLeaseServer(listen=[LOCAL])) as server:
            relay = DHCPRelay(
                listen=[LOCAL],
                server_addresses=[("127.0.0.1", server.bound_addresses[0].port)],
            )
            with running(relay):
                _dora(relay.bound_addresses[0].port)
    assert _loud(caplog) == []


def test_sync_capture(caplog: pytest.LogCaptureFixture) -> None:
    seen: "list[_ty.Any]" = []
    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        with running(DHCPCapture(listen=[LOCAL], sink=seen.append)) as capture:
            _send_discover(capture.bound_addresses[0].port)
            wait_for(lambda: seen, "the captured event")
    assert _loud(caplog) == []


def _send_discover(port: int) -> None:
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(build_request().encode(), ("127.0.0.1", port))
    finally:
        sender.close()


@pytest.mark.parametrize("loop_type", LOOPS, ids=lambda t: t.__name__)
def test_async_server_relay_and_capture(
    loop_type: type, caplog: pytest.LogCaptureFixture
) -> None:
    seen: "list[_ty.Any]" = []

    async def main() -> None:
        loop = asyncio.get_running_loop()
        async with _AsyncFixedLease(listen=[LOCAL]) as server:
            await server.start()
            async with AsyncDHCPRelay(
                listen=[LOCAL],
                server_addresses=[("127.0.0.1", server.bound_addresses[0].port)],
            ) as relay:
                await relay.start()
                await loop.run_in_executor(None, _dora, relay.bound_addresses[0].port)
        async with AsyncDHCPCapture(listen=[LOCAL], sink=seen.append) as capture:
            await capture.start()
            await loop.run_in_executor(
                None, _send_discover, capture.bound_addresses[0].port
            )
            deadline = loop.time() + WAIT_SECONDS
            while not seen and loop.time() < deadline:
                await asyncio.sleep(0.01)

    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        loop = loop_type()
        try:
            loop.run_until_complete(asyncio.wait_for(main(), WAIT_SECONDS * 4))
        finally:
            loop.close()
    assert seen, "the capture saw nothing"
    assert _loud(caplog) == []
