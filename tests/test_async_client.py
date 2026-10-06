"""`AsyncDHCPClient`: the client's exchanges on an event loop.

Every exchange here runs on each loop type the platform has. Peers are real
sockets on loopback: a `DHCPServer`, an `AsyncDHCPServer`, and a scripted peer
that answers with exactly the datagrams a test chooses. Every wait has a timeout
with a second of margin and fails with a message; a pending exchange that is
cancelled leaves no task, no thread and no socket behind.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time
import types
import typing as _ty
from datetime import timedelta
from ipaddress import IPv4Address as IPv4

import pytest

from conftest import CHADDR, FixedLeaseServer, running
from driving import LOOPS, WAIT_SECONDS, threads_settle
from pydhcp import AsyncDHCPClient, DHCPMessage, DHCPOptions
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import (
    DHCPFlags,
    DHCPMessageType,
    DHCPOpcode,
    HardwareAddressType,
)
from pydhcp.server import AsyncDHCPServer

LOCAL = ("127.0.0.1", 0)
OTHER_CHADDR = b"\x00\xaa\xbb\xcc\xdd\xee"

loop_types = pytest.mark.parametrize("loop_type", LOOPS, ids=lambda t: t.__name__)


class _AsyncFixedLease(AsyncDHCPServer):
    LEASE_SECONDS = 60
    acquire_lease = FixedLeaseServer.acquire_lease  # type: ignore[assignment]


def _run(
    loop_type: type, main: _ty.Callable[[], _ty.Any], seconds: float = 12.0
) -> _ty.Any:
    """Run `main()` on a loop of `loop_type`, and check what it left behind."""
    threads_before = threading.active_count()
    loop = loop_type()
    try:
        result = loop.run_until_complete(asyncio.wait_for(main(), seconds))
        assert not asyncio.all_tasks(loop), "a task outlived the test"
    finally:
        loop.close()
    threads_settle(threads_before)
    return result


def _reply(
    xid: int,
    message_type: DHCPMessageType = DHCPMessageType.DHCPOFFER,
    chaddr: bytes = CHADDR,
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = message_type
    options[DHCPOptionCode.SERVER_IDENTIFIER] = IPv4("127.0.0.1")
    return DHCPMessage(
        op=DHCPOpcode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=xid,
        secs=timedelta(0),
        flags=DHCPFlags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("127.0.0.7"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=chaddr,
        sname="",
        file="",
        options=options,
    )


class _Peer:
    """A UDP peer on loopback that records what it receives and answers by script."""

    def __init__(
        self,
        answer: _ty.Optional[_ty.Callable[[DHCPMessage], "list[DHCPMessage]"]] = None,
    ) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(LOCAL)
        self.sock.settimeout(0.05)
        self.port: int = self.sock.getsockname()[1]
        self.received: "list[DHCPMessage]" = []
        self._answer = answer
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, source = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            message = DHCPMessage.decode(memoryview(data))
            self.received.append(message)
            if self._answer is not None:
                for reply in self._answer(message):
                    self.sock.sendto(reply.encode(), source)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(WAIT_SECONDS)
        assert not self._thread.is_alive(), "the peer thread outlived the test"
        self.sock.close()


def _message_type(message: DHCPMessage) -> _ty.Any:
    return message.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)


async def _until(predicate: _ty.Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out after {WAIT_SECONDS} s waiting for {what}")


def _is_ack(message: _ty.Optional[DHCPMessage]) -> bool:
    return message is not None and _message_type(message) == DHCPMessageType.DHCPACK


@loop_types
def test_a_dora_against_the_thread_based_server(loop_type: type) -> None:
    async def main() -> None:
        with running(FixedLeaseServer(listen=[LOCAL])) as server:
            port = server.bound_addresses[0].port
            async with AsyncDHCPClient(listen=LOCAL) as client:
                await client.start()
                ack = await client.dora(
                    CHADDR,
                    timeout=2.0,
                    retries=1,
                    destination="127.0.0.1",
                    port=port,
                    broadcast=False,
                )
                assert _is_ack(ack), ack
                assert ack is not None and ack.yiaddr == IPv4("127.0.0.1")
                assert client._pending_keys == set()
                assert client._waiters == {}
                assert client._worker is None, "the client needs no worker thread"

    _run(loop_type, main)


@loop_types
def test_a_dora_against_the_asyncio_server_on_the_same_loop(loop_type: type) -> None:
    async def main() -> None:
        async with _AsyncFixedLease(listen=[LOCAL]) as server:
            await server.start()
            port = server.bound_addresses[0].port
            async with AsyncDHCPClient(listen=LOCAL) as client:
                await client.start()
                offer = await client.discover_offer(
                    CHADDR,
                    timeout=2.0,
                    retries=1,
                    destination="127.0.0.1",
                    port=port,
                    broadcast=False,
                )
                assert offer is not None
                assert _message_type(offer) == DHCPMessageType.DHCPOFFER
                ack = await client.dora(
                    CHADDR,
                    timeout=2.0,
                    retries=1,
                    destination="127.0.0.1",
                    port=port,
                    broadcast=False,
                )
                assert _is_ack(ack), ack

    _run(loop_type, main)


@loop_types
def test_an_exchange_gives_up_after_the_schedule_and_not_before(
    loop_type: type,
) -> None:
    schedule = [0.2, 0.3]

    async def main() -> "tuple[float, list[DHCPMessage], int]":
        peer = _Peer()
        try:
            async with AsyncDHCPClient(listen=LOCAL) as client:
                await client.start()
                client._retransmit_intervals = (  # type: ignore[method-assign]
                    lambda timeout, retries: iter(schedule)
                )
                began = time.monotonic()
                offer = await client.discover_offer(
                    CHADDR, destination="127.0.0.1", port=peer.port, broadcast=False
                )
                elapsed = time.monotonic() - began
                assert offer is None
                assert client._pending_keys == set()
                assert client._waiters == {}
                await asyncio.sleep(0.1)  # the last datagram has reached the peer
                return elapsed, list(peer.received), client.metrics.packets_sent
        finally:
            peer.close()

    elapsed, received, sent = _run(loop_type, main)
    assert sum(schedule) - 0.05 <= elapsed <= sum(schedule) + 1.0, elapsed
    assert [_message_type(m) for m in received] == [DHCPMessageType.DHCPDISCOVER] * 2
    assert sent == 2
    # One transaction, retransmitted: secs counts up from the first send.
    assert len({m.xid for m in received}) == 1


@loop_types
def test_a_reply_for_another_transaction_or_client_is_ignored(
    loop_type: type,
) -> None:
    def answer(message: DHCPMessage) -> "list[DHCPMessage]":
        return [
            _reply(message.xid ^ 1),  # another transaction
            _reply(message.xid, chaddr=OTHER_CHADDR),  # another client
            _reply(message.xid, DHCPMessageType.DHCPNAK),  # not the awaited kind
            _reply(message.xid),
        ]

    async def main() -> None:
        peer = _Peer(answer)
        seen: "list[DHCPMessage]" = []
        try:
            async with AsyncDHCPClient(listen=LOCAL) as client:
                client.on_reply = lambda msg, context: seen.append(msg)  # type: ignore[method-assign]
                await client.start()
                offer = await client.discover_offer(
                    CHADDR,
                    timeout=2.0,
                    retries=0,
                    destination="127.0.0.1",
                    port=peer.port,
                    broadcast=False,
                )
                assert offer is not None
                assert offer.xid == peer.received[0].xid
                assert _message_type(offer) == DHCPMessageType.DHCPOFFER
                # The two foreign replies never reached the hook; the matching
                # NAK and OFFER did (the exchange kept the one it waited for).
                await _until(lambda: len(seen) >= 2, "the matching replies")
                assert {m.chaddr for m in seen} == {CHADDR}
                assert {m.xid for m in seen} == {offer.xid}
        finally:
            peer.close()

    _run(loop_type, main)


@loop_types
def test_cancelling_a_pending_exchange_leaves_nothing_behind(loop_type: type) -> None:
    async def main() -> None:
        peer = _Peer()
        tasks_before = len(asyncio.all_tasks())
        try:
            async with AsyncDHCPClient(listen=LOCAL) as client:
                await client.start()
                receiving = len(asyncio.all_tasks())
                pending = asyncio.ensure_future(
                    client.dora(
                        CHADDR,
                        timeout=30.0,
                        retries=0,
                        destination="127.0.0.1",
                        port=peer.port,
                        broadcast=False,
                    )
                )
                await _until(lambda: peer.received, "the DISCOVER at the peer")
                assert client._waiters and client._pending_keys
                pending.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await pending
                assert client._waiters == {}
                assert client._pending_keys == set()
                assert len(asyncio.all_tasks()) == receiving, "the exchange left a task"
            sockets = list(client._sockets)
            assert sockets == [] and client.bound_addresses == ()
        finally:
            peer.close()
        await asyncio.sleep(0)
        assert len(asyncio.all_tasks()) <= tasks_before + 1

    _run(loop_type, main)


@loop_types
def test_two_exchanges_at_once_each_receive_their_own_reply(loop_type: type) -> None:
    async def main() -> None:
        with running(FixedLeaseServer(listen=[LOCAL])) as server:
            port = server.bound_addresses[0].port
            async with AsyncDHCPClient(listen=LOCAL) as client:
                await client.start()
                first, second = await asyncio.gather(
                    *[
                        client.dora(
                            chaddr,
                            timeout=2.0,
                            retries=1,
                            destination="127.0.0.1",
                            port=port,
                            broadcast=False,
                        )
                        for chaddr in (CHADDR, OTHER_CHADDR)
                    ]
                )
                assert _is_ack(first) and _is_ack(second)
                assert first is not None and second is not None
                assert first.chaddr == CHADDR
                assert second.chaddr == OTHER_CHADDR
                assert first.xid != second.xid
                assert client._waiters == {} and client._pending_keys == set()

    _run(loop_type, main)


@loop_types
def test_an_offer_without_a_server_identifier_is_refused(loop_type: type) -> None:
    def answer(message: DHCPMessage) -> "list[DHCPMessage]":
        offer = _reply(message.xid)
        del offer.options[int(DHCPOptionCode.SERVER_IDENTIFIER)]
        return [offer]

    async def main() -> None:
        peer = _Peer(answer)
        try:
            async with AsyncDHCPClient(listen=LOCAL) as client:
                await client.start()
                ack = await client.dora(
                    CHADDR,
                    timeout=1.0,
                    retries=0,
                    destination="127.0.0.1",
                    port=peer.port,
                    broadcast=False,
                )
                assert ack is None
                assert [_message_type(m) for m in peer.received] == [
                    DHCPMessageType.DHCPDISCOVER
                ]
        finally:
            peer.close()

    _run(loop_type, main)


class _StubbedClockClient(AsyncDHCPClient):
    """A client whose clock moves only when an exchange waits; nothing sleeps."""

    WAIT_COST = 3.0

    def __init__(self, *args: _ty.Any, **kwargs: _ty.Any) -> None:
        super().__init__(*args, **kwargs)
        self.now = 1000.0
        self.intervals: "list[float]" = []

    def _monotonic(self) -> float:
        return self.now

    async def _wait_for(
        self, waiter: _ty.Any, msg_type: _ty.Any, timeout: float
    ) -> None:
        self.intervals.append(timeout)
        self.now += self.WAIT_COST
        return None


@loop_types
def test_secs_counts_up_from_the_first_send(loop_type: type) -> None:
    """RFC 2131 s2: `secs` is the time since acquisition began, on every send."""

    async def main() -> "tuple[list[DHCPMessage], list[float]]":
        peer = _Peer()
        try:
            async with _StubbedClockClient(listen=LOCAL) as client:
                await client.start()
                assert (
                    await client.discover_offer(
                        CHADDR,
                        timeout=8.0,
                        retries=2,
                        destination="127.0.0.1",
                        port=peer.port,
                        broadcast=False,
                    )
                    is None
                )
                await _until(lambda: len(peer.received) == 3, "three datagrams")
                return list(peer.received), client.intervals
        finally:
            peer.close()

    received, intervals = _run(loop_type, main)
    assert [int(m.secs.total_seconds()) for m in received] == [0, 3, 6]
    assert len(intervals) == 3 and intervals == sorted(intervals)


@loop_types
def test_replies_to_an_idle_client_are_queued_bounded_and_drained(
    loop_type: type,
) -> None:
    async def main() -> None:
        async with AsyncDHCPClient(listen=LOCAL) as client:
            await client.start()
            assert client.drain_replies() == []
            assert await client.next_reply(timeout=0) is None
            assert await client.next_reply(timeout=0.05) is None
            port = client.bound_addresses[0].port
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for xid in range(client.MAX_QUEUED_REPLIES + 5):
                    # Delivered through handle(), as the receive task does.
                    client.handle(_reply(xid), None)  # type: ignore[arg-type]
                sender.sendto(_reply(0xFEED).encode(), ("127.0.0.1", port))
                await _until(lambda: client.metrics.packets_received >= 1, "a datagram")
            finally:
                sender.close()
            assert client.metrics.replies_dropped_overflow >= 5
            first = await client.next_reply(timeout=1.0)
            assert first is not None
            rest = client.drain_replies()
            assert len(rest) + 1 == client.MAX_QUEUED_REPLIES
            assert rest[-1][0].xid == 0xFEED
            assert client.drain_replies() == []

    _run(loop_type, main)


@loop_types
def test_next_reply_waits_for_a_reply(loop_type: type) -> None:
    async def main() -> None:
        async with AsyncDHCPClient(listen=LOCAL) as client:
            await client.start()
            waiting = asyncio.ensure_future(client.next_reply(timeout=3.0))
            await asyncio.sleep(0.05)
            assert not waiting.done()
            client.handle(_reply(5), None)  # type: ignore[arg-type]
            got = await asyncio.wait_for(waiting, WAIT_SECONDS)
            assert got is not None and got[0].xid == 5

    _run(loop_type, main)


@loop_types
def test_send_works_before_serving_starts(loop_type: type) -> None:
    async def main() -> None:
        peer = _Peer()
        try:
            async with AsyncDHCPClient(listen=LOCAL) as client:
                sent = await client.send(
                    client.build_discover(CHADDR, xid=9),
                    dst="127.0.0.1",
                    port=peer.port,
                )
                assert sent >= 300
                await _until(lambda: peer.received, "the datagram at the peer")
                assert peer.received[0].xid == 9
                assert client.metrics.packets_sent == 1
        finally:
            peer.close()

    _run(loop_type, main)


@loop_types
def test_send_after_close_is_refused(loop_type: type) -> None:
    async def main() -> None:
        client = AsyncDHCPClient(listen=LOCAL)
        await client.aclose()
        with pytest.raises(RuntimeError, match="closed"):
            await client.send(client.build_discover(CHADDR), dst="127.0.0.1", port=9)

    _run(loop_type, main)


@loop_types
def test_a_real_exchange_logs_nothing_loud(
    loop_type: type, caplog: pytest.LogCaptureFixture
) -> None:
    async def main() -> None:
        async with _AsyncFixedLease(listen=[LOCAL]) as server:
            await server.start()
            async with AsyncDHCPClient(listen=LOCAL) as client:
                await client.start()
                ack = await client.dora(
                    CHADDR,
                    timeout=2.0,
                    retries=1,
                    destination="127.0.0.1",
                    port=server.bound_addresses[0].port,
                    broadcast=False,
                )
                assert _is_ack(ack)

    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        _run(loop_type, main)
    loud = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert loud == []


@loop_types
def test_a_failed_send_leaves_no_transaction_accepted(loop_type: type) -> None:
    async def main() -> None:
        async with AsyncDHCPClient(listen=LOCAL) as client:
            client.bind()

            async def refuse(*_args: _ty.Any, **_kwargs: _ty.Any) -> int:
                raise OSError("network unreachable")

            sock = client._sockets[0]
            real = client._endpoints[sock]
            client._endpoints[sock] = types.SimpleNamespace(  # type: ignore[assignment]
                asend=refuse
            )
            try:
                message = client.build_discover(CHADDR, xid=3)
                with pytest.raises(OSError, match="unreachable"):
                    await client.send(message, dst="127.0.0.1", port=9)
                assert client._pending_keys == set()
                assert client.metrics.packets_sent == 0
            finally:
                client._endpoints[sock] = real

    _run(loop_type, main)
