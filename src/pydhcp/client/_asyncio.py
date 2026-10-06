"""The asyncio client: the client's rules over the asyncio listener."""

from __future__ import annotations

import asyncio as _asyncio
import contextlib as _contextlib
import ipaddress as _ipaddress
import time as _time
import typing as _ty

from ..listener._asyncio import AsyncDHCPListener
from ..listener._receive import DHCPRequestContext
from ..listener._spec import ListenLike
from ..listener._transport import _dest_string
from ..options._codes import DHCPOptionCode
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage
from .._network import IPv4AddressLike
from ._core import (
    BROADCAST_DESTINATION,
    ClientIdentifierLike,
    Reply,
    _ClientCore,
)

__all__ = ["AsyncDHCPClient"]

_SERVER_PORT = int(_enum.DHCPPort.SERVER)


class AsyncDHCPClient(_ClientCore, AsyncDHCPListener):
    """`DHCPClient` on an event loop: the same messages, matching and backoff.

    `discover_offer`, `dora` and `send` are coroutines taking the same keywords
    as the synchronous client's. The receive tasks must be running (`start()` or
    `serve_forever()`) for an exchange to hear a reply. `handle()` and
    `on_reply()` run on the event loop, not on a worker thread, so `on_reply`
    must not block. Any number of exchanges may be pending at once, each on its
    own transaction and client.
    """

    #: A reply is only moved into a loop-owned queue, so it is handled where it
    #: arrives and no worker thread exists.
    _HANDLE_ON_WORKER = False

    def __init__(
        self,
        listen: ListenLike = None,
        *,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
        reuse_address: _ty.Optional[bool] = None,
        receive_buffer_size: _ty.Optional[int] = None,
    ) -> None:
        AsyncDHCPListener.__init__(
            self,
            listen=listen,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
            reuse_address=reuse_address,
            receive_buffer_size=receive_buffer_size,
        )
        self._init_client_state()
        #: Created on first use, on the loop that serves: before Python 3.10 a
        #: queue binds to the current loop when it is constructed.
        self._replies: _ty.Optional[_asyncio.Queue[Reply]] = None
        #: Exchange key -> the queue the task running that exchange waits on.
        self._waiters: dict[tuple[int, bytes], _asyncio.Queue[Reply]] = {}

    async def send(
        self,
        message: DHCPMessage,
        *,
        dst: IPv4AddressLike = BROADCAST_DESTINATION,
        port: int = _SERVER_PORT,
    ) -> int:
        if not self._sockets:
            self.bind()
        endpoint = self._endpoints[self._sockets[0]]
        data = self._encode(message)
        # Expected before the send, not after: the reply can be handled on the
        # loop turn between the datagram leaving and this coroutine resuming.
        key = self._pending_key(message)
        was_pending = key in self._pending_keys
        self._pending_keys.add(key)
        try:
            sent = await endpoint.asend(
                bytes(data),
                _dest_string(_ipaddress.IPv4Address(dst)),
                int(port),
            )
        except BaseException:
            if not was_pending:
                self._pending_keys.discard(key)
            raise
        self.metrics.packets_sent += 1
        return int(sent)

    def _monotonic(self) -> float:
        """Monotonic clock, as one override point for every timing decision."""
        return _time.monotonic()

    async def _exchange(
        self,
        message: DHCPMessage,
        msg_type: _enum.DHCPMessageType,
        *,
        destination: IPv4AddressLike,
        port: int,
        timeout: float,
        retries: int,
        started_at: float,
    ) -> _ty.Optional[DHCPMessage]:
        """Send `message`, retransmitting on RFC 2131 s4.1 backoff, until `msg_type`."""
        key = self._pending_key(message)
        try:
            with self._waiting_for(key) as waiter:
                for interval in self._retransmit_intervals(timeout, retries):
                    self._stamp_secs(message, self._monotonic() - started_at)
                    await self.send(message, dst=destination, port=port)
                    reply = await self._wait_for(waiter, msg_type, interval)
                    if reply is not None:
                        return reply
                return None
        finally:
            # Also on cancellation: a spent transaction does not stay acceptable.
            self._pending_keys.discard(key)

    @_contextlib.contextmanager
    def _waiting_for(
        self, key: tuple[int, bytes]
    ) -> _ty.Iterator[_asyncio.Queue[Reply]]:
        """Claim the replies for one exchange for the duration of the block.

        Two blocks open on the *same* key are one exchange and share the queue;
        only the outer one removes it. Nothing awaits inside, so the table
        needs no lock: it is only touched on the loop.
        """
        waiter = self._waiters.get(key)
        owned = waiter is None
        if waiter is None:
            waiter = self._waiters[key] = _asyncio.Queue(
                maxsize=self.MAX_QUEUED_REPLIES
            )
        try:
            yield waiter
        finally:
            if owned and self._waiters.get(key) is waiter:
                del self._waiters[key]

    async def _wait_for(
        self,
        waiter: _asyncio.Queue[Reply],
        msg_type: _enum.DHCPMessageType,
        timeout: float,
    ) -> _ty.Optional[DHCPMessage]:
        """Take the first reply of `msg_type` from one exchange's own queue."""
        deadline = self._monotonic() + timeout
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return None
            try:
                msg, _context = await _asyncio.wait_for(waiter.get(), remaining)
            except _asyncio.TimeoutError:
                return None
            if not self._is_awaited(msg, msg_type):
                continue
            return msg

    async def discover_offer(
        self,
        chaddr: bytes,
        *,
        timeout: float = 2.0,
        retries: int = 2,
        destination: IPv4AddressLike = BROADCAST_DESTINATION,
        port: int = _SERVER_PORT,
        xid: _ty.Optional[int] = None,
        client_identifier: _ty.Optional[ClientIdentifierLike] = None,
        parameter_request_list: _ty.Optional[_ty.Iterable[DHCPOptionCode]] = None,
        broadcast: bool = True,
    ) -> _ty.Optional[DHCPMessage]:
        """Broadcast DHCPDISCOVER and return the first DHCPOFFER, or None.

        `timeout` is the initial retransmission interval, as in
        `DHCPClient.discover_offer`. Cancelling the call abandons the exchange.
        """
        discover = self.build_discover(
            chaddr,
            xid=xid,
            client_identifier=client_identifier,
            parameter_request_list=parameter_request_list,
            broadcast=broadcast,
        )
        return await self._exchange(
            discover,
            _enum.DHCPMessageType.DHCPOFFER,
            destination=destination,
            port=port,
            timeout=timeout,
            retries=retries,
            started_at=self._monotonic(),
        )

    async def dora(
        self,
        chaddr: bytes,
        *,
        timeout: float = 2.0,
        retries: int = 2,
        destination: IPv4AddressLike = BROADCAST_DESTINATION,
        port: int = _SERVER_PORT,
        xid: _ty.Optional[int] = None,
        client_identifier: _ty.Optional[ClientIdentifierLike] = None,
        parameter_request_list: _ty.Optional[_ty.Iterable[DHCPOptionCode]] = None,
        broadcast: bool = True,
    ) -> _ty.Optional[DHCPMessage]:
        """Run a full DISCOVER/OFFER/REQUEST/ACK exchange and return the DHCPACK, or None."""
        # RFC 2131 s2: `secs` counts from the start of *acquisition*.
        started_at = self._monotonic()
        offer = await self.discover_offer(
            chaddr,
            timeout=timeout,
            retries=retries,
            destination=destination,
            port=port,
            xid=xid,
            client_identifier=client_identifier,
            parameter_request_list=parameter_request_list,
            broadcast=broadcast,
        )
        if offer is None:
            return None
        request = self._request_after(
            offer,
            chaddr,
            client_identifier=client_identifier,
            parameter_request_list=parameter_request_list,
            broadcast=broadcast,
        )
        if request is None:
            return None
        return await self._exchange(
            request,
            _enum.DHCPMessageType.DHCPACK,
            destination=destination,
            port=port,
            timeout=timeout,
            retries=retries,
            started_at=started_at,
        )

    def _shared_replies(self) -> _asyncio.Queue[Reply]:
        if self._replies is None:
            self._replies = _asyncio.Queue(maxsize=self.MAX_QUEUED_REPLIES)
        return self._replies

    def _deliver(
        self, key: tuple[int, bytes], msg: DHCPMessage, context: DHCPRequestContext
    ) -> None:
        waiter = self._waiters.get(key)
        self._put_bounded(
            waiter if waiter is not None else self._shared_replies(), (msg, context)
        )

    def _put_bounded(self, replies: _asyncio.Queue[Reply], item: Reply) -> None:
        """Enqueue, discarding the oldest rather than growing without bound."""
        while True:
            try:
                replies.put_nowait(item)
                return
            except _asyncio.QueueFull:
                replies.get_nowait()
                self.metrics.replies_dropped_overflow += 1

    async def next_reply(
        self, timeout: _ty.Optional[float] = None
    ) -> _ty.Optional[Reply]:
        """The oldest queued reply, waiting up to `timeout` seconds; `None` if none came."""
        replies = self._shared_replies()
        try:
            return replies.get_nowait()
        except _asyncio.QueueEmpty:
            pass
        if timeout is not None and timeout <= 0:
            return None
        try:
            return await _asyncio.wait_for(replies.get(), timeout)
        except _asyncio.TimeoutError:
            return None

    def drain_replies(self) -> list[Reply]:
        replies: list[Reply] = []
        queue = self._replies
        while queue is not None:
            try:
                replies.append(queue.get_nowait())
            except _asyncio.QueueEmpty:
                break
        return replies
