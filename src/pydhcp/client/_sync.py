"""The thread-based client: the client's rules over the thread-based listener."""

from __future__ import annotations

import contextlib as _contextlib
import ipaddress as _ipaddress
import queue as _queue
import threading as _threading
import time as _time
import typing as _ty

from ..listener._receive import DHCPRequestContext
from ..listener._spec import ListenLike
from ..listener._sync import DHCPListener
from ..listener._transport import UDPTransport
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

__all__ = ["DHCPClient"]

_SERVER_PORT = int(_enum.DHCPPort.SERVER)


class DHCPClient(_ClientCore, DHCPListener):
    """Small DHCPv4 packet client for tests and troubleshooting.

    The base client builds and sends DHCP client messages, then queues matching
    replies. It does not configure operating-system network interfaces. Its
    receive thread must be running (`start()`) for an exchange to hear a reply.
    """

    def __init__(
        self,
        listen: ListenLike = None,
        *,
        poll_interval: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
        reuse_address: _ty.Optional[bool] = None,
        receive_buffer_size: _ty.Optional[int] = None,
    ) -> None:
        DHCPListener.__init__(
            self,
            listen=listen,
            poll_interval=poll_interval,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
            reuse_address=reuse_address,
            receive_buffer_size=receive_buffer_size,
        )
        self._init_client_state()
        self._replies: _queue.Queue[Reply] = _queue.Queue(
            maxsize=self.MAX_QUEUED_REPLIES
        )
        #: Exchange key -> the queue the thread running that exchange is
        #: waiting on. A reply for a key in here is handed to its own exchange
        #: instead of the shared queue, which is what lets two exchanges run on
        #: one client without eating each other's replies.
        self._waiters: dict[tuple[int, bytes], _queue.Queue[Reply]] = {}
        self._waiters_lock = _threading.Lock()

    def send(
        self,
        message: DHCPMessage,
        *,
        dst: IPv4AddressLike = BROADCAST_DESTINATION,
        port: int = _SERVER_PORT,
    ) -> int:
        if not self._sockets:
            self.bind()
        transport = UDPTransport(self._sockets[0])
        data = self._encode(message)
        sent = transport.send(
            data,
            _ipaddress.IPv4Address(dst),
            port=int(port),
            client_mac=message.chaddr,
        )
        self._note_sent(message)
        return sent

    def _monotonic(self) -> float:
        """Monotonic clock, as one override point for every timing decision.

        Retransmission intervals and `secs` are the only things here that read a
        clock, and a test that proved the backoff schedule by living through it
        would cost the suite the full 2+4+8 seconds of the default one. Stub
        this instead.
        """
        return _time.monotonic()

    def _exchange(
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
        """Send `message`, retransmitting on RFC 2131 s4.1 backoff, until `msg_type`.

        `started_at` is when *acquisition* began, not when this message was
        built: see `_stamp_secs`.
        """
        key = self._pending_key(message)
        try:
            # Registered before the first send, not inside the wait: a reply
            # that arrives in between is delivered by the receive thread, and
            # with no queue to route it to it would land in the shared one and
            # be invisible to the exchange that asked for it.
            with self._waiting_for(key) as waiter:
                for interval in self._retransmit_intervals(timeout, retries):
                    self._stamp_secs(message, self._monotonic() - started_at)
                    self.send(message, dst=destination, port=port)
                    reply = self._wait_for(waiter, msg_type, interval)
                    if reply is not None:
                        return reply
                return None
        finally:
            # The exchange is over either way. Left in place, this set only ever
            # grew, and every later replay of a spent xid -- visible to anyone on
            # the segment, since these go out as broadcasts -- stayed acceptable
            # forever. dora() re-registers its own REQUEST.
            self._pending_keys.discard(key)

    @_contextlib.contextmanager
    def _waiting_for(self, key: tuple[int, bytes]) -> _ty.Iterator[_queue.Queue[Reply]]:
        """Claim the replies for one exchange for the duration of the block.

        This is what keeps two exchanges on one client apart: `handle()` routes
        a reply straight to the queue of the exchange it belongs to, so a
        waiting exchange never has to read -- and therefore never has to discard
        -- a reply that is someone else's. Two blocks open on the *same* key are
        one exchange by definition and share the queue; only the outer one
        removes it.
        """
        with self._waiters_lock:
            waiter = self._waiters.get(key)
            owned = waiter is None
            if waiter is None:
                waiter = self._waiters[key] = _queue.Queue(
                    maxsize=self.MAX_QUEUED_REPLIES
                )
        try:
            yield waiter
        finally:
            if owned:
                with self._waiters_lock:
                    if self._waiters.get(key) is waiter:
                        del self._waiters[key]

    def _wait_for(
        self,
        waiter: _queue.Queue[Reply],
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
                msg, _context = waiter.get(timeout=remaining)
            except _queue.Empty:
                return None
            if not self._is_awaited(msg, msg_type):
                continue
            return msg

    def discover_offer(
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

        `timeout` is the *initial* retransmission interval, not a fixed one:
        each retransmission waits about twice as long as the last, jittered, up
        to `RETRANSMIT_MAX_INTERVAL` (RFC 2131 s4.1). With the defaults the
        whole call is bounded at roughly 2+4+8 seconds rather than 3x2.
        """
        discover = self.build_discover(
            chaddr,
            xid=xid,
            client_identifier=client_identifier,
            parameter_request_list=parameter_request_list,
            broadcast=broadcast,
        )
        return self._exchange(
            discover,
            _enum.DHCPMessageType.DHCPOFFER,
            destination=destination,
            port=port,
            timeout=timeout,
            retries=retries,
            started_at=self._monotonic(),
        )

    def dora(
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
        """Run a full DISCOVER/OFFER/REQUEST/ACK exchange and return the DHCPACK, or None.

        `timeout` is the initial retransmission interval for each half of the
        exchange -- see `discover_offer`.
        """
        # RFC 2131 s2: `secs` counts from the start of *acquisition*, so the
        # REQUEST half keeps counting from the DISCOVER rather than resetting.
        started_at = self._monotonic()
        offer = self.discover_offer(
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
            now=self._monotonic(),
        )
        if request is None:
            return None
        return self._exchange(
            request,
            _enum.DHCPMessageType.DHCPACK,
            destination=destination,
            port=port,
            timeout=timeout,
            retries=retries,
            started_at=started_at,
        )

    def _deliver(
        self, key: tuple[int, bytes], msg: DHCPMessage, context: DHCPRequestContext
    ) -> None:
        with self._waiters_lock:
            waiter = self._waiters.get(key)
        self._put_bounded(
            waiter if waiter is not None else self._replies, (msg, context)
        )

    def _put_bounded(self, replies: _queue.Queue[Reply], item: Reply) -> None:
        """Enqueue, discarding the oldest rather than growing without bound.

        Oldest rather than newest: a caller waiting on an exchange wants the
        recent ones. Measured before the cap existed: 50000 unsolicited
        BOOTREPLYs put 50000 entries in the queue of a client nobody was
        draining.
        """
        while True:
            try:
                replies.put_nowait(item)
                return
            except _queue.Full:
                try:
                    replies.get_nowait()
                    self.metrics.replies_dropped_overflow += 1
                except _queue.Empty:  # pragma: no cover - drained concurrently
                    pass

    def next_reply(self, timeout: _ty.Optional[float] = None) -> _ty.Optional[Reply]:
        try:
            return self._replies.get(timeout=timeout)
        except _queue.Empty:
            return None

    def drain_replies(self) -> list[Reply]:
        replies: list[Reply] = []
        while True:
            try:
                replies.append(self._replies.get_nowait())
            except _queue.Empty:
                return replies
