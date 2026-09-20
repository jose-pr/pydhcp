from __future__ import annotations

import contextlib as _contextlib
import datetime as _dt
import queue as _queue
import random as _random
import secrets as _secrets
import threading as _threading
import time as _time
import typing as _ty

from . import constants as _const, network as _net
from .packet import enums as _enum
from .listener import DhcpListener, ListenSpec, RequestContext, UdpTransport
from .packet.message import DhcpMessage
from .options import DhcpOptionCode, DhcpOptions
from .options import type as _type
from .log import LOGGER


class DhcpClient(DhcpListener):
    """Small DHCPv4 packet client for tests and troubleshooting.

    The base client builds and sends DHCP client messages, then queues matching
    replies. It does not configure operating-system network interfaces.
    """

    DEFAULT_PORTS = (_enum.DhcpPort.CLIENT,)

    #: Upper bound on undrained replies. An idle client accepts every BOOTREPLY
    #: on the segment so that `start()` + `on_reply` works as an observer, which
    #: on a busy network is unbounded growth when nobody calls `drain_replies()`.
    #: Past this the oldest is discarded and counted in
    #: `metrics.replies_dropped_overflow`.
    MAX_QUEUED_REPLIES = 1024

    #: Ceiling on the retransmission interval, from RFC 2131 s4.1: the delay
    #: "SHOULD be doubled with subsequent retransmissions up to a maximum of 64
    #: seconds".
    RETRANSMIT_MAX_INTERVAL = 64.0

    #: RFC 2131 s4.1 randomizes each interval "by the value of a uniform random
    #: number chosen from the range -1 to +1". That range is written against the
    #: RFC's own 4-second first delay; `timeout` here is caller-chosen and is
    #: often a fraction of a second in a test, where +/-1s would be both longer
    #: than the interval and able to drive it negative. So the amplitude is
    #: whichever is smaller, this or a quarter of the interval -- identical to
    #: the RFC once the interval reaches 4s, proportional below it.
    RETRANSMIT_JITTER_SECONDS = 1.0

    def __init__(
        self,
        listen: ListenSpec = None,
        select_timeout: float | None = None,
        max_packet_size: int | None = None,
        per_interface: bool | None = None,
    ) -> None:
        super().__init__(
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._replies: _queue.Queue[tuple[DhcpMessage, RequestContext]] = _queue.Queue(
            maxsize=self.MAX_QUEUED_REPLIES
        )
        self._pending_keys: set[tuple[int, bytes]] = set()
        #: Exchange key -> the queue the thread running that exchange is
        #: waiting on. A reply for a key in here is handed to its own exchange
        #: instead of the shared queue, which is what lets two exchanges run on
        #: one client without eating each other's replies.
        self._waiters: dict[
            tuple[int, bytes], _queue.Queue[tuple[DhcpMessage, RequestContext]]
        ] = {}
        self._waiters_lock = _threading.Lock()

    def build_discover(
        self,
        chaddr: bytes,
        *,
        xid: int | None = None,
        client_identifier: bytes | bytearray | None = None,
        parameter_request_list: _ty.Iterable[DhcpOptionCode] | None = None,
        broadcast: bool = True,
    ) -> DhcpMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=broadcast)
        msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = (
            _enum.DhcpMessageType.DHCPDISCOVER
        )
        self._add_client_options(msg, client_identifier, parameter_request_list)
        return msg

    def build_request(
        self,
        chaddr: bytes,
        *,
        xid: int | None = None,
        requested_ip: _net.IPv4 | str | None = None,
        server_identifier: _net.IPv4 | str | None = None,
        ciaddr: _net.IPv4 | str | None = None,
        client_identifier: bytes | bytearray | None = None,
        parameter_request_list: _ty.Iterable[DhcpOptionCode] | None = None,
        broadcast: bool = True,
    ) -> DhcpMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=broadcast)
        msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = (
            _enum.DhcpMessageType.DHCPREQUEST
        )
        if ciaddr is not None:
            msg.ciaddr = _net.IPv4(ciaddr)
        if requested_ip is not None:
            msg.options[DhcpOptionCode.REQUESTED_IP] = _net.IPv4(requested_ip)
        if server_identifier is not None:
            msg.options[DhcpOptionCode.SERVER_IDENTIFIER] = _net.IPv4(server_identifier)
        self._add_client_options(msg, client_identifier, parameter_request_list)
        return msg

    def build_inform(
        self,
        chaddr: bytes,
        *,
        ciaddr: _net.IPv4 | str,
        xid: int | None = None,
        client_identifier: bytes | bytearray | None = None,
        parameter_request_list: _ty.Iterable[DhcpOptionCode] | None = None,
    ) -> DhcpMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=False)
        msg.ciaddr = _net.IPv4(ciaddr)
        msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = _enum.DhcpMessageType.DHCPINFORM
        self._add_client_options(msg, client_identifier, parameter_request_list)
        return msg

    def build_release(
        self,
        chaddr: bytes,
        *,
        ciaddr: _net.IPv4 | str,
        server_identifier: _net.IPv4 | str | None = None,
        xid: int | None = None,
        client_identifier: bytes | bytearray | None = None,
    ) -> DhcpMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=False)
        msg.ciaddr = _net.IPv4(ciaddr)
        msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = (
            _enum.DhcpMessageType.DHCPRELEASE
        )
        if server_identifier is not None:
            msg.options[DhcpOptionCode.SERVER_IDENTIFIER] = _net.IPv4(server_identifier)
        self._add_client_options(msg, client_identifier, None)
        return msg

    def build_decline(
        self,
        chaddr: bytes,
        *,
        requested_ip: _net.IPv4 | str,
        server_identifier: _net.IPv4 | str | None = None,
        xid: int | None = None,
        client_identifier: bytes | bytearray | None = None,
    ) -> DhcpMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=True)
        msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = (
            _enum.DhcpMessageType.DHCPDECLINE
        )
        msg.options[DhcpOptionCode.REQUESTED_IP] = _net.IPv4(requested_ip)
        if server_identifier is not None:
            msg.options[DhcpOptionCode.SERVER_IDENTIFIER] = _net.IPv4(server_identifier)
        self._add_client_options(msg, client_identifier, None)
        return msg

    def send(
        self,
        message: DhcpMessage,
        destination: _net.IPv4 | str = _net.IPv4("255.255.255.255"),
        port: int = int(_enum.DhcpPort.SERVER),
    ) -> int:
        if not self._sockets:
            self.bind()
        transport = UdpTransport(self._sockets[0])
        data = message.encode(_const.DHCP_MIN_LEGAL_PACKET_SIZE)
        sent = transport.send(data, _net.IPv4(destination), int(port), message.chaddr)
        self._pending_keys.add(self._pending_key(message))
        self.metrics.packets_sent += 1
        return sent

    def _monotonic(self) -> float:
        """Monotonic clock, as one override point for every timing decision.

        Retransmission intervals and `secs` are the only things here that read a
        clock, and a test that proved the backoff schedule by living through it
        would cost the suite the full 2+4+8 seconds of the default one. Stub
        this instead.
        """
        return _time.monotonic()

    @staticmethod
    def _pending_key(msg: DhcpMessage) -> tuple[int, bytes]:
        """Identify an exchange by transaction *and* client, as the relay does.

        Matching on the xid alone is wrong in both directions, and both were
        measured on this client. Outward: a reply carrying a seen xid but a
        foreign `chaddr` was accepted, and the xid travels in cleartext in a
        broadcast DISCOVER, so any host on the segment can read one and answer
        it. Inward: two exchanges from one client share the reply stream, so the
        one that happened to be waiting consumed and discarded the other's
        reply, and the other timed out.

        Same shape as `DhcpRelay._pending_key`, including the `hlen` slice: a
        decoded message already trims `chaddr` to `hlen`, an in-memory one need
        not have.
        """
        return msg.xid, bytes(msg.chaddr[: msg.hlen or len(msg.chaddr)])

    def _retransmit_interval(self, attempt: int, initial: float) -> float:
        """How long to wait for a reply before retransmission `attempt`+1.

        RFC 2131 s4.1: the delay doubles with each retransmission up to 64
        seconds, randomized each time. The randomization is not decoration -- a
        fleet of clients that back off in lock-step retransmits in lock-step,
        which is the collision the jitter exists to break up.
        """
        # `2.0**attempt`, not `2**attempt`: int ** int is typed as returning
        # Any (a negative exponent gives a float), which silently spreads
        # through every value derived from it.
        interval = min(initial * 2.0**attempt, self.RETRANSMIT_MAX_INTERVAL)
        amplitude = min(self.RETRANSMIT_JITTER_SECONDS, interval / 4)
        jittered = interval + _random.uniform(-amplitude, amplitude)
        # Clamped, not just centred: "a maximum of 64 seconds" is the ceiling on
        # the delay itself, so at the cap the randomization is one-sided.
        return max(0.0, min(jittered, self.RETRANSMIT_MAX_INTERVAL))

    def _exchange(
        self,
        message: DhcpMessage,
        msg_type: _enum.DhcpMessageType,
        *,
        destination: _net.IPv4 | str,
        port: int,
        timeout: float,
        retries: int,
        started_at: float,
    ) -> DhcpMessage | None:
        """Send `message`, retransmitting on RFC 2131 s4.1 backoff, until `msg_type`.

        `started_at` is when *acquisition* began, not when this message was
        built: RFC 2131 s2 defines `secs` as "seconds elapsed since client began
        address acquisition or renewal process", so a DORA's REQUEST continues
        the DISCOVER's clock rather than restarting it. Servers and relays
        prioritise a long-suffering client on that field, and it was hardcoded
        to 0, so every retransmission looked brand new.
        """
        key = self._pending_key(message)
        try:
            # Registered before the first send, not inside the wait: a reply
            # that arrives in between is delivered by the receive thread, and
            # with no queue to route it to it would land in the shared one and
            # be invisible to the exchange that asked for it.
            with self._waiting_for(key) as waiter:
                for attempt in range(retries + 1):
                    elapsed = self._monotonic() - started_at
                    message.secs = _dt.timedelta(seconds=max(0.0, elapsed))
                    self.send(message, destination, port)
                    reply = self._wait_for(
                        waiter,
                        msg_type,
                        self._retransmit_interval(attempt, timeout),
                    )
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
    def _waiting_for(
        self, key: tuple[int, bytes]
    ) -> _ty.Iterator[_queue.Queue[tuple[DhcpMessage, RequestContext]]]:
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
        waiter: _queue.Queue[tuple[DhcpMessage, RequestContext]],
        msg_type: _enum.DhcpMessageType,
        timeout: float,
    ) -> DhcpMessage | None:
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
            if msg.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) is not msg_type:
                continue
            return msg

    def discover_offer(
        self,
        chaddr: bytes,
        *,
        timeout: float = 2.0,
        retries: int = 2,
        destination: _net.IPv4 | str = _net.IPv4("255.255.255.255"),
        port: int = int(_enum.DhcpPort.SERVER),
        **discover_kwargs: _ty.Any,
    ) -> DhcpMessage | None:
        """Broadcast DHCPDISCOVER and return the first DHCPOFFER, or None.

        `timeout` is the *initial* retransmission interval, not a fixed one:
        each retransmission waits about twice as long as the last, jittered, up
        to `RETRANSMIT_MAX_INTERVAL` (RFC 2131 s4.1). With the defaults the
        whole call is bounded at roughly 2+4+8 seconds rather than 3x2.
        """
        discover = self.build_discover(chaddr, **discover_kwargs)
        return self._exchange(
            discover,
            _enum.DhcpMessageType.DHCPOFFER,
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
        destination: _net.IPv4 | str = _net.IPv4("255.255.255.255"),
        port: int = int(_enum.DhcpPort.SERVER),
        broadcast: bool = True,
        **discover_kwargs: _ty.Any,
    ) -> DhcpMessage | None:
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
            broadcast=broadcast,
            **discover_kwargs,
        )
        if offer is None:
            return None
        server_identifier = offer.options.get(
            DhcpOptionCode.SERVER_IDENTIFIER, decode=_type.IPv4Address
        )
        if server_identifier is None:
            # RFC 2131 s4.3.2: a REQUEST in SELECTING state MUST carry the
            # server identifier, and the server uses it to tell "this offer is
            # mine" from "another server's offer was chosen". Sending one
            # without it asks every server on the segment to answer.
            LOGGER.warning(
                f"[XID={offer.xid:08x}] DHCPOFFER has no SERVER_IDENTIFIER; "
                "cannot send a conforming DHCPREQUEST"
            )
            return None
        request = self.build_request(
            chaddr,
            xid=offer.xid,
            requested_ip=offer.yiaddr,
            server_identifier=server_identifier,
            broadcast=broadcast,
            # RFC 2131 s4.2 and s4.4.1 both say MUST: the same client
            # identifier in every subsequent message, and the same parameter
            # list in any subsequent REQUEST. Omitting the identifier keyed the
            # REQUEST under htype+chaddr while the OFFER was allocated under the
            # supplied one, so the server saw two different clients.
            client_identifier=discover_kwargs.get("client_identifier"),
            parameter_request_list=discover_kwargs.get("parameter_request_list"),
        )
        return self._exchange(
            request,
            _enum.DhcpMessageType.DHCPACK,
            destination=destination,
            port=port,
            timeout=timeout,
            retries=retries,
            started_at=started_at,
        )

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        if msg.op != _enum.OpCode.BOOTREPLY:
            return
        key = self._pending_key(msg)
        if self._pending_keys and key not in self._pending_keys:
            return
        # An idle client (nothing sent yet) deliberately still accepts: that is
        # what makes `start()` + `on_reply` usable as an observer.
        with self._waiters_lock:
            waiter = self._waiters.get(key)
        self._put_bounded(
            waiter if waiter is not None else self._replies, (msg, context)
        )
        self.on_reply(msg, context)

    def _put_bounded(
        self,
        replies: _queue.Queue[tuple[DhcpMessage, RequestContext]],
        item: tuple[DhcpMessage, RequestContext],
    ) -> None:
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

    def on_reply(self, msg: DhcpMessage, context: RequestContext) -> None:
        """Hook called after a BOOTREPLY is accepted and queued."""

    def next_reply(
        self, timeout: float | None = None
    ) -> tuple[DhcpMessage, RequestContext] | None:
        try:
            return self._replies.get(timeout=timeout)
        except _queue.Empty:
            return None

    def drain_replies(self) -> list[tuple[DhcpMessage, RequestContext]]:
        replies: list[tuple[DhcpMessage, RequestContext]] = []
        while True:
            try:
                replies.append(self._replies.get_nowait())
            except _queue.Empty:
                return replies

    def _base_request(
        self,
        chaddr: bytes,
        *,
        xid: int | None,
        broadcast: bool,
    ) -> DhcpMessage:
        return DhcpMessage(
            op=_enum.OpCode.BOOTREQUEST,
            htype=_enum.HardwareAddressType.ETHERNET,
            hlen=len(chaddr),
            hops=0,
            xid=_secrets.randbits(32) if xid is None else int(xid),
            # A freshly built message has no acquisition behind it yet;
            # `_exchange` stamps the real elapsed time before each send.
            secs=_dt.timedelta(seconds=0),
            flags=_enum.Flags.BROADCAST if broadcast else _enum.Flags.UNICAST,
            ciaddr=_net.WILDCARD_IPv4,
            yiaddr=_net.WILDCARD_IPv4,
            siaddr=_net.WILDCARD_IPv4,
            giaddr=_net.WILDCARD_IPv4,
            chaddr=bytes(chaddr),
            sname="",
            file="",
            options=DhcpOptions(),
        )

    def _add_client_options(
        self,
        msg: DhcpMessage,
        client_identifier: bytes | bytearray | None,
        parameter_request_list: _ty.Iterable[DhcpOptionCode] | None,
    ) -> None:
        if client_identifier is not None:
            msg.options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray(client_identifier)
        if parameter_request_list is not None:
            msg.options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = list(
                parameter_request_list
            )
