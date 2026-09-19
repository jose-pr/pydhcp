from __future__ import annotations

import datetime as _dt
import queue as _queue
import secrets as _secrets
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
        self._pending_xids: set[int] = set()

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
        self._pending_xids.add(message.xid)
        self.metrics.packets_sent += 1
        return sent

    def _wait_for(
        self, xid: int, msg_type: _enum.DhcpMessageType, timeout: float
    ) -> DhcpMessage | None:
        deadline = _time.monotonic() + timeout
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                return None
            reply = self.next_reply(timeout=remaining)
            if reply is None:
                return None
            msg, _context = reply
            if msg.xid != xid:
                continue
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
        """Broadcast DHCPDISCOVER and return the first DHCPOFFER, or None."""
        discover = self.build_discover(chaddr, **discover_kwargs)
        try:
            for _attempt in range(retries + 1):
                self.send(discover, destination, port)
                offer = self._wait_for(
                    discover.xid, _enum.DhcpMessageType.DHCPOFFER, timeout
                )
                if offer is not None:
                    return offer
            return None
        finally:
            # The exchange is over either way. Left in place, this set only ever
            # grew, and every later replay of a spent xid -- visible to anyone on
            # the segment, since these go out as broadcasts -- stayed acceptable
            # forever. dora() re-registers the xid for its own REQUEST.
            self._pending_xids.discard(discover.xid)

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
        """Run a full DISCOVER/OFFER/REQUEST/ACK exchange and return the DHCPACK, or None."""
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
        try:
            for _attempt in range(retries + 1):
                self.send(request, destination, port)
                ack = self._wait_for(
                    request.xid, _enum.DhcpMessageType.DHCPACK, timeout
                )
                if ack is not None:
                    return ack
            return None
        finally:
            self._pending_xids.discard(request.xid)

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        if msg.op != _enum.OpCode.BOOTREPLY:
            return
        if self._pending_xids and msg.xid not in self._pending_xids:
            return
        # An idle client (nothing sent yet) deliberately still accepts: that is
        # what makes `start()` + `on_reply` usable as an observer. What it must
        # not do is grow without bound while nobody drains the queue, so the
        # oldest reply is discarded to make room and counted. Oldest rather than
        # newest: a caller waiting on an exchange wants the recent ones.
        while True:
            try:
                self._replies.put_nowait((msg, context))
                break
            except _queue.Full:
                try:
                    self._replies.get_nowait()
                    self.metrics.replies_dropped_overflow += 1
                except _queue.Empty:  # pragma: no cover - drained concurrently
                    pass
        self.on_reply(msg, context)

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
