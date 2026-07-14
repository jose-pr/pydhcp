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


class DhcpClient(DhcpListener):
    """Small DHCPv4 packet client for tests and troubleshooting.

    The base client builds and sends DHCP client messages, then queues matching
    replies. It does not configure operating-system network interfaces.
    """

    DEFAULT_PORTS = (_enum.DhcpPort.CLIENT,)

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
        self._replies: _queue.Queue[tuple[DhcpMessage, RequestContext]] = _queue.Queue()
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
        msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = _enum.DhcpMessageType.DHCPDISCOVER
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
        msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = _enum.DhcpMessageType.DHCPREQUEST
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
        msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = _enum.DhcpMessageType.DHCPRELEASE
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
        msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = _enum.DhcpMessageType.DHCPDECLINE
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
        for _attempt in range(retries + 1):
            self.send(discover, destination, port)
            offer = self._wait_for(discover.xid, _enum.DhcpMessageType.DHCPOFFER, timeout)
            if offer is not None:
                return offer
        return None

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
        request = self.build_request(
            chaddr,
            xid=offer.xid,
            requested_ip=offer.yiaddr,
            server_identifier=server_identifier,
            broadcast=broadcast,
        )
        for _attempt in range(retries + 1):
            self.send(request, destination, port)
            ack = self._wait_for(request.xid, _enum.DhcpMessageType.DHCPACK, timeout)
            if ack is not None:
                return ack
        return None

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        if msg.op != _enum.OpCode.BOOTREPLY:
            return
        if self._pending_xids and msg.xid not in self._pending_xids:
            return
        self._replies.put((msg, context))
        self.on_reply(msg, context)

    def on_reply(self, msg: DhcpMessage, context: RequestContext) -> None:
        """Hook called after a BOOTREPLY is accepted and queued."""

    def next_reply(self, timeout: float | None = None) -> tuple[DhcpMessage, RequestContext] | None:
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
            msg.options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = list(parameter_request_list)
