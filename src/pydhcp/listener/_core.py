"""What both listeners share: configuration, binding and the handling of one datagram.

The thread-based and the asyncio listener are siblings over this class. It owns
no thread, loop or task; each driver reads datagrams its own way and hands them
to `_dispatch`.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import logging as _logging
import socket as _socket
import typing as _ty

import netimps as _netimps

from .. import _clock, _constants as _const, _network as _net
from .._metrics import DHCPMetrics
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage
from ._binding import _bind_sockets, _close_socket
from ._receive import DHCPRequestContext, _context_for, _pktinfo_supported
from ._spec import ListenSpec, _expand_wildcards, _parselisteners

LOGGER = _logging.getLogger(__name__)


class _ListenerCore:
    DEFAULT_PORTS: _ty.Sequence[int] = tuple(p.value for p in _enum.DHCPPort)

    #: Whether to set ``SO_REUSEADDR`` on every listening socket. Off: see
    #: `_bind_sockets` for what sharing a DHCP port actually looks like when it
    #: goes wrong. A class attribute rather than a constructor argument so every
    #: subclass (server, client, relay, capture) inherits it without each
    #: constructor having to forward it.
    REUSE_ADDRESS: bool = False

    #: Receive buffer to ask the OS for on every listening socket, in octets;
    #: 0 keeps the OS default. 1 MiB holds about 3500 typical 300-octet DHCP
    #: datagrams, against about 220 in Windows' 64 KiB default -- a segment
    #: powering up sends its DISCOVERs together. The kernel may grant less
    #: (Linux caps at net.core.rmem_max); a shortfall is logged at INFO.
    RECEIVE_BUFFER_SIZE: int = 1 << 20

    #: Said in the "Listening on" record, to tell the two drivers apart.
    _BIND_LABEL = ""

    def __init__(
        self,
        listen: ListenSpec = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
    ) -> None:
        #: ``None`` and 0 both mean the largest UDP payload.
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._pktinfo = _pktinfo_supported(listen, per_interface)
        self._listen = _parselisteners(
            listen, self.DEFAULT_PORTS, expand_wildcard=False
        )
        #: Without packet info a wildcard is served by one socket per host
        #: address; the expansion is read when binding, not when constructing.
        self._expand_wildcard = not self._pktinfo
        self._per_interface = per_interface
        self._sockets: list[_socket.socket] = []
        #: The netimps endpoint each socket is received through.
        self._endpoints: dict[_socket.socket, _netimps.UDPEndpoint] = {}
        self.metrics = DHCPMetrics()

    @property
    def bound_addresses(self) -> "tuple[_net.SocketAddress, ...]":
        """The addresses this listener is currently bound to.

        Empty before `bind()` and once the sockets are closed. Asking the socket
        rather than repeating the listen list is the point: binding port 0 gives
        an ephemeral port that only the socket knows, which is how a test or a
        tool discovers where to send.
        """
        addresses = []
        for sock in self._sockets:
            try:
                addresses.append(_net.SocketAddress(sock))
            except OSError:  # pragma: no cover - socket closed underneath us
                continue
        return tuple(addresses)

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        pass

    def bind(self) -> None:
        listen = (
            _expand_wildcards(self._listen) if self._expand_wildcard else self._listen
        )
        _bind_sockets(
            listen,
            self._sockets,
            self._endpoints,
            self._pktinfo,
            label=self._BIND_LABEL,
            reuse_address=self.REUSE_ADDRESS,
            receive_buffer=self.RECEIVE_BUFFER_SIZE,
        )

    def _read_clock(self) -> _clock._Instant:
        return _clock._read()

    def _close_sockets(self) -> None:
        for sock in self._sockets:
            _close_socket(sock, self._endpoints)
        self._sockets.clear()

    def _dispatch(
        self,
        data: bytes,
        client: _net.SocketAddress,
        sock: _socket.socket,
        ifindex: "_ty.Optional[int]" = None,
        local_ip: "_ty.Optional[_ipaddress.IPv4Address]" = None,
    ) -> None:
        """Decode, count and hand one datagram to `handle()`.

        Split in two because they fail for unrelated reasons and need different
        reports: a malformed packet is the sender's doing and a warning, a
        failure inside `handle()` is ours and keeps its traceback.
        """
        try:
            msg = DHCPMessage.decode(memoryview(data))
        except Exception as e:
            self.metrics.packets_dropped_error += 1
            LOGGER.warning(
                f"Discarding an undecodable {len(data)}-octet datagram from "
                f"{client}: {e.__class__.__name__} | {e}"
            )
            return
        try:
            self.metrics.packets_received += 1
            context = _context_for(
                sock,
                client,
                msg.chaddr,
                ifindex,
                local_ip,
                self._endpoints.get(sock),
                self._read_clock(),
            )
            if LOGGER.isEnabledFor(_logging.DEBUG):
                msg.log(client, _net.SocketAddress(sock), _logging.DEBUG)
            self.handle(msg, context)
        except Exception as e:
            # `DHCPCapture.hook_fail_fast` relies on this staying a catch rather
            # than a propagate.
            self.metrics.packets_dropped_error += 1
            LOGGER.error(
                f"Encounter error handling request from {client}: "
                f"{e.__class__.__name__} | {e}",
                exc_info=True,
            )
