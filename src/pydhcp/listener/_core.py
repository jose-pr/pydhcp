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

from .. import _clock, _constants as _const, _leniency, _network as _net
from .._metrics import DHCPMetrics
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage
from ._binding import _bind_sockets, _close_socket, _requested
from ._interfaces import _interface_adapters
from ._limit import _brief, _LogLimit
from ._receive import DHCPRequestContext, _Arrival, _context_for, _pktinfo_supported
from ._spec import (
    ListenLike,
    _expand_wildcards,
    _interface_limits,
    _parselisteners,
)

LOGGER = _logging.getLogger(__name__)


class _ListenerCore:
    DEFAULT_PORTS: _ty.Sequence[int] = tuple(p.value for p in _enum.DHCPPort)

    #: Whether to set ``SO_REUSEADDR`` on every listening socket when the
    #: constructor's `reuse_address` is not given. Off: see `_bind_sockets` for
    #: what sharing a DHCP port actually looks like when it goes wrong.
    REUSE_ADDRESS: bool = False

    #: Receive buffer to ask the OS for on every listening socket, in octets,
    #: when the constructor's `receive_buffer_size` is not given; 0 keeps the
    #: OS default. 1 MiB holds about 3500 typical 300-octet DHCP
    #: datagrams, against about 220 in Windows' 64 KiB default -- a segment
    #: powering up sends its DISCOVERs together. The kernel may grant less
    #: (Linux caps at net.core.rmem_max); a shortfall is logged at INFO.
    RECEIVE_BUFFER_SIZE: int = 1 << 20

    #: Whether a socket serving one interface is bound to that device where the
    #: host can (`netimps.has_device_binding()`: Linux), so the kernel delivers
    #: nothing from another interface. Off, or elsewhere, the allow-list drops
    #: it after the receive.
    USE_DEVICE_BINDING: bool = True

    #: Said in the "Listening on" record, to tell the two drivers apart.
    _BIND_LABEL = ""

    def __init__(
        self,
        listen: ListenLike = None,
        *,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
        reuse_address: _ty.Optional[bool] = None,
        receive_buffer_size: _ty.Optional[int] = None,
    ) -> None:
        #: ``None`` and 0 both mean the largest UDP payload.
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._listen_spec = listen
        self._listen = _parselisteners(
            listen, self.DEFAULT_PORTS, expand_wildcard=False
        )
        #: The interfaces a wildcard socket is limited to, by the address it
        #: was asked for; resolved to indexes by `bind()`.
        self._limits = _interface_limits(listen, self.DEFAULT_PORTS)
        if self._limits and per_interface:
            raise ValueError(
                "per_interface cannot be combined with listening on an interface: "
                "one socket per address hears no broadcast on most platforms"
            )
        self._per_interface = per_interface
        #: ``None`` takes the class attribute when binding.
        self._reuse_address = reuse_address
        self._receive_buffer_size = receive_buffer_size
        self._pktinfo_probed: _ty.Optional[bool] = None
        #: Closed is final: set by `close()`, never cleared.
        self._closed = False
        self._sockets: list[_socket.socket] = []
        #: The netimps endpoint each socket is received through.
        self._endpoints: dict[_socket.socket, _netimps.UDPEndpoint] = {}
        #: The interface indexes a socket serves, for a socket limited to some.
        self._allowed: "dict[_socket.socket, frozenset[int]]" = {}
        self.metrics = DHCPMetrics()
        #: What a sender can make this listener, or the role on it, write.
        self._log_limit = _LogLimit()

    @property
    def _pktinfo(self) -> bool:
        """Whether this listener receives through the packet-info path.

        Asked of a socket on first use, which is `bind()`: a constructor
        performs no I/O.
        """
        if self._pktinfo_probed is None:
            self._pktinfo_probed = _pktinfo_supported(
                self._listen_spec, self._per_interface
            )
        return self._pktinfo_probed

    @property
    def _expand_wildcard(self) -> bool:
        """Without packet info a wildcard is served by one socket per host address."""
        return not self._pktinfo

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
                addresses.append(_net.SocketAddress.from_socket(sock))
            except OSError:  # pragma: no cover - socket closed underneath us
                continue
        return tuple(addresses)

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        pass

    def bind(self) -> None:
        """Open the sockets. Idempotent; raises what the bind raised, leaving none open.

        Raises `RuntimeError` once the listener is closed.
        """
        if self._closed:
            raise RuntimeError(f"{type(self).__name__} is closed")
        # Before anything is opened: an interface that does not exist is an
        # error of the arguments, and leaves no socket behind.
        # One lookup serves both the allow-list and the device.
        adapters = {
            address: _interface_adapters(selectors)
            for address, selectors in self._limits.items()
        }
        allowed = {
            address: frozenset(adapter.index for adapter in found)
            for address, found in adapters.items()
        }
        # A device is one adapter: a socket serving several (an `Interface` list,
        # or a MAC that several adapters carry) is limited by the allow-list alone.
        devices = (
            {a: found[0] for a, found in adapters.items() if len(found) == 1}
            if self.USE_DEVICE_BINDING and _netimps.has_device_binding()
            else {}
        )
        if allowed and not self._pktinfo:
            raise ValueError(
                "listening on an interface needs packet info, which sockets on "
                "this host do not report"
            )
        listen = (
            _expand_wildcards(self._listen) if self._expand_wildcard else self._listen
        )
        _bind_sockets(
            listen,
            self._sockets,
            self._endpoints,
            self._pktinfo,
            label=self._BIND_LABEL,
            reuse_address=(
                self.REUSE_ADDRESS
                if self._reuse_address is None
                else self._reuse_address
            ),
            receive_buffer=(
                self.RECEIVE_BUFFER_SIZE
                if self._receive_buffer_size is None
                else self._receive_buffer_size
            ),
            devices=devices,
            on_device_refused=self._device_refused,
        )
        self._allowed = {
            sock: allowed[requested]
            for sock in self._sockets
            if (requested := _requested(sock)) in allowed
        }

    def _device_refused(
        self, address: _net.SocketAddress, device: _netimps.Interface, error: OSError
    ) -> None:
        """Say that `address` is limited to its interface by the allow-list alone."""
        self._log_limited(
            LOGGER,
            _logging.WARNING,
            "device binding refused",
            "Could not bind %s to the device %s (%s | %s): datagrams from other "
            "interfaces are dropped after the receive instead.",
            address,
            device.name,
            type(error).__name__,
            _brief(error),
        )

    def _admits(self, arrival: _Arrival, sock: _socket.socket) -> bool:
        """Whether a datagram arrived on an interface this socket serves.

        A socket told to serve some interfaces drops, before decoding, what
        arrives on any other, and counts it: one wildcard socket hears every
        interface, which is the only way to hear a broadcast. Where the socket
        is bound to its device the kernel delivers nothing from another
        interface and the count stays 0; this check remains as the second line.
        """
        allowed = self._allowed.get(sock)
        if allowed is None or arrival.ifindex in allowed:
            return True
        self.metrics.packets_dropped_other_interface += 1
        self._log_limited(
            LOGGER,
            _logging.DEBUG,
            "datagram from another interface",
            "Dropping a datagram that arrived on interface %s: this socket serves %s.",
            arrival.ifindex,
            sorted(allowed),
        )
        return False

    def _read_clock(self) -> _clock._Instant:
        return _clock._read()

    def _close_sockets(self) -> None:
        for sock in self._sockets:
            _close_socket(sock, self._endpoints)
        self._sockets.clear()

    def _log_limited(
        self,
        logger: _logging.Logger,
        level: int,
        reason: str,
        message: str,
        *args: object,
        exc_info: bool = False,
    ) -> None:
        """Write a line about something a sender did, at the limited rate.

        Reads the clock on the way out of an error path only, never per datagram.
        """
        self._log_limit.log(
            logger,
            level,
            reason,
            message,
            *args,
            now=self._read_clock().monotonic,
            exc_info=exc_info,
        )

    def _note_truncated(self, error: object) -> None:
        self.metrics.packets_dropped_truncated += 1
        self._log_limited(
            LOGGER,
            _logging.WARNING,
            "truncated datagram",
            "Dropping a truncated datagram: %s",
            _brief(error),
        )

    def _note_receive_error(self, where: str, error: BaseException) -> None:
        self.metrics.packets_dropped_error += 1
        self._log_limited(
            LOGGER,
            _logging.ERROR,
            f"receive failed: {type(error).__name__}",
            "Receive failed on %s: %s | %s",
            where,
            type(error).__name__,
            _brief(error),
            exc_info=True,
        )

    def _control_truncated(self, client: _net.SocketAddress) -> None:
        self._log_limited(
            LOGGER,
            _logging.WARNING,
            "control data truncated",
            "Packet-info control data truncated for a datagram from %s; the "
            "receiving interface may be resolved wrongly.",
            client,
        )

    def _dispatch_arrival(self, arrival: _Arrival, sock: _socket.socket) -> None:
        """`_dispatch` for one `_arrival`."""
        self._dispatch(
            arrival.data,
            arrival.client,
            sock,
            arrival.ifindex,
            arrival.local_ip,
            destination=arrival.destination,
            is_unicast=arrival.is_unicast,
            adapter=arrival.adapter,
        )

    def _dispatch(
        self,
        data: bytes,
        client: _net.SocketAddress,
        sock: _socket.socket,
        ifindex: "_ty.Optional[int]" = None,
        local_ip: "_ty.Optional[_ipaddress.IPv4Address]" = None,
        *,
        destination: "_ty.Optional[_ipaddress.IPv4Address]" = None,
        is_unicast: "_ty.Optional[bool]" = None,
        adapter: "_ty.Optional[_netimps.Interface]" = None,
    ) -> None:
        """Decode, count and hand one datagram to `handle()`.

        Split in two because they fail for unrelated reasons and need different
        reports: a malformed packet is the sender's doing and a limited warning,
        a failure inside `handle()` is ours and keeps its traceback for the first
        occurrence of each exception class.
        """
        received = self._read_clock()
        try:
            with _leniency.collecting() as forgiven:
                msg = DHCPMessage.decode(memoryview(data))
        except Exception as e:
            self.metrics.packets_dropped_error += 1
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "undecodable datagram",
                "Discarding an undecodable %d-octet datagram from %s: %s | %s",
                len(data),
                client,
                e.__class__.__name__,
                _brief(e),
                now=received.monotonic,
            )
            return
        if forgiven.count:
            self.metrics.packets_decoded_leniently += 1
        try:
            self.metrics.packets_received += 1
            context = _context_for(
                sock,
                client,
                msg.chaddr,
                ifindex,
                local_ip,
                self._endpoints.get(sock),
                received,
                self._log_limit,
                destination,
                is_unicast,
                adapter,
                self.metrics,
                data if type(data) is bytes else bytes(data),
            )
            if LOGGER.isEnabledFor(_logging.DEBUG):
                bound = _net.SocketAddress.from_socket(sock)
                msg.log(
                    client,
                    _net.SocketAddress(local_ip or bound.ip, bound.port),
                    _logging.DEBUG,
                )
            self.handle(msg, context)
        except Exception as e:
            # `DHCPCapture.hook_fail_fast` relies on this staying a catch rather
            # than a propagate.
            self.metrics.packets_dropped_error += 1
            self._log_limit.log(
                LOGGER,
                _logging.ERROR,
                f"handler error: {type(e).__name__}",
                "Encounter error handling request from %s: %s | %s",
                client,
                e.__class__.__name__,
                _brief(e),
                now=received.monotonic,
                exc_info=True,
            )
