from __future__ import annotations

import socket as _socket

import netimps as _netimps
import select as _select
import threading as _thread
import struct as _struct
import concurrent.futures as _futures
import typing as _ty

from . import network as _net, constants as _const
from .packet import enums as _enum
from .packet.message import DhcpMessage
from .log import LOGGER
from .metrics import DhcpMetrics
import logging as _logging

IP_PKTINFO = getattr(_socket, "IP_PKTINFO", None)
CMSG_SPACE = getattr(_socket, "CMSG_SPACE", None)
#: POSIX-only in typeshed, so referencing `sock.recvmsg` directly is an error on a
#: Windows check and an unused-ignore on a POSIX one -- no single annotation is
#: right for both. Going through the same getattr alias as the constants above is.
_RECVMSG = getattr(_socket.socket, "recvmsg", None)

ListenAddress = _ty.Union[_net.IPv4, str]
ListenPort = _ty.Union[int, _ty.Sequence[int]]
ListenBinding = _ty.Union[ListenAddress, tuple[ListenAddress, ListenPort]]
ListenSpec = _ty.Optional[_ty.Union[ListenBinding, _ty.Sequence[ListenBinding]]]


class Transport:
    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest: _net.IPv4,
        port: int,
        client_mac: bytes,
    ) -> int:
        raise NotImplementedError()


class UdpTransport(Transport):
    def __init__(self, socket: _socket.socket):
        self.socket = socket

    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest: _net.IPv4,
        port: int,
        client_mac: bytes,
    ) -> int:
        dest_ip = dest
        dest_str = "255.255.255.255" if dest_ip == _net.WILDCARD_IPv4 else str(dest_ip)

        # Future RawTransport can be plugged in here to craft L2 Ethernet frames targeting client_mac.
        # Standard UDP sockets can't directly target L2 MAC on UDP if there is no ARP entry,
        # so we fall back to broadcast if unicast fails.
        try:
            return self.socket.sendto(data, (dest_str, port))
        except Exception as e:
            LOGGER.warning(
                f"UDP unicast to {dest_str} failed ({e}), falling back to broadcast."
            )
            return self.socket.sendto(data, ("255.255.255.255", port))


class PktInfoUdpTransport(UdpTransport):
    """POSIX packet-info transport for wildcard routing."""

    def __init__(self, socket: _socket.socket):
        super().__init__(socket)
        self.ifindex: int | None = None
        self.local_ip: _net.IPv4 | None = None

    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest: _net.IPv4,
        port: int,
        client_mac: bytes,
    ) -> int:
        if (
            hasattr(self.socket, "sendmsg")
            and self.ifindex is not None
            and self.local_ip is not None
            and IP_PKTINFO is not None
        ):
            pktinfo = _struct.pack(
                "=I4s4s",
                self.ifindex,
                _socket.inet_aton(str(self.local_ip)),
                _socket.inet_aton(str(self.local_ip)),
            )
            return int(
                self.socket.sendmsg(
                    [data],
                    [(_socket.IPPROTO_IP, IP_PKTINFO, pktinfo)],
                    0,
                    (str(dest), port),
                )
            )
        return super().send(data, dest, port, client_mac)


class RequestContext(_ty.NamedTuple):
    transport: Transport
    interface: _net.NetworkInterface
    client: _net.SocketAddress
    client_mac: bytes
    ifindex: int | None = None
    local_ip: _net.IPv4 | None = None


def _split_listen_string(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _split_host_port(value: str) -> tuple[str, int | None]:
    """Split ``host:port``, defaulting an empty host to the IPv4 wildcard.

    Delegates to :func:`netimps.normalize_host`, which handles the IPv6 forms
    the previous implementation could not: ``[::1]:67`` now yields
    ``("::1", 67)`` rather than silently dropping the port, and a bare ``::1``
    stays an address instead of being read as host ``::`` port ``1``.
    """
    # ":67" means "wildcard, port 67" here, but is an empty host to a strict
    # parser -- normalize it before delegating rather than losing the form.
    if value.startswith(":") and not value.startswith("::"):
        value = "0.0.0.0" + value

    host, port = _netimps.normalize_host(value)
    return host or "0.0.0.0", port


def _iter_listen_bindings(listen: ListenSpec) -> _ty.Iterator[ListenBinding]:
    if listen is None:
        return
    if isinstance(listen, str):
        for part in _split_listen_string(listen):
            yield part
        return
    if isinstance(listen, tuple):
        yield listen
        return
    if isinstance(listen, _net.IPv4):
        yield listen
        return
    for binding in listen:
        if isinstance(binding, str) and "," in binding:
            for part in _split_listen_string(binding):
                yield part
        else:
            yield binding


def _is_wildcard_binding(binding: ListenBinding) -> bool:
    ip = binding[0] if isinstance(binding, tuple) else binding
    return ip == "*" or ip == _net.WILDCARD_IPv4 or ip == "0.0.0.0"


def _listen_uses_wildcard(listen: ListenSpec) -> bool:
    return any(
        _is_wildcard_binding(binding) for binding in _iter_listen_bindings(listen)
    )


def _parselisteners(
    listen: ListenSpec = None,
    default_ports: _ty.Sequence[int] = (),
    expand_wildcard: bool = True,
) -> list[_net.SocketAddress]:
    _listen: list[_net.SocketAddress] = []
    for bind in _iter_listen_bindings(listen):
        port: _ty.Optional[_ty.Union[int, _ty.Sequence[int]]]
        if not isinstance(bind, tuple):
            ip, port = _split_host_port(bind) if isinstance(bind, str) else (bind, None)
        else:
            ip, port = bind
            if isinstance(ip, str):
                ip, parsed_port = _split_host_port(ip)
                if port is None:
                    port = parsed_port

        if not ip:
            ip = "127.0.0.1"
        elif ip == "*":
            ip = _net.WILDCARD_IPv4
        if not isinstance(ip, _net.IPv4):
            ip = _net.IPv4(ip)

        if ip == _net.WILDCARD_IPv4 and expand_wildcard:
            ips = [
                i.ip for i in _net.host_ip_interfaces() if isinstance(i.ip, _net.IPv4)
            ]
        else:
            ips = [ip]
        for ip in ips:
            ports: _ty.Sequence[int]
            if port is None:
                ports = default_ports
            elif isinstance(port, int):
                ports = [port]
            else:
                ports = port
            for p in ports:
                p = int(p)
                bind_addr = _net.SocketAddress(ip, p)
                if bind_addr not in _listen:
                    _listen.append(bind_addr)
    return _listen


#: Resolved interfaces, keyed by (ifindex, local address). Enumerating every host
#: adapter costs tens of milliseconds on Windows, and it was paid per datagram --
#: enough that a modest flood denied service on its own. Cleared by `bind()`, which
#: is the point at which the set of addresses this listener serves can change.
_INTERFACE_CACHE: dict[tuple[int, str], _net.NetworkInterface] = {}


def _clear_interface_cache() -> None:
    _INTERFACE_CACHE.clear()


_PKTINFO_STRUCT = "=I4s4s"


def _pktinfo_supported(listen: ListenSpec, per_interface: "bool | None") -> bool:
    """Whether this listener can use the POSIX packet-info path.

    Only a wildcard bind needs it, and only POSIX has it. Without it a wildcard
    has to be expanded into one socket per address -- which on Linux then
    receives no broadcasts at all, so a client's DISCOVER never arrives.
    """
    return (
        per_interface is not True
        and _RECVMSG is not None
        and hasattr(_socket, "IP_PKTINFO")
        and _listen_uses_wildcard(listen)
    )


def _bind_sockets(
    listen: "_ty.Sequence[_net.SocketAddress]",
    sockets: "list[_socket.socket]",
    pktinfo: bool,
    label: str = "",
) -> None:
    """Bind one socket per listen address, reusing any already bound.

    Shared by both listeners. Held apart, the async copy silently lacked the
    ``IP_PKTINFO`` socket option and the bind-error hints, so the same mistake
    produced a helpful message from one listener and a bare errno from the other.
    """
    _clear_interface_cache()
    active = {_net.SocketAddress(sock): sock for sock in sockets}
    wanted = []
    for address in listen:
        wanted.append(address)
        if address in active:
            continue
        LOGGER.info(f"Listening on{' (' + label + ')' if label else ''}: {address}")
        try:
            sock = address.listen(
                _socket.AF_INET,
                _socket.SOCK_DGRAM,
                _socket.IPPROTO_UDP,
                options=[
                    _net.SocketOption(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1),
                    _net.SocketOption(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1),
                ],
            )
            if pktinfo and address.ip == _net.WILDCARD_IPv4 and IP_PKTINFO is not None:
                sock.setsockopt(_socket.IPPROTO_IP, IP_PKTINFO, 1)
        except OSError as e:
            # netimps recognises the POSIX errnos *and* the Windows WinError
            # codes, which differ; the DHCP-specific suggestion is appended
            # rather than replacing the generic diagnosis.
            hint = _netimps.bind_error_hint(e, address.port)
            if hint is None:
                raise
            if isinstance(e, PermissionError) or "permission" in hint.lower():
                raise PermissionError(f"{hint}. Try 6767 for testing.") from e
            if "in use" in hint:
                raise OSError(
                    e.errno, f"{hint}; try port {address.port + 1000}."
                ) from e
            raise OSError(e.errno, hint) from e
        sockets.append(sock)
    for address, sock in active.items():
        if address not in wanted:
            sockets.remove(sock)
            try:
                sock.close()
            except Exception:
                pass


def _recv_with_pktinfo(
    sock: _socket.socket, max_packet_size: int
) -> "tuple[bytes, _net.SocketAddress, int | None, _net.IPv4 | None]":
    """Receive one datagram together with the interface it arrived on."""
    if CMSG_SPACE is None or IP_PKTINFO is None or _RECVMSG is None:
        raise RuntimeError("packet info support unavailable")
    data, ancdata, _flags, client_tuple = _RECVMSG(
        sock, max_packet_size, CMSG_SPACE(_struct.calcsize(_PKTINFO_STRUCT))
    )
    local_ip: "_net.IPv4 | None" = None
    ifindex: "int | None" = None
    for level, ctype, cdata in ancdata:
        if level == _socket.IPPROTO_IP and ctype == IP_PKTINFO:
            ifindex, dst1, _ = _struct.unpack(
                _PKTINFO_STRUCT, cdata[: _struct.calcsize(_PKTINFO_STRUCT)]
            )
            local_ip = _net.IPv4(_socket.inet_ntoa(dst1))
            break
    return data, _net.SocketAddress(*client_tuple), ifindex, local_ip


def _context_for(
    sock: _socket.socket,
    client: _net.SocketAddress,
    client_mac: bytes,
    ifindex: "int | None" = None,
    local_ip: "_net.IPv4 | None" = None,
) -> RequestContext:
    """Build the context for one received datagram.

    Shared by both listeners: duplicating it is what let the async half miss
    every fix the sync half gained.
    """
    transport: Transport
    if ifindex is not None or local_ip is not None:
        pkt_transport = PktInfoUdpTransport(sock)
        pkt_transport.ifindex = ifindex
        pkt_transport.local_ip = local_ip
        transport = pkt_transport
    else:
        transport = UdpTransport(sock)
    return RequestContext(
        transport=transport,
        interface=_resolve_interface(sock, local_ip, ifindex),
        client=client,
        client_mac=client_mac,
        ifindex=ifindex,
        local_ip=local_ip,
    )


def _resolve_interface(
    sock: _socket.socket,
    pkt_local_ip: _ty.Optional[_net.IPv4] = None,
    pkt_ifindex: _ty.Optional[int] = None,
) -> _net.NetworkInterface:
    """Find the NetworkInterface a datagram actually arrived on.

    ``pkt_local_ip``/``pkt_ifindex`` come from the ``IP_PKTINFO`` control message
    and are authoritative when present: the pktinfo path only runs on a wildcard
    bind, where ``getsockname()`` reports 0.0.0.0 -- precisely the information
    pktinfo exists to supply. Use both, in order: the index picks the adapter,
    the address picks which of its addresses (a NIC may hold several, and the
    reply's SERVER_IDENTIFIER must be the right one).

    Falls back to a synthetic host-route entry when nothing matches, which keeps
    callers from having to special-case it. Results are cached per
    (ifindex, address); `bind()` clears the cache.
    """
    if pkt_local_ip is None and pkt_ifindex is None:
        try:
            sock_ip, _port = sock.getsockname()
        except Exception:
            sock_ip = "127.0.0.1"
        cache_key = (0, sock_ip)
    else:
        cache_key = (pkt_ifindex or 0, str(pkt_local_ip) if pkt_local_ip else "")
    cached = _INTERFACE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    resolved = _resolve_interface_uncached(sock, pkt_local_ip, pkt_ifindex)
    _INTERFACE_CACHE[cache_key] = resolved
    return resolved


def _resolve_interface_uncached(
    sock: _socket.socket,
    pkt_local_ip: _ty.Optional[_net.IPv4] = None,
    pkt_ifindex: _ty.Optional[int] = None,
) -> _net.NetworkInterface:
    if pkt_ifindex:
        fallback: _ty.Optional[_net.NetworkInterface] = None
        for index, interface in _net._iter_indexed_interfaces(family=4):
            if index != pkt_ifindex:
                continue
            if pkt_local_ip is not None and interface.ip == pkt_local_ip:
                return interface
            if fallback is None:
                fallback = interface
        if fallback is not None and pkt_local_ip is None:
            return fallback

    if pkt_local_ip is not None:
        local_ip = str(pkt_local_ip)
    else:
        try:
            local_ip, _ = sock.getsockname()
        except Exception:
            local_ip = "127.0.0.1"

    # Matched against pydhcp's own per-address view, since the caller expects a
    # NetworkInterface. netimps.interface_for() answers the same question but
    # returns its own Interface type, which is the wrong shape here.
    for i in _net.host_ip_interfaces(family=None):
        if str(i.ip) == local_ip:
            return i

    import ipaddress as _ipaddress

    try:
        ip_addr = _net.IPv4(local_ip)
    except Exception:
        ip_addr = _net.IPv4("127.0.0.1")
    LOGGER.warning(
        f"Could not resolve interface for IP {local_ip}; using synthetic interface"
    )
    return _net.NetworkInterface(
        name=f"unknown[{local_ip}]",
        ip_interface=_ipaddress.IPv4Interface((str(ip_addr), 32)),
        mac=None,
    )


class DhcpListener:
    DEFAULT_PORTS: _ty.Sequence[int] = tuple(p.value for p in _enum.DhcpPort)

    def __init__(
        self,
        listen: ListenSpec = None,
        select_timeout: float | None = None,
        max_packet_size: int | None = _const.UDP_MAX_PACKET_SIZE,
        per_interface: bool | None = None,
    ) -> None:
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._pktinfo = _pktinfo_supported(listen, per_interface)
        self._listen = _parselisteners(
            listen, self.DEFAULT_PORTS, expand_wildcard=not self._pktinfo
        )
        self._per_interface = per_interface
        self._sockets: list[_socket.socket] = []
        self._sigint_handler: _ty.Optional[_ty.Any] = None
        self._previous_sigint: _ty.Optional[_ty.Any] = None
        self._select_timeout = select_timeout or 1
        self._cancellation_token: _thread.Event | None = None
        self.metrics = DhcpMetrics()

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        pass

    def bind(self) -> None:
        _bind_sockets(self._listen, self._sockets, self._pktinfo)

    def stop(self) -> None:
        if self._cancellation_token is not None:
            self._cancellation_token.set()

    def close(self) -> None:
        """Close every bound socket and release the SIGINT handler.

        `stop()` only ends the receive loop; without this the sockets stayed
        open, so a process that creates a listener per operation leaked a bound
        UDP socket and its port each time, and the next bind to the same port
        failed or silently shared it.
        """
        for socket in self._sockets:
            try:
                socket.close()
            except Exception:
                pass
        self._sockets.clear()
        self._restore_sigint_handler()

    def __enter__(self) -> "DhcpListener":
        self.bind()
        return self

    def __exit__(self, *_exc: _ty.Any) -> None:
        self.stop()
        self.close()

    def wait(self) -> None:
        while self._cancellation_token is not None:
            self._cancellation_token.wait(self._select_timeout)

    def _install_sigint_handler(self) -> None:
        """Install a Ctrl-C handler, if this thread is allowed to.

        `signal.signal` raises off the main thread, which used to propagate out
        of `start()` *after* the cancellation token was set -- leaving the
        listener permanently 'started' and impossible to start again. Library
        code should not claim a process-wide handler as a side effect of
        starting, so failure here is not an error.
        """
        import signal

        if _thread.current_thread() is not _thread.main_thread():
            return

        def stop(*args: _ty.Any) -> None:
            self.stop()
            LOGGER.info("Stopped listening due to Ctrl-C")

        try:
            self._sigint_handler = stop
            self._previous_sigint = signal.signal(signal.SIGINT, stop)
        except (ValueError, OSError):  # pragma: no cover - platform dependent
            self._sigint_handler = None
            self._previous_sigint = None

    def _restore_sigint_handler(self) -> None:
        import signal

        if self._sigint_handler is None:
            return
        try:
            # Only give it back if nobody else has claimed it since.
            if signal.getsignal(signal.SIGINT) is self._sigint_handler:
                signal.signal(signal.SIGINT, self._previous_sigint)
        except (ValueError, OSError, TypeError):  # pragma: no cover
            pass
        self._sigint_handler = None
        self._previous_sigint = None

    def start(
        self, cancellation_token: _thread.Event | None = None
    ) -> _thread.Thread | None:
        if not self._cancellation_token:
            thread = _thread.Thread(target=self.listen, args=())
            self._cancellation_token = cancellation_token or _thread.Event()
            self._install_sigint_handler()
            thread.start()
            return thread
        return None

    def listen(self) -> None:
        self.bind()
        listen = True
        rlist: list[_socket.socket]
        buffer = bytearray(self._max_packet_size)
        view = memoryview(buffer)
        if self._cancellation_token is None:
            self._cancellation_token = _thread.Event()
        try:
            while listen and not self._cancellation_token.is_set():
                rlist, _, _ = _select.select(
                    list(self._sockets), [], [], self._select_timeout
                )
                if self._cancellation_token.is_set():
                    break
                for socket in rlist:
                    try:
                        if self._pktinfo:
                            data, client, ifindex, local_ip = _recv_with_pktinfo(
                                socket, self._max_packet_size
                            )
                            msg = DhcpMessage.decode(memoryview(data))
                        else:
                            # No control message to read, so keep the preallocated
                            # buffer rather than letting recvmsg allocate per packet.
                            size, client_tuple = socket.recvfrom_into(
                                view, self._max_packet_size
                            )
                            client = _net.SocketAddress(*client_tuple)
                            ifindex = None
                            local_ip = None
                            msg = DhcpMessage.decode(view[:size])
                        context = _context_for(
                            socket, client, msg.chaddr, ifindex, local_ip
                        )
                        self.metrics.packets_received += 1
                        msg.log(client, _net.SocketAddress(socket), _logging.DEBUG)
                        self.handle(msg, context)
                    except Exception as e:
                        LOGGER.error(
                            f"Encounter error handling request: {e.__class__.__name__} | {e}"
                        )
        except KeyboardInterrupt:
            LOGGER.info("Stopped listening due to Ctrl-C")
            self._cancellation_token.set()
        finally:
            self._cancellation_token = None


import asyncio as _asyncio


class _DhcpDatagramProtocol(_asyncio.DatagramProtocol):
    """Fallback receive path for loops without `add_reader`.

    Windows' default proactor loop raises NotImplementedError for socket
    readability, so it cannot use the reader path. It also has no IP_PKTINFO,
    so nothing is lost by receiving without control messages here.
    """

    def __init__(self, listener: "AsyncDhcpListener", sock: _socket.socket) -> None:
        self.listener = listener
        self.sock = sock
        self.transport: _ty.Optional[_asyncio.DatagramTransport] = None

    def connection_made(self, transport: _asyncio.BaseTransport) -> None:
        self.transport = _ty.cast(_asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # Hand off rather than handle here. This runs on the event loop, and the
        # handler is ordinary synchronous code -- lease lookups, a whole-file
        # rewrite in FileLeaseBackend, interface work -- so doing it inline
        # blocked every other coroutine in the host application for the duration
        # and made the server strictly serial anyway.
        self.listener._dispatch_received(data, _net.SocketAddress(*addr), self.sock)

    def error_received(self, exc: Exception) -> None:
        # Without this, a UDP error (an ICMP port-unreachable from a previous
        # send, typically) is swallowed by asyncio's default handler.
        LOGGER.warning(f"Async listener socket error: {exc.__class__.__name__} | {exc}")

    def connection_lost(self, exc: _ty.Optional[Exception]) -> None:
        if exc is not None:
            LOGGER.error(
                f"Async listener endpoint closed unexpectedly: "
                f"{exc.__class__.__name__} | {exc}"
            )


class AsyncDhcpListener:
    DEFAULT_PORTS: _ty.Sequence[int] = tuple(p.value for p in _enum.DhcpPort)

    def __init__(
        self,
        listen: ListenSpec = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: bool | None = None,
    ) -> None:
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._pktinfo = _pktinfo_supported(listen, per_interface)
        self._listen = _parselisteners(
            listen, self.DEFAULT_PORTS, expand_wildcard=not self._pktinfo
        )
        self._per_interface = per_interface
        self._sockets: list[_socket.socket] = []
        self._transports: list[_asyncio.DatagramTransport] = []
        self._readers: list[_socket.socket] = []
        self._loop: _ty.Optional[_asyncio.AbstractEventLoop] = None
        self._worker: _ty.Optional[_futures.ThreadPoolExecutor] = None
        self.metrics = DhcpMetrics()

    def _on_readable(self, sock: _socket.socket) -> None:
        """Read one datagram off a ready socket, on the event loop.

        Only the read happens here; the handler runs on the worker. Reading via
        add_reader rather than a DatagramTransport is what makes the packet-info
        path possible at all -- asyncio's transport calls sock.recvfrom() and
        offers no way to get at the control message that says which interface a
        broadcast arrived on.
        """
        try:
            if self._pktinfo:
                data, client, ifindex, local_ip = _recv_with_pktinfo(
                    sock, self._max_packet_size
                )
            else:
                data, client_tuple = sock.recvfrom(self._max_packet_size)
                client = _net.SocketAddress(*client_tuple)
                ifindex = None
                local_ip = None
        except BlockingIOError:  # pragma: no cover - spurious readability
            return
        except Exception as e:
            LOGGER.error(
                f"Encounter error reading async datagram: "
                f"{e.__class__.__name__} | {e}"
            )
            return
        self._dispatch_received(data, client, sock, ifindex, local_ip)

    def _dispatch_received(
        self,
        data: bytes,
        client: _net.SocketAddress,
        sock: _socket.socket,
        ifindex: "int | None" = None,
        local_ip: "_net.IPv4 | None" = None,
    ) -> None:
        """Run one datagram's handling off the event loop.

        Exactly one worker thread, so handlers still run one at a time and in
        arrival order. That matters: the lease backends are not thread-safe, so a
        pool here would trade a blocked event loop for a data race.
        """
        worker = self._worker
        if worker is None:  # not started through start(); keep working anyway
            self._handle_datagram(data, client, sock, ifindex, local_ip)
            return
        future = worker.submit(
            self._handle_datagram, data, client, sock, ifindex, local_ip
        )
        future.add_done_callback(self._report_worker_result)

    @staticmethod
    def _report_worker_result(future: "_futures.Future[None]") -> None:
        error = future.exception()
        if error is not None:  # pragma: no cover - _handle_datagram catches
            LOGGER.error(
                f"Unhandled error in async handler: "
                f"{error.__class__.__name__} | {error}"
            )

    def _handle_datagram(
        self,
        data: bytes,
        client: _net.SocketAddress,
        sock: _socket.socket,
        ifindex: "int | None" = None,
        local_ip: "_net.IPv4 | None" = None,
    ) -> None:
        try:
            msg = DhcpMessage.decode(memoryview(data))
            self.metrics.packets_received += 1
            msg.log(client, _net.SocketAddress(sock), _logging.DEBUG)
            context = _context_for(sock, client, msg.chaddr, ifindex, local_ip)
            self.handle(msg, context)
        except Exception as e:
            LOGGER.error(
                f"Encounter error handling async request from {client} : "
                f"{e.__class__.__name__} | {e}"
            )

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        pass

    def bind(self) -> None:
        _bind_sockets(self._listen, self._sockets, self._pktinfo, label="async")

    async def start(self) -> None:
        self.bind()
        if self._worker is None:
            self._worker = _futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="pydhcp-async-handler"
            )
        loop = _asyncio.get_running_loop()
        self._loop = loop
        for sock in self._sockets:
            sock.setblocking(False)
            try:
                loop.add_reader(sock.fileno(), self._on_readable, sock)
            except NotImplementedError:
                # Proactor loop (the Windows default): no socket readability, so
                # receive through a datagram transport instead. That path cannot
                # deliver control messages, which is why it is the fallback and
                # not the default -- but it is only ever taken where IP_PKTINFO
                # does not exist anyway.
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _DhcpDatagramProtocol(self, sock), sock=sock
                )
                self._transports.append(transport)
            else:
                self._readers.append(sock)

    def stop(self) -> _ty.Any:
        """Close every transport and socket.

        Deliberately not a coroutine, even though `await listener.stop()` is the
        documented form and still works. The work here is entirely synchronous,
        and as `async def` this silently did nothing whenever it was reached
        through the inherited `DhcpListener` contract: `server.stop()` returned a
        coroutine nobody awaited, so the server kept running with its ports
        bound, and mypy accepted it. Returning an already-finished future keeps
        the `await` form working from inside a running loop.
        """
        loop, self._loop = self._loop, None
        for sock in self._readers:
            if loop is not None:
                try:
                    loop.remove_reader(sock.fileno())
                except Exception:  # pragma: no cover - loop already closed
                    pass
        self._readers.clear()
        for transport in self._transports:
            transport.close()
        self._transports.clear()
        worker, self._worker = self._worker, None
        if worker is not None:
            # Don't wait: stop() is called from the event loop, and a handler in
            # flight may be doing exactly the blocking work this worker exists to
            # keep off it.
            worker.shutdown(wait=False)
        for sock in self._sockets:
            try:
                sock.close()
            except Exception:
                pass
        self._sockets.clear()

        try:
            future = _asyncio.get_running_loop().create_future()
        except RuntimeError:
            # No running loop, so nobody can be awaiting this anyway.
            return None
        future.set_result(None)
        return future
