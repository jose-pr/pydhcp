from __future__ import annotations

import socket as _socket

import netimps as _netimps
import select as _select
import threading as _thread
import struct as _struct
import typing as _ty

from . import network as _net, constants as _const
from .packet import enums as _enum
from .packet.message import DhcpMessage
from .log import LOGGER
from .metrics import DhcpMetrics
import logging as _logging

IP_PKTINFO = getattr(_socket, "IP_PKTINFO", None)
CMSG_SPACE = getattr(_socket, "CMSG_SPACE", None)

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
            LOGGER.warning(f"UDP unicast to {dest_str} failed ({e}), falling back to broadcast.")
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
        if hasattr(self.socket, "sendmsg") and self.ifindex is not None and self.local_ip is not None and IP_PKTINFO is not None:
            pktinfo = _struct.pack("=I4s4s", self.ifindex, _socket.inet_aton(str(self.local_ip)), _socket.inet_aton(str(self.local_ip)))
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
    return any(_is_wildcard_binding(binding) for binding in _iter_listen_bindings(listen))


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


def _resolve_interface(sock: _socket.socket) -> _net.NetworkInterface:
    """Find the NetworkInterface a bound socket sits on.

    Falls back to a synthetic host-route entry when no local interface owns the
    address -- which happens for a wildcard bind, where getsockname() reports
    0.0.0.0. The synthetic entry keeps callers from having to special-case it.
    """
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
    LOGGER.warning(f"Could not resolve interface for IP {local_ip}; using synthetic interface")
    return _net.NetworkInterface(
        name=f"unknown[{local_ip}]",
        ip_interface=_ipaddress.IPv4Interface((str(ip_addr), 32)),
        mac=None
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
        self._pktinfo = (
            per_interface is not True
            and hasattr(_socket.socket, "recvmsg")
            and hasattr(_socket, "IP_PKTINFO")
            and _listen_uses_wildcard(listen)
        )
        self._listen = _parselisteners(listen, self.DEFAULT_PORTS, expand_wildcard=not self._pktinfo)
        self._per_interface = per_interface
        self._sockets: list[_socket.socket] = []
        self._select_timeout = select_timeout or 1
        self._cancelleation_token: _thread.Event | None = None
        self.metrics = DhcpMetrics()

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        pass

    def bind(self) -> None:
        active = {_net.SocketAddress(socket): socket for socket in self._sockets}
        _listen = []
        for address in self._listen:
            _listen.append(address)
            if address in active:
                continue
            LOGGER.info(f"Listening on: {address}")
            try:
                socket = address.listen(
                    _socket.AF_INET,
                    _socket.SOCK_DGRAM,
                    _socket.IPPROTO_UDP,
                    options=[
                        _net.SocketOption(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1),
                        _net.SocketOption(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1),
                    ],
                )
                if self._pktinfo and address.ip == _net.WILDCARD_IPv4:
                    if IP_PKTINFO is not None:
                        socket.setsockopt(_socket.IPPROTO_IP, IP_PKTINFO, 1)
            except OSError as e:
                # netimps recognises the POSIX errnos *and* the Windows
                # WinError codes, which differ; the DHCP-specific suggestion
                # is appended rather than replacing the generic diagnosis.
                hint = _netimps.bind_error_hint(e, address.port)
                if hint is None:
                    raise
                if isinstance(e, PermissionError) or "permission" in hint.lower():
                    raise PermissionError(
                        f"{hint}. Try 6767 for testing."
                    ) from e
                if "in use" in hint:
                    raise OSError(
                        e.errno, f"{hint}; try port {address.port + 1000}."
                    ) from e
                raise OSError(e.errno, hint) from e
            self._sockets.append(socket)
        for address, socket in active.items():
            if address not in _listen:
                self._sockets.remove(socket)
                try:
                    socket.close()
                except:
                    pass

    def stop(self) -> None:
        if self._cancelleation_token is not None:
            self._cancelleation_token.set()

    def wait(self) -> None:
        while self._cancelleation_token is not None:
            self._cancelleation_token.wait(self._select_timeout)

    def start(self, cancellation_token: _thread.Event | None = None) -> _thread.Thread | None:
        if not self._cancelleation_token:
            thread = _thread.Thread(target=self.listen, args=())
            self._cancelleation_token = cancellation_token or _thread.Event()
            import signal

            def stop(*args: _ty.Any) -> None:
                self.stop()
                LOGGER.info("Stopped listening due to Ctrl-C")

            signal.signal(signal.SIGINT, stop)
            thread.start()
            return thread
        return None

    def listen(self) -> None:
        self.bind()
        listen = True
        rlist: list[_socket.socket]
        buffer = bytearray(self._max_packet_size)
        view = memoryview(buffer)
        if self._cancelleation_token is None:
            self._cancelleation_token = _thread.Event()
        try:
            while listen and not self._cancelleation_token.is_set():
                rlist, _, _ = _select.select(
                    list(self._sockets), [], [], self._select_timeout
                )
                if self._cancelleation_token.is_set():
                    break
                for socket in rlist:
                    try:
                        if self._pktinfo and hasattr(socket, "recvmsg"):
                            if CMSG_SPACE is None or IP_PKTINFO is None:
                                raise RuntimeError("packet info support unavailable")
                            data, ancdata, _, client_tuple = socket.recvmsg(
                                self._max_packet_size,
                                CMSG_SPACE(_struct.calcsize("=I4s4s")),
                            )
                            size = len(data)
                            local_ip = None
                            ifindex = None
                            for level, ctype, cdata in ancdata:
                                if level == _socket.IPPROTO_IP and ctype == IP_PKTINFO:
                                    ifindex, dst1, _ = _struct.unpack(
                                        "=I4s4s", cdata[: _struct.calcsize("=I4s4s")]
                                    )
                                    local_ip = _net.IPv4(_socket.inet_ntoa(dst1))
                                    break
                            msg = DhcpMessage.decode(memoryview(data))
                            client = _net.SocketAddress(*client_tuple)
                            interface = _resolve_interface(socket)
                            pkt_transport = PktInfoUdpTransport(socket)
                            context = RequestContext(
                                transport=pkt_transport,
                                interface=interface,
                                client=client,
                                client_mac=msg.chaddr,
                                ifindex=ifindex,
                                local_ip=local_ip,
                            )
                            pkt_transport.ifindex = ifindex
                            pkt_transport.local_ip = local_ip
                        else:
                            size, client_tuple = socket.recvfrom_into(view, self._max_packet_size)
                            client = _net.SocketAddress(*client_tuple)
                            msg = DhcpMessage.decode(view[:size])
                            interface = _resolve_interface(socket)
                            transport = UdpTransport(socket)
                            context = RequestContext(
                                transport=transport,
                                interface=interface,
                                client=client,
                                client_mac=msg.chaddr,
                            )
                        self.metrics.packets_received += 1
                        msg.log(client, _net.SocketAddress(socket), _logging.DEBUG)
                        self.handle(msg, context)
                    except Exception as e:
                        if isinstance(e, KeyboardInterrupt):
                            raise e
                        LOGGER.error(
                            f"Encounter error handling request: {e.__class__.__name__} | {e}"
                        )
        except KeyboardInterrupt:
            LOGGER.info("Stopped listening due to Ctrl-C")
            self._cancelleation_token.set()
        finally:
            self._cancelleation_token = None


# Key by default is (subnet, mac) unless client identifier option set

#

import asyncio as _asyncio

class _DhcpDatagramProtocol(_asyncio.DatagramProtocol):
    def __init__(self, listener: "AsyncDhcpListener", sock: _socket.socket) -> None:
        self.listener = listener
        self.sock = sock
        self.transport: _ty.Optional[_asyncio.DatagramTransport] = None

    def connection_made(self, transport: _asyncio.BaseTransport) -> None:
        self.transport = _ty.cast(_asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            client = _net.SocketAddress(*addr)
            msg = DhcpMessage.decode(memoryview(data))
            self.listener.metrics.packets_received += 1
            msg.log(client, _net.SocketAddress(self.sock), _logging.DEBUG)
            interface = _resolve_interface(self.sock)
            transport = UdpTransport(self.sock)
            context = RequestContext(
                transport=transport,
                interface=interface,
                client=client,
                client_mac=msg.chaddr,
            )
            self.listener.handle(msg, context)
        except Exception as e:
            if isinstance(e, KeyboardInterrupt):
                raise e
            LOGGER.error(
                f"Encounter error handling async request from {addr} : {e.__class__.__name__} | {e}"
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
        self._pktinfo = False
        self._listen = _parselisteners(listen, self.DEFAULT_PORTS, expand_wildcard=True)
        self._per_interface = per_interface
        self._sockets: list[_socket.socket] = []
        self._transports: list[_asyncio.DatagramTransport] = []
        self.metrics = DhcpMetrics()

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        pass

    def bind(self) -> None:
        active = {_net.SocketAddress(socket): socket for socket in self._sockets}
        _listen = []
        for address in self._listen:
            _listen.append(address)
            if address in active:
                continue
            LOGGER.info(f"Listening on (async): {address}")
            socket = address.listen(
                _socket.AF_INET,
                _socket.SOCK_DGRAM,
                _socket.IPPROTO_UDP,
                options=[
                    _net.SocketOption(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1),
                    _net.SocketOption(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1),
                ],
            )
            self._sockets.append(socket)
        for address, socket in active.items():
            if address not in _listen:
                self._sockets.remove(socket)
                try:
                    socket.close()
                except Exception:
                    pass

    async def start(self) -> None:
        self.bind()
        loop = _asyncio.get_running_loop()
        for sock in self._sockets:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _DhcpDatagramProtocol(self, sock),
                sock=sock
            )
            self._transports.append(transport)

    async def stop(self) -> None:
        for transport in self._transports:
            transport.close()
        self._transports.clear()
        for sock in self._sockets:
            try:
                sock.close()
            except Exception:
                pass
        self._sockets.clear()

