import socket as _socket
import select as _select
import threading as _thread
import typing as _ty

from . import netutils as _net, constants as _const, enum as _enum
from .message import DhcpMessage
from .log import LOGGER
from .metrics import METRICS
import logging as _logging


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


class RequestContext(_ty.NamedTuple):
    transport: Transport
    interface: _net.NetworkInterface
    client: _net.SocketAddress
    client_mac: bytes


def _parselisteners(
    listen: list[tuple[_net.IPv4, int] | _net.IPv4 | str] | str | None = None,
    default_ports: _ty.Sequence[int] = (),
) -> list[_net.SocketAddress]:
    _listen: list[_net.SocketAddress] = []
    if listen is None:
        listen = []
    elif not isinstance(listen, list):
        listen = [listen]
    for bind in listen:
        if not isinstance(bind, tuple):
            ip, port = (bind, None)
        else:
            ip, port = bind

        if not ip:
            ip = "127.0.0.1"
        elif ip == "*":
            ip = _net.WILDCARD_IPv4
        if not isinstance(ip, _net.IPv4):
            ip = _net.IPv4(ip)

        if ip == _net.WILDCARD_IPv4:
            ips = [
                i.ip for i in _net.host_ip_interfaces() if isinstance(i.ip, _net.IPv4)
            ]
        else:
            ips = [ip]
        for ip in ips:
            ports: _ty.Sequence[int]
            if port is None:
                ports = default_ports
            elif not isinstance(port, (list, tuple)):
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
    try:
        local_ip, _ = sock.getsockname()
    except Exception:
        local_ip = "127.0.0.1"
    
    for i in _net.host_ip_interfaces():
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
        listen: list[tuple[_net.IPv4, int] | _net.IPv4 | str] | str | None = None,
        select_timeout: float | None = None,
        max_packet_size: int | None = _const.UDP_MAX_PACKET_SIZE,
    ) -> None:
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._listen = _parselisteners(listen, self.DEFAULT_PORTS)
        self._sockets: list[_socket.socket] = []
        self._select_timeout = select_timeout or 1
        self._cancelleation_token: _thread.Event | None = None

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
            except PermissionError as e:
                raise PermissionError(
                    f"Permission denied binding to port {address.port}. Port {address.port} requires root; try 6767 for testing."
                ) from e
            except OSError as e:
                import errno
                if e.errno == errno.EACCES or getattr(e, "winerror", None) == 10013:
                    raise PermissionError(
                        f"Permission denied binding to port {address.port}. Port {address.port} requires root; try 6767 for testing."
                    ) from e
                elif e.errno == errno.EADDRINUSE or getattr(e, "winerror", None) == 10048:
                    raise OSError(
                        e.errno,
                        f"Port {address.port} already in use; try port {address.port + 1000}."
                    ) from e
                else:
                    raise
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
                        size, client_tuple = socket.recvfrom_into(view, self._max_packet_size)
                        METRICS.packets_received += 1
                        client = _net.SocketAddress(*client_tuple)
                        msg = DhcpMessage.decode(view[:size])
                        msg.log(client, _net.SocketAddress(socket), _logging.DEBUG)
                        interface = _resolve_interface(socket)
                        transport = UdpTransport(socket)
                        context = RequestContext(
                            transport=transport,
                            interface=interface,
                            client=client,
                            client_mac=msg.chaddr,
                        )
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
            METRICS.packets_received += 1
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
        listen: _ty.Optional[_ty.Union[_ty.List[_ty.Union[_ty.Tuple[_net.IPv4, int], _net.IPv4, str]], str]] = None,
        max_packet_size: _ty.Optional[int] = None,
    ) -> None:
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._listen = _parselisteners(listen, self.DEFAULT_PORTS)
        self._sockets: list[_socket.socket] = []
        self._transports: list[_asyncio.DatagramTransport] = []

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

