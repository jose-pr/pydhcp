import socket as _socket
import select as _select
import threading as _thread

from .netutils import Address, all_ipv4_addresses, IPAddress, ALL_IPS
from .message import DhcpMessage
from .log import LOGGER
from . import iana as _iana


def _parselisteners(
    listen: list[tuple[IPAddress, int] | IPAddress | str] = None,
    default_ports: list = [],
):
    _listen: list[Address] = []
    listen = listen or []
    if not isinstance(listen, list):
        listen = [listen]
    for bind in listen:
        if not isinstance(bind, tuple):
            ip, port = (bind, None)
        else:
            ip, port = bind

        if not ip:
            ip = "127.0.0.1"
        elif ip == "*":
            ip = ALL_IPS
        if not isinstance(ip, IPAddress):
            ip = IPAddress(ip)

        if ip == ALL_IPS:
            ips = all_ipv4_addresses()
        else:
            ips = [ip]
        for ip in ips:
            if not port:
                port = default_ports
            if port and not isinstance(port, (list, tuple)):
                port = [port]
            for port in port:
                port = int(port)
                bind = Address(ip, port)
                if bind not in _listen:
                    _listen.append(bind)
    return _listen


class DhcpListener:
    DEFAULT_PORTS = (_iana.DHCP_SERVER_PORT, _iana.DHCP_CLIENT_PORT)

    def __init__(
        self,
        listen: list[tuple[IPAddress, int] | IPAddress | str] = None,
        select_timeout=None,
    ) -> None:
        if listen is None:
            listen = "*"
        self._listen = _parselisteners(listen, self.DEFAULT_PORTS)
        self._sockets: list[_socket.socket] = []
        self._select_timeout = select_timeout or 1
        self._cancelleation_token: _thread.Event = None

    def handle(
        self, msg: DhcpMessage, client: Address, server: Address, socket: _socket.socket
    ):
        pass

    def bind(self):
        active = {socket.getsockname(): socket for socket in self._sockets}
        _listen = []
        for address in self._listen:
            address = address.compat()
            _listen.append(address)
            if address in active:
                continue
            LOGGER.info(f"Listening on: {address}")
            socket = _socket.socket(
                _socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_UDP
            )
            socket.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            socket.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
            socket.bind(address)
            self._sockets.append(socket)
        for address, socket in active.items():
            if address not in _listen:
                self._sockets.remove(socket)
                try:
                    socket.close()
                except:
                    pass

    def stop(self):
        if self._cancelleation_token is not None:
            self._cancelleation_token.set()

    def wait(self):
        while self._cancelleation_token is not None:
            self._cancelleation_token.wait(self._select_timeout)

    def start(self, cancellation_token: _thread.Event = None):
        if not self._cancelleation_token:
            thread = _thread.Thread(target=self.listen, args=())
            self._cancelleation_token = cancellation_token or _thread.Event()
            import signal

            def stop(*args):
                self.stop()
                LOGGER.info("Stopped listening due to Ctrl-C")

            signal.signal(signal.SIGINT, stop)
            thread.start()
            return thread
        return None

    def listen(self):
        self.bind()
        listen = True
        rlist: list[_socket.socket]
        buffer = bytearray(4096)
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
                    size, client = socket.recvfrom_into(view, 4096)
                    client = Address(*client)
                    server = Address(*socket.getsockname())
                    try:
                        msg = DhcpMessage.decode(view[:size])
                        header = f"{"#" * 10} DHCP MESSAGE From: {client} Received By: {server} {"#" * 10}"
                        LOGGER.debug(f"\n{header}\n{msg.dumps()}\n{"#" * len(header)}")
                        self.handle(msg, client, server, socket)
                    except Exception as e:
                        if isinstance(e, KeyboardInterrupt):
                            raise e
                        LOGGER.error(
                            f"Encounter error handling request from {client} at {server} : {e.__class__.__name__} | {e}"
                        )
        except KeyboardInterrupt:
            LOGGER.info("Stopped listening due to Ctrl-C")
            self._cancelleation_token.set()
        finally:
            self._cancelleation_token = None


# Key by default is (subnet, mac) unless client identifier option set

#
