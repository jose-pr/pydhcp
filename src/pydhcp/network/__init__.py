from __future__ import annotations

import typing as _ty
import ipaddress as _ip

import netimps as _netimps
from . import platform as _platform
import socket as _socket

IPv4 = _ip.IPv4Address
IPv6 = _ip.IPv6Address
IP = _ty.Union[IPv4, IPv6]
IPv4Network = _ip.IPv4Network
IPv6Network = _ip.IPv6Network
IPNetwork = _ty.Union[IPv4Network, IPv6Network]
IPv4Interface = _ip.IPv4Interface

WILDCARD_IPv4 = IPv4("0.0.0.0")


class MACAddress(_netimps.MACAddress):
    """A hardware address rendered the way DHCP tooling expects.

    Only the *presentation* differs from :class:`netimps.MACAddress`:
    uppercase-hyphenated (``00-11-22-33-44-55``) rather than lowercase-colon,
    because that is the form this project's CLI and logs have always used.
    Parsing, comparison and hashing are inherited unchanged, so instances
    compare equal to the base type and interoperate with it as dict keys.

    Note this is a *display* type. The wire hardware address (``chaddr``,
    option 61) is raw ``bytes`` throughout ``packet/`` and never passes through
    here -- deliberately, since ``chaddr`` permits ``hlen`` up to 16 for
    non-Ethernet ``htype`` while a MAC is exactly 6.
    """

    def __str__(self) -> str:
        return self.as_str("-", upper=True)

    def hex(self, *args, **kwargs) -> str:
        """``bytes.hex`` passthrough.

        The base type is a value object exposing ``.packed`` rather than a
        ``bytes`` subclass, so this method is not inherited -- but callers
        (and tests) predating that reasonably expect it.
        """
        return self.packed.hex(*args, **kwargs)


class _SocketAddress(_ty.NamedTuple):
    ip: IPv4
    port: int


class SocketOption(_ty.NamedTuple):
    level: int
    name: int
    value: int


class SocketAddress(_SocketAddress):
    def __new__(
        cls,
        ip: _ty.Union[str, IPv4, _socket.socket],
        port: _ty.Optional[int] = None,
    ) -> "SocketAddress":
        if isinstance(ip, _socket.socket):
            ip_val, port_val = ip.getsockname()
        elif port is None:
            raise ValueError()
        else:
            ip_val, port_val = ip, port
        return super(SocketAddress, cls).__new__(cls, IPv4(ip_val), int(port_val))

    def compat(self) -> tuple[str, int]:
        return (str(self.ip), self.port)

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(ip={self.ip}, port={self.port})"

    def listen(
        self,
        family: _socket.AddressFamily = _socket.AF_INET,
        kind: _socket.SocketKind = _socket.SOCK_DGRAM,
        proto: int = 0,
        fileno: _ty.Optional[int] = None,
        options: _ty.Iterable[SocketOption] = (),
    ) -> _socket.socket:
        sock = _socket.socket(family, kind, proto, fileno)
        for opt in options:
            sock.setsockopt(*opt)
        sock.bind((str(self.ip), self.port))
        return sock


class SocketSession(_ty.NamedTuple):
    socket: _socket.socket
    client: SocketAddress

    @property
    def server(self) -> SocketAddress:
        ip, port = self.socket.getsockname()
        return SocketAddress(ip, port)

    def respond(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        to: _ty.Optional[_ty.Union[SocketAddress, tuple[_ty.Union[IPv4, str], int], IPv4, str]] = None,
    ) -> int:
        if to is None:
            to_addr: _ty.Union[SocketAddress, tuple[_ty.Union[IPv4, str], int], IPv4, str] = self.client
        else:
            to_addr = to

        if not isinstance(to_addr, (tuple, list)):
            dest: _ty.Union[IPv4, str] = to_addr
            port: int = self.client.port
        else:
            dest, port = to_addr

        dest_ip = IPv4(dest)
        dest_str = "255.255.255.255" if dest_ip == WILDCARD_IPv4 else str(dest_ip)
        return self.socket.sendto(data, (dest_str, int(port)))


class NetworkInterface(_ty.NamedTuple):
    name: str
    ip_interface: _ip.IPv4Interface | _ip.IPv6Interface
    mac: _ty.Optional[MACAddress] = None

    @property
    def ip(self) -> _ip.IPv4Address | _ip.IPv6Address:
        return self.ip_interface.ip

    @property
    def network(self) -> _ip.IPv4Network | _ip.IPv6Network:
        return self.ip_interface.network


APIPA = _ip.ip_network("169.254.0.0/16")


def host_ip_interfaces(
    filter: _ty.Union[_ty.Callable[[NetworkInterface], bool], bool] = True
) -> _ty.Iterator[NetworkInterface]:
    if filter is True:
        filter = lambda ni: ni.ip not in APIPA
    for name, ip_interface, mac in _platform.get_interfaces():
        mac_val = MACAddress(mac) if mac else None
        ni = NetworkInterface(
            name=name,
            ip_interface=ip_interface,
            mac=mac_val
        )
        if not filter or filter(ni):
            yield ni
