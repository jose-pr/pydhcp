from __future__ import annotations

import enum as _enum
import typing as _ty
import ipaddress as _ip

import netimps as _netimps
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

    def hex(
        self, sep: _ty.Union[str, bytes, None] = None, bytes_per_sep: int = 1
    ) -> str:
        """``bytes.hex`` passthrough.

        The base type is a value object exposing ``.packed`` rather than a
        ``bytes`` subclass, so this method is not inherited -- but callers
        (and tests) predating that reasonably expect it. ``sep`` and
        ``bytes_per_sep`` mean what they do on :meth:`bytes.hex`; omitting
        ``sep`` gives the unseparated form.
        """
        if sep is None:
            return self.packed.hex()
        return self.packed.hex(sep, bytes_per_sep)


#: Pseudo-members for hardware types with no name, cached so identity holds.
_HTYPE_PSEUDO_MEMBERS: "dict[int, HardwareAddressType]" = {}


class HardwareAddressType(_enum.IntEnum):
    """IANA ARP hardware types, as used by the BOOTP `htype` field.

    Values 0-37 of the IANA "Number Hardware Type (hrd)" registry that are in
    use for DHCP; anything else in an octet becomes an unnamed pseudo-member
    rather than being rewritten (see `_missing_`).

    Defined here rather than in `packet/enums.py` (which re-exports it, and is
    where the rest of the message-header enums live) because it is what closes
    the `options` -> `packet` -> `options` import cycle: `ClientIdentifier`
    names its leading type octet with this enum, and reaching `packet.enums`
    for it meant a function-local import re-executed on every `__repr__`. This
    module imports nothing from the package, and it is where `MACAddress`
    already lives -- this enum says what kind of hardware address `chaddr`
    holds.
    """

    NONE = 0
    ETHERNET = 1
    EXPERIMENTAL_ETHERNET = 2
    AX25 = 3
    PRONET = 4
    CHAOS = 5
    IEEE_802 = 6
    ARCNET = 7
    HYPERCHANNEL = 8
    LANSTAR = 9
    AUTONET = 10
    LOCALTALK = 11
    LOCALNET = 12
    ULTRA_LINK = 13
    SMDS = 14
    FRAME_RELAY = 15
    ATM_16 = 16
    HDLC = 17
    FIBRE_CHANNEL = 18
    ATM_19 = 19
    SERIAL_LINE = 20
    ATM_21 = 21
    MIL_STD_188_220 = 22
    METRICOM = 23
    IEEE_1394 = 24
    MAPOS = 25
    TWINAXIAL = 26
    EUI_64 = 27
    HIPARP = 28
    IP_ARP_over_ISO_7816_3 = 29
    ARPSEC = 30
    IPSEC_TUNNEL = 31
    INFINIBAND = 32
    CAI = 33
    WIEGAND = 34
    PURE_IP = 35
    HW_EXP1 = 36
    HFI = 37

    @classmethod
    def _missing_(cls, value: object) -> "_ty.Optional[HardwareAddressType]":
        """Return an unnamed pseudo-member for any octet without one.

        Rewriting an unknown type to ETHERNET was destructive in exactly the way
        a relay must not be: RFC 1542 s4.1.2 has a relay alter giaddr and hops
        and nothing else, so forwarding an IPoIB request (RFC 4390, htype 32)
        handed the server a different htype than the client sent. The derived
        client identifier is built from this value too, so it changed as well.
        """
        if isinstance(value, str):
            # The round-trip form emitted by `label()`, so a message that went
            # out through to_mapping()/JSON comes back with its type intact.
            if value.startswith("HTYPE_") and value[6:].isdigit():
                value = int(value[6:])
            else:
                return None
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        if not 0 <= value <= 255:
            return None
        pseudo = _HTYPE_PSEUDO_MEMBERS.get(value)
        if pseudo is None:
            pseudo = int.__new__(cls, value)
            pseudo._name_ = None  # type: ignore[assignment]
            pseudo._value_ = value
            _HTYPE_PSEUDO_MEMBERS[value] = pseudo
        return pseudo

    def label(self) -> str:
        """Name of this hardware type, or `HTYPE_<n>` when it has none."""
        return self._name_ or f"HTYPE_{self.value}"

    def __repr__(self) -> str:
        # Without this an unnamed member reports `<HardwareAddressType.None: 32>`,
        # which reads as the NONE member (value 0) rather than "no name".
        return f"<{type(self).__name__}.{self.label()}: {self.value}>"

    def dumps(self, address: bytes) -> str:
        if self is HardwareAddressType.ETHERNET:
            return address.hex(":", 1).upper()
        return repr(address)


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
        """Create and bind a socket at this address.

        ``options`` are ``(level, name, value)`` triples applied before the
        bind. Delegates to :func:`netimps.bind`, which closes the socket before
        any exception propagates -- so a failed bind leaks nothing.

        ``reuse_address`` is left off: this has never set ``SO_REUSEADDR``
        implicitly, and turning it on now would let a socket bind a port still
        in ``TIME_WAIT``. Callers that want it pass it in ``options``, as
        ``listener.py`` does.
        """
        if fileno is not None:
            # netimps.bind() creates the socket itself, so an existing fd has
            # to keep the direct path.
            sock = _socket.socket(family, kind, proto, fileno)
            for opt in options:
                sock.setsockopt(*opt)
            sock.bind((str(self.ip), self.port))
            return sock

        return _netimps.bind(
            str(self.ip),
            self.port,
            family=family,
            kind=kind,
            reuse_address=False,
            options=tuple(options),
        )


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
        to: _ty.Optional[
            _ty.Union[SocketAddress, tuple[_ty.Union[IPv4, str], int], IPv4, str]
        ] = None,
    ) -> int:
        if to is None:
            to_addr: _ty.Union[
                SocketAddress, tuple[_ty.Union[IPv4, str], int], IPv4, str
            ] = self.client
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


#: RFC 3927 link-local. A host assigns itself one of these when DHCP fails, so
#: their presence usually means "no lease" -- which is why they are filtered by
#: default. Re-exported from netimps so the definition lives in one place.
APIPA = _netimps.APIPA


def host_ip_interfaces(
    filter: _ty.Union[_ty.Callable[[NetworkInterface], bool], bool] = True,
    family: _ty.Optional[int] = 4,
) -> _ty.Iterator[NetworkInterface]:
    """Yield one :class:`NetworkInterface` per local address.

    One entry *per address*, not per adapter, since callers here select and
    filter by address. ``filter`` defaults to excluding APIPA; pass ``False``
    for everything, or a predicate of your own.

    ``family`` defaults to **4**: this is a DHCPv4 implementation, and the
    enumeration it replaced was IPv4-only, so yielding IPv6 addresses would
    silently change what existing callers iterate over. Pass ``None`` for both
    families or ``6`` for IPv6 only.

    Enumeration comes from :func:`netimps.iter_addresses`, which reports real
    prefix lengths and human-readable adapter names on every platform.
    """
    if filter is True:
        filter = lambda ni: ni.ip not in APIPA
    for _index, ni in _iter_indexed_interfaces(family=family):
        if not filter or filter(ni):
            yield ni


def _iter_indexed_interfaces(
    family: _ty.Optional[int] = 4,
) -> _ty.Iterator[tuple[int, NetworkInterface]]:
    """Yield ``(if_index, NetworkInterface)`` once per local address.

    Internal: :class:`NetworkInterface` is keyed by address and deliberately
    carries no interface index, but the ``IP_PKTINFO`` receive path needs the
    index to pick the adapter a datagram arrived on. Keeping the construction
    here means :func:`host_ip_interfaces` and that path cannot drift apart.

    ``if_index`` is netimps' ``if_nametoindex`` value, or ``0`` if unknown.
    """
    for iface, address in _netimps.iter_addresses(family=family):
        yield iface.index, NetworkInterface(
            name=iface.name,
            ip_interface=address,
            mac=MACAddress(iface.mac) if iface.mac else None,
        )
