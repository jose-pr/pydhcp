from __future__ import annotations

import enum as _enum
import ipaddress as _ip
import socket as _socket
import typing as _ty

import netimps as _netimps

#: Pseudo-members for hardware types with no name, cached so identity holds.
_HTYPE_PSEUDO_MEMBERS: "dict[int, HardwareAddressType]" = {}


class HardwareAddressType(_enum.IntEnum):
    """IANA ARP hardware types, as used by the BOOTP `htype` field.

    Values 0-37 of the IANA "Number Hardware Type (hrd)" registry that are in
    use for DHCP; anything else in an octet becomes an unnamed pseudo-member
    rather than being rewritten (see `_missing_`).

    Defined here rather than in `packet/_enums.py` (which re-exports it, and is
    where the rest of the message-header enums live) because it is what closes
    the `options` -> `packet` -> `options` import cycle: `ClientIdentifier`
    names its leading type octet with this enum, and reaching `packet._enums`
    for it meant a function-local import re-executed on every `__repr__`. This
    module imports nothing from the package.
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
    IP_ARP_OVER_ISO_7816_3 = 29
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
    ip: _ip.IPv4Address
    port: int


class SocketAddress(_SocketAddress):
    def __new__(cls, ip: _ty.Union[str, _ip.IPv4Address], port: int) -> "SocketAddress":
        return super(SocketAddress, cls).__new__(cls, _ip.IPv4Address(ip), int(port))

    @classmethod
    def from_socket(cls, sock: _socket.socket) -> "SocketAddress":
        """The local address `sock` is bound to; asks the socket (`getsockname()`)."""
        ip, port = sock.getsockname()[:2]
        return cls(ip, port)

    def compat(self) -> tuple[str, int]:
        return (str(self.ip), self.port)

    def __str__(self) -> str:
        return _netimps.join_host(self.ip, self.port)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(ip={self.ip}, port={self.port})"


class NetworkInterface(_ty.NamedTuple):
    name: str
    ip_interface: _ty.Union[_ip.IPv4Interface, _ip.IPv6Interface]
    mac: _ty.Optional[_netimps.MACAddress] = None

    @property
    def ip(self) -> _ty.Union[_ip.IPv4Address, _ip.IPv6Address]:
        return self.ip_interface.ip

    @property
    def network(self) -> _ty.Union[_ip.IPv4Network, _ip.IPv6Network]:
        return self.ip_interface.network


def host_ip_interfaces(
    filter: _ty.Union[_ty.Callable[[NetworkInterface], bool], bool] = True,
    family: _ty.Optional[int] = 4,
    *,
    cache: _ty.Union[bool, float] = False,
) -> _ty.Iterator[NetworkInterface]:
    """Yield one :class:`NetworkInterface` per local address.

    One entry *per address*, not per adapter, since callers here select and
    filter by address. ``filter`` defaults to excluding APIPA (RFC 3927: a host
    assigns itself one of those when DHCP fails, so one usually means "no
    lease"); pass ``False`` for everything, or a predicate of your own.

    ``family`` defaults to **4**: this is a DHCPv4 implementation. Pass ``None``
    for both families or ``6`` for IPv6 only.

    Enumeration comes from :func:`netimps.iter_addresses`, which reports real
    prefix lengths and human-readable adapter names on every platform. ``cache``
    is netimps' enumeration cache: ``False`` enumerates now, ``True`` reuses an
    enumeration up to ``netimps.INTERFACE_CACHE_TTL`` old, a number is that TTL
    in seconds. Per-packet callers pass ``True``.
    """
    if filter is True:
        filter = lambda ni: ni.ip not in _netimps.LINK_LOCAL_V4
    adapters = _netimps.get_interfaces(cache=cache)
    for iface, address in _netimps.iter_addresses(adapters, family=family):
        ni = NetworkInterface(
            name=iface.name, ip_interface=address, mac=iface.mac or None
        )
        if not filter or filter(ni):
            yield ni
