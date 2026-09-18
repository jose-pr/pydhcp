from __future__ import annotations
import enum as _enum
import typing as _ty

from ..options.type import DhcpOptionType

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

__all__ = [
    "DhcpMessageType",
    "OpCode",
    "DhcpPort",
    "Flags",
    "HardwareAddressType",
]


class DhcpMessageType(DhcpOptionType, _enum.IntEnum):
    """DHCP message types"""

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        option_part = option[:1]
        if len(option_part) != 1:
            raise ValueError()
        return cls(option_part[0]), 1

    def _dhcp_write(self, data: bytearray) -> int:
        data.append(self.value)
        return 1

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return 1

    def __repr__(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    DHCPDISCOVER = 1
    """ Client broadcast to locate available servers."""
    DHCPOFFER = 2
    """ Server to client in response to DHCPDISCOVER with offer of configuration parameters."""
    DHCPREQUEST = 3
    """Client message to servers either (a) requesting
    offered parameters from one server and implicitly
    declining offers from all others, (b) confirming
    correctness of previously allocated address after,
    e.g., system reboot, or (c) extending the lease on a
    particular network address."""
    DHCPDECLINE = 4
    """Client to server indicating network address is already
    in use."""
    DHCPACK = 5
    """Server to client with configuration parameters,
    including committed network address."""
    DHCPNAK = 6
    """Server to client indicating client's notion of network
    address is incorrect (e.g., client has moved to new
    subnet) or client's lease as expired"""
    DHCPRELEASE = 7
    """Client to server relinquishing network address and
    cancelling remaining lease."""
    DHCPINFORM = 8
    """ Client to server, asking only for local configuration
    parameters; client already has externally configured
    network address."""

    DHCPFORCERENEW = 9
    """Forces the client to the RENEW state. """
    DHCPLEASEQUERY = 10
    """The DHCPLEASEQUERY message is a new DHCP message type transmitted
   from a DHCP relay agent to a DHCP server.  A DHCPLEASEQUERY-aware
   relay agent sends the DHCPLEASEQUERY message when it needs to know
   the location of an IP endpoint.  The DHCPLEASEQUERY-aware DHCP server
   replies with a DHCPLEASEUNASSIGNED, DHCPLEASEACTIVE, or
   DHCPLEASEUNKNOWN message. """
    DHCPLEASEUNASSIGNED = 11
    """The DHCPLEASEUNASSIGNED is similar to a DHCPLEASEACTIVE message, but
   indicates that there is no currently active lease on the resultant IP
   address but that this DHCP server is authoritative for this IP
   address."""
    DHCPLEASEUNKNOWN = 12
    """The DHCPLEASEUNKNOWN message indicates that the DHCP server
   has no knowledge of the information specified in the query (e.g., IP
   address, MAC address, or Client-identifier option)."""
    DHCPLEASEACTIVE = 13
    """The DHCPLEASEACTIVE response to a
   DHCPLEASEQUERY message allows the relay agent to determine the IP
   endpoint location and the remaining duration of the IP address lease."""
    DHCPBULKLEASEQUERY = 14
    DHCPLEASEQUERYDONE = 15
    DHCPACTIVELEASEQUERY = 16
    DHCPLEASEQUERYSTATUS = 17
    DHCPTLS = 18


class OpCode(_enum.IntEnum):
    """Specifies if the message originates from a server or client"""

    BOOTREQUEST = 1
    """DHCP message sent from a client to a server."""
    BOOTREPLY = 2
    """DHCP message sent from a server to a client."""


class DhcpPort(_enum.IntEnum):
    SERVER = 67
    CLIENT = 68


class Flags(_enum.Flag):
    UNICAST = 0
    BROADCAST = 1 << 15
    """Set by client that cant listen to unicast response as it doesnt have an ip yet"""


#: Pseudo-members for hardware types with no name, cached so identity holds.
_HTYPE_PSEUDO_MEMBERS: "dict[int, HardwareAddressType]" = {}


class HardwareAddressType(_enum.IntEnum):
    """IANA ARP hardware types, as used by the BOOTP `htype` field.

    Values 0-37 of the IANA "Number Hardware Type (hrd)" registry that are in
    use for DHCP; anything else in an octet becomes an unnamed pseudo-member
    rather than being rewritten (see `_missing_`).
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
