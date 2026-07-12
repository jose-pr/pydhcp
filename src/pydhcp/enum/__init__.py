from .optioncode import DhcpOptionCode
from .messagetype import DhcpMessageType
import typing as _ty
import enum as _enum
from . import _optioncode_types


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


class HardwareAddressType(_enum.IntEnum):
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

    def dumps(self, address: bytes):
        match self:
            case HardwareAddressType.ETHERNET:
                return address.hex(":", 1).upper()
            case _other:
                return f"{address}"
