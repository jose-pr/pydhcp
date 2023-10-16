from .options import DhcpOptionCode
from .messagetype import DhcpMessageType
from .hardwaretype import HardwareAddressType

import enum as _enum

# https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml


class OpCode(_enum.IntEnum):
    """Specifies if the message originates from a server or client"""

    BOOTREQUEST = 1
    """DHCP message sent from a client to a server."""
    BOOTREPLY = 2
    """DHCP message sent from a server to a client."""


class Flags(_enum.Flag):
    UNICAST = 0
    BROADCAST = 1 << 15
    """Set by client that cant listen to unicast response as it doesnt have an ip yet"""


class OptionOverload(_enum.Flag):
    NONE = 0
    FILE = 1
    SNAME = 2
    BOTH = FILE | SNAME


MAGIC_COOKIE = 0x63825363.to_bytes(4, "big")
"""The first four octets of the 'options' field of the DHCP message decimal values: 99, 130, 83 and 99"""

INIFINITE_LEASE_TIME = 0xFFFFFFFF

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

from ._optiontypes import _REGISTERED
