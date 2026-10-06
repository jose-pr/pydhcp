from __future__ import annotations
import enum as _enum

from ..options._codecs._message_type import DHCPMessageType as DHCPMessageType

# `htype` is a message-header field, so `pydhcp.packet` exports it, but the enum is
# defined in `pydhcp._network`: the option codecs name it too, and the options
# package imports nothing from `pydhcp.packet`.
from .._network import HardwareAddressType as HardwareAddressType

__all__ = [
    "DHCPMessageType",
    "DHCPOpcode",
    "DHCPPort",
    "DHCPFlags",
    "HardwareAddressType",
]


class DHCPOpcode(_enum.IntEnum):
    """Specifies if the message originates from a server or client"""

    BOOTREQUEST = 1
    """DHCP message sent from a client to a server."""
    BOOTREPLY = 2
    """DHCP message sent from a server to a client."""


class DHCPPort(_enum.IntEnum):
    SERVER = 67
    CLIENT = 68


class DHCPFlags(_enum.Flag):
    UNICAST = 0
    BROADCAST = 1 << 15
    """Set by client that cant listen to unicast response as it doesnt have an ip yet"""
