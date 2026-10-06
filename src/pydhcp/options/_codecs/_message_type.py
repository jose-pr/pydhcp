"""The DHCP message type: the codec of option 53 (RFC 2132 s9.6).

Defined here, in the options package, because the option registry binds it to
`DHCPOptionCode.DHCP_MESSAGE_TYPE` and the registry loads with the options
package; `pydhcp.packet` re-exports the same object.
"""

from __future__ import annotations

import enum as _enum
import typing as _ty

from ...exceptions import DHCPDecodeError
from ._base import DHCPOptionType

__all__ = ["DHCPMessageType"]


_DHCPMessageTypeT = _ty.TypeVar("_DHCPMessageTypeT", bound="DHCPMessageType")


class DHCPMessageType(DHCPOptionType, _enum.IntEnum):
    """DHCP message types"""

    @classmethod
    def _dhcp_read(
        cls: type[_DHCPMessageTypeT], option: memoryview
    ) -> tuple[_DHCPMessageTypeT, int]:
        option_part = option[:1]
        if len(option_part) != 1:
            raise DHCPDecodeError(
                "DHCP_MESSAGE_TYPE needs 1 octet, got 0 (RFC 2132 s9.6)"
            )
        try:
            return cls(option_part[0]), 1
        except ValueError as exc:
            raise DHCPDecodeError(str(exc)) from exc

    def _dhcp_write(self, data: bytearray) -> int:
        data.append(self.value)
        return 1

    @classmethod
    def _dhcp_len_hint(cls) -> _ty.Optional[int]:
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
