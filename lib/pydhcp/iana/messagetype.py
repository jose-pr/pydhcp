import enum as _enum
from . import options as _opts
from ..optiontype import DhcpOptionType
import typing as _ty

if _ty.TYPE_CHECKING:
    from typing_extensions import Self


class DhcpMessageType(DhcpOptionType, _enum.IntEnum):
    """DHCP message types"""

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        assert len(option) == 1
        return cls(option[0]), 1

    def _dhcp_write(self, data: bytearray):
        data.append(self)
        return 1

    @classmethod
    def _dhcp_len_hint(self):
        return 1

    def __repr__(self):
        return self.name

    def __str__(self):
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


_opts.DhcpOptionCode.DHCP_MESSAGE_TYPE.register_type(DhcpMessageType)
