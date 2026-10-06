"""The DHCP message's fields, and the wire constants and checks every layer shares."""

from __future__ import annotations

import ipaddress as _ipaddress
import dataclasses as _data
import datetime as _dt
import struct as _struct
import typing as _ty

from ..exceptions import DHCPDecodeError, DHCPValueError
from . import _enums as _enum
from .. import _constants as _const, _nvt as _nvt
from ..options import DHCPOptions
from ..options._codes import DHCPOptionCode

_NULL = 0x00.to_bytes(1, "big")


_FIXED_HEADER_SIZE = 236


_MAGIC_COOKIE_END = 240


_HEADER_STRUCT = _struct.Struct("!BBBBIHHIIII")


#: Everything `encode`'s `max_packetsize` budget is spent on before the first
#: option octet. `max_packetsize` measures the whole IP datagram -- which is why
#: its default is RFC 2131 s2's 576-octet minimum datagram and not a message
#: length -- so the overhead is 20 (IPv4) + 8 (UDP), then the 236-octet fixed
#: header and the 4-octet magic cookie:
#:
#:     268 = 28 (UDP_MIN_PACKET_SIZE) + 240 (_MAGIC_COOKIE_END)
_ENCODE_FIXED_OVERHEAD = _const.UDP_MIN_PACKET_SIZE + _MAGIC_COOKIE_END


#: Smallest `max_packetsize` that can produce a packet: the overhead plus one
#: octet for the END marker. A `max_packetsize` of 268 reaches the encoder but
#: leaves a zero-length options field, which `partial_encode` rejects with
#: "Invalid Options Max Size", naming neither the argument nor the shortfall.
_MIN_ENCODE_PACKET_SIZE = _ENCODE_FIXED_OVERHEAD + 1


#: Fixed widths of the BOOTP text fields, RFC 2131 s2 figure 1.
_SNAME_FIELD_SIZE = 64


_FILE_FIELD_SIZE = 128


_CHADDR_FIELD_SIZE = 16


def _check_header_int(field: str, value: _ty.Any, maximum: int) -> int:
    """Range-check a fixed-width header field before `struct` sees it.

    `_HEADER_STRUCT.pack_into` raises `struct.error` for an out-of-range value
    and names the *format character*, not the field: `hops=256`, `hlen=256`
    and `xid=2**32` each raise `'B' format requires 0 <= number <= 255` (or
    `'I' ...`), from which a caller cannot tell which of the four `B` fields
    was wrong. `struct.error` is also neither `ValueError` nor `TypeError`, so
    an `except ValueError` around a send path would not catch it.
    """
    if isinstance(value, int) and 0 <= value <= maximum:
        return int(value)
    raise DHCPValueError(
        f"{field}={value!r} does not fit its header field: "
        f"it must be an integer in 0..{maximum}"
    )


def _check_bootp_field(field: str, value: _ty.Sized, width: int) -> None:
    """Refuse to silently truncate a fixed-width BOOTP field.

    Packing `sname`, `file` and `chaddr` with `.ljust(width)[:width]` would drop
    the tail of an over-long value with no error and no log line: a 100-character
    `sname` and a 200-character `file` would encode "successfully" at 300 octets,
    carrying only the first 64 and 128 octets. `file` is the PXE boot filename --
    a truncated one sends the client to a TFTP path that does not exist, and
    nothing in the exchange reports why it failed.

    Over-long options are handled instead of truncated (see `encode`'s overload
    branches), which is what makes doing neither here indefensible.
    """
    if len(value) > width:
        raise DHCPValueError(
            f"{field} is {len(value)} octets and does not fit its "
            f"{width}-octet BOOTP field"
        )


def _decode_bootp_field(raw: memoryview, field: str) -> str:
    """Decode a NUL-terminated BOOTP text field.

    RFC 2131 specifies NVT ASCII for `sname` and `file`, but senders do put other
    encodings there, and rejecting the field threw away the whole packet -- its
    message type and client id included -- over a name the receiver usually does
    not read. Undecodable octets are preserved rather than replaced, so a relay
    re-encoding the message emits the name it received; `pydhcp._nvt` explains
    why that matters most for `file`, which is the PXE boot filename.
    """
    text = raw.tobytes().split(_NULL, 1)[0]
    return _nvt.decode(text, f"BOOTP {field} field")


@_data.dataclass(init=False)
class _MessageFields:
    """The fields and class constants of `DHCPMessage` -- the dataclass itself.

    `DHCPMessage` is this class plus layers of behaviour, each subclassing the
    last (`_MessageDecode`, `_MessageEncode`, `_MessageMapping`,
    `_MessageDisplay`), so the fields are declared exactly once.
    """

    MIN_LEGAL_SIZE = _const.DHCP_MIN_LEGAL_PACKET_SIZE - _const.UDP_MIN_PACKET_SIZE
    """Smallest DHCP message every implementation must be able to handle: 548.

    RFC 2131 s2: 576 octets is the minimum IP datagram an IP host must be
    prepared to accept, and a DHCP client "MUST be prepared to receive DHCP
    messages with an 'options' field of at least length 312 octets". Those are
    the same statement -- the arithmetic closes exactly:

        576 - 20 (IPv4) - 8 (UDP)            = 548   this message
        548 - 236 (fixed header, op..file)   = 312   the options field

    So this is a floor on *capability*, not on any particular packet, which is
    why nothing enforces it: `decode()` deliberately accepts shorter messages
    (241 octets and up), and plenty of real senders emit them. The floor pydhcp
    applies to what it *sends* is a different and smaller number,
    `BOOTP_MIN_PACKET_SIZE` (300).
    """
    MAGIC_COOKIE: _ty.ClassVar[bytes] = 0x63825363.to_bytes(4, "big")
    """The first four octets of the 'options' field of the DHCP message decimal values: 99, 130, 83 and 99"""

    op: _enum.DHCPOpcode  # One byte
    """Message op code / message type"""
    htype: _enum.HardwareAddressType
    """Hardware address type, see ARP section in "Assigned Numbers" RFC"""
    hlen: int  # One byte
    """Hardware address length"""
    hops: int  # One byte
    """Client sets to zero, optionally used by relay agents when booting via a relay agent."""
    xid: int  # 4 bytes
    """Transaction ID, a random number chosen by the
    client, used by the client and server to associate
    messages and responses between a client and a server."""
    secs: _dt.timedelta  # 2 bytes
    """Filled in by client, seconds elapsed since client
    began address acquisition or renewal process."""
    flags: _enum.DHCPFlags  # 2 bytes
    """Only use for the BROADCAST flag in clients"""
    ciaddr: _ipaddress.IPv4Address
    """Client IP address; only filled in if client is in
    BOUND, RENEW or REBINDING state and can respond
    to ARP requests."""
    yiaddr: _ipaddress.IPv4Address
    """'your' (client) IP address."""
    siaddr: _ipaddress.IPv4Address
    """IP address of next server to use in bootstrap;
    returned in DHCPOFFER, DHCPACK by server."""
    giaddr: _ipaddress.IPv4Address
    """Relay agent IP address, used in booting via a
    relay agent."""
    chaddr: bytes  # 16 bytes
    """Client hardware address."""
    sname: str  # 64 bytes
    """Optional server host name, null terminated string."""
    file: str  # 128 bytes
    """Boot file name, null terminated string; "generic"
    name or null in DHCPDISCOVER, fully qualified
    directory-path name in DHCPOFFER."""
    options: DHCPOptions
    """Optional parameters field."""

    def __init__(
        self,
        op: _enum.DHCPOpcode,
        *,
        htype: _enum.HardwareAddressType = _enum.HardwareAddressType.ETHERNET,
        hlen: _ty.Optional[int] = None,
        hops: int = 0,
        xid: int = 0,
        secs: _dt.timedelta = _dt.timedelta(0),
        flags: _enum.DHCPFlags = _enum.DHCPFlags.UNICAST,
        ciaddr: _ipaddress.IPv4Address = _const.WILDCARD_V4,
        yiaddr: _ipaddress.IPv4Address = _const.WILDCARD_V4,
        siaddr: _ipaddress.IPv4Address = _const.WILDCARD_V4,
        giaddr: _ipaddress.IPv4Address = _const.WILDCARD_V4,
        chaddr: bytes = b"",
        sname: str = "",
        file: str = "",
        options: _ty.Optional[DHCPOptions] = None,
    ) -> None:
        """A message with every header field but `op` defaulted.

        `hlen` is the length of `chaddr` when left out, and must equal it when
        given: the header's hardware address length is the length of the address
        in the same header, so a message that says otherwise is refused here and
        by `encode`. (`decode` reads whatever `hlen` the sender wrote, and the
        address is that many octets, so a received message always agrees.) A
        fresh option bag is made when `options` is not given.
        """
        if hlen is None:
            hlen = len(chaddr)
        elif hlen != len(chaddr):
            raise DHCPValueError(
                f"hlen={hlen} is not the length of chaddr ({len(chaddr)} octets)"
            )
        self.op = op
        self.htype = htype
        self.hlen = hlen
        self.hops = hops
        self.xid = xid
        self.secs = secs
        self.flags = flags
        self.ciaddr = ciaddr
        self.yiaddr = yiaddr
        self.siaddr = siaddr
        self.giaddr = giaddr
        self.chaddr = chaddr
        self.sname = sname
        self.file = file
        self.options = DHCPOptions() if options is None else options

    @property
    def message_type(self) -> _ty.Optional[_enum.DHCPMessageType]:
        """The DHCP message type (option 53), or `None` when there is none to read.

        `None` for a message with no option 53 and for one whose payload is not
        a message type this package knows (the wrong length, or an unassigned
        number); the option's octets are still there to forward.
        """
        try:
            return self.options.get(
                DHCPOptionCode.DHCP_MESSAGE_TYPE, decode=_enum.DHCPMessageType
            )
        except DHCPDecodeError:
            return None

    @property
    def broadcast(self) -> bool:
        """Whether the broadcast bit of `flags` is set (RFC 2131 s2).

        The reserved bits are carried in `flags` as they were received.
        """
        return bool(int(self.flags) & int(_enum.DHCPFlags.BROADCAST))

    #: Key marking an option written as raw hex because its decoded form does
    #: not reproduce the original octets. Round-trips through JSON, YAML, TOML
    #: and INI alike, and `from_mapping` reads it back.
    HEX_VALUE_KEY: _ty.ClassVar[str] = "hex"
