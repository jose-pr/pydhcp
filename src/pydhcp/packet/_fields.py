"""The DHCP message's fields, and the wire constants and checks every layer shares."""

from __future__ import annotations

import dataclasses as _data
import datetime as _dt
import struct as _struct
import typing as _ty

from ..exceptions import DHCPValueError
from . import enums as _enum
from .. import constants as _const, network as _net, nvt as _nvt
from ..options import DhcpOptions

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
#: octet for the END marker. Measured 2026-09-20 across 266..284 -- 268 does
#: reach the encoder, but leaves a zero-length options field and dies inside
#: `partial_encode` on "Invalid Options Max Size", which names neither the
#: argument nor the shortfall.
_MIN_ENCODE_PACKET_SIZE = _ENCODE_FIXED_OVERHEAD + 1


#: Fixed widths of the BOOTP text fields, RFC 2131 s2 figure 1.
_SNAME_FIELD_SIZE = 64


_FILE_FIELD_SIZE = 128


_CHADDR_FIELD_SIZE = 16


def _check_header_int(field: str, value: _ty.Any, maximum: int) -> int:
    """Range-check a fixed-width header field before `struct` sees it.

    `_HEADER_STRUCT.pack_into` raises `struct.error` for an out-of-range value
    and names the *format character*, not the field: measured 2026-09-20,
    `hops=256`, `hlen=256` and `xid=2**32` each produced
    `'B' format requires 0 <= number <= 255` (or `'I' ...`), from which a caller
    cannot tell which of the four `B` fields was wrong. `struct.error` is also
    neither `ValueError` nor `TypeError`, so an `except ValueError` around a
    send path did not catch it.
    """
    if isinstance(value, int) and 0 <= value <= maximum:
        return int(value)
    raise DHCPValueError(
        f"{field}={value!r} does not fit its header field: "
        f"it must be an integer in 0..{maximum}"
    )


def _check_bootp_field(field: str, value: _ty.Sized, width: int) -> None:
    """Refuse to silently truncate a fixed-width BOOTP field.

    `sname`, `file` and `chaddr` were packed with `.ljust(width)[:width]`, so an
    over-long value lost its tail with no error and no log line. Measured
    2026-09-20: a 100-character `sname` and a 200-character `file` both encoded
    "successfully" at 300 octets, carrying the first 64 and 128 octets. `file`
    is the PXE boot filename -- a truncated one sends the client to a TFTP path
    that does not exist, and nothing in the exchange reports why it failed.

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
    re-encoding the message emits the name it received; `pydhcp.nvt` explains
    why that matters most for `file`, which is the PXE boot filename.
    """
    text = raw.tobytes().split(_NULL, 1)[0]
    return _nvt.decode(text, f"BOOTP {field} field")


@_data.dataclass
class _MessageFields:
    """The fields and class constants of `DhcpMessage` -- the dataclass itself.

    `DhcpMessage` is this class plus layers of behaviour, each subclassing the
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

    op: _enum.OpCode  # One byte
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
    flags: _enum.Flags  # 2 bytes
    """Only use for the BROADCAST flag in clients"""
    ciaddr: _net.IPv4
    """Client IP address; only filled in if client is in
    BOUND, RENEW or REBINDING state and can respond
    to ARP requests."""
    yiaddr: _net.IPv4
    """'your' (client) IP address."""
    siaddr: _net.IPv4
    """IP address of next server to use in bootstrap;
    returned in DHCPOFFER, DHCPACK by server."""
    giaddr: _net.IPv4
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
    options: DhcpOptions
    """Optional parameters field."""

    #: Key marking an option written as raw hex because its decoded form does
    #: not reproduce the original octets. Round-trips through JSON, YAML, TOML
    #: and INI alike, and `from_mapping` reads it back.
    HEX_VALUE_KEY: _ty.ClassVar[str] = "hex"
