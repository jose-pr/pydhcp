"""Encoding a DHCP message for the wire: strict about what is written."""

from __future__ import annotations

from ..exceptions import DHCPValueError
from .. import _constants as _const, _nvt as _nvt
from . import _layout
from ._decode import _MessageDecode
from ._fields import (
    _FIXED_HEADER_SIZE,
    _MAGIC_COOKIE_END,
    _HEADER_STRUCT,
    _ENCODE_FIXED_OVERHEAD,
    _MIN_ENCODE_PACKET_SIZE,
    _SNAME_FIELD_SIZE,
    _FILE_FIELD_SIZE,
    _CHADDR_FIELD_SIZE,
    _check_header_int,
    _check_bootp_field,
)


class _MessageEncode(_MessageDecode):
    """`encode`, and choosing how options overload `sname`/`file`."""

    def encode(self, max_packetsize: int = _const.DHCP_MIN_LEGAL_PACKET_SIZE) -> bytes:
        """Serialize the message, fitting it into `max_packetsize` octets.

        `max_packetsize` is the whole **IP datagram**, not the DHCP message, so
        the options field gets what is left after a fixed overhead:

            max_options_field_size = max_packetsize - 268
            268 = 20 (IPv4) + 8 (UDP) + 236 (fixed header) + 4 (magic cookie)

        The default, `DHCP_MIN_LEGAL_PACKET_SIZE` (576), is RFC 2131 s2's
        minimum datagram and leaves 308 octets for options. **269** is the floor
        -- 268 of overhead plus the one octet the END marker needs -- and
        anything below it raises `ValueError`, **including an explicit 0**: a
        caller passing 0 has a wrong belief worth reporting, and encoding to
        another size instead would hide it. 576 is *not* a lower bound: RFC 2132
        s9.10's 576 minimum constrains what a client may advertise in option 57,
        and `encode(280)` is a legitimate call.

        The options are written in one pass when they fit the options field. When
        they do not, `sname` and `file` carry some (RFC 2131 s4.1, RFC 3396; see
        `_layout`): option 53 and option 52 stay first in the options field, an
        occupied name moves into option 66 or 67, and a name too long for its
        field travels that way too. A message needs at least 275 for any
        overload, since the options field then holds options 53 and 52.

        The result is padded up to `BOOTP_MIN_PACKET_SIZE` (300) with PAD octets
        after END, never past `max_packetsize` less the 28 octets of IPv4 and UDP
        header.

        Raises:
            ValueError: `max_packetsize` is below 269, or a header field is out
                of range, or `chaddr` does not fit its fixed field.
            OverflowError: the options, with the names that move into options 66
                and 67, do not fit the three fields. The message names the
                option that did not fit and how many octets short the room is.
            DHCPValueError: a name cannot travel as an option because option 66
                or 67 already holds other octets.
        """
        max_packetsize = int(max_packetsize)
        if max_packetsize < _MIN_ENCODE_PACKET_SIZE:
            raise ValueError(
                f"max_packetsize={max_packetsize} cannot hold a DHCP packet: "
                f"the minimum is {_MIN_ENCODE_PACKET_SIZE}, being "
                f"{_const.UDP_MIN_PACKET_SIZE} octets of IPv4 and UDP header, "
                f"{_FIXED_HEADER_SIZE} of fixed header, "
                f"{_MAGIC_COOKIE_END - _FIXED_HEADER_SIZE} of magic cookie and "
                "1 for the END marker"
            )
        options_field, sname_bytes, file_bytes = _layout.pack(
            self.options._options,
            _nvt.encode(self.sname),
            _nvt.encode(self.file),
            max_packetsize - _ENCODE_FIXED_OVERHEAD,
            max_packetsize,
            self.options._describe,
        )

        # Validate what is actually packed, not what the caller set: encode()
        # legitimately *moves* a long sname/file out into options 66 and 67 when
        # it overloads, and `sname_bytes`/`file_bytes` are then the option
        # fragments `partial_encode` produced, already bounded by the field
        # width it was given.
        _check_bootp_field("sname", sname_bytes, _SNAME_FIELD_SIZE)
        _check_bootp_field("file", file_bytes, _FILE_FIELD_SIZE)
        _check_bootp_field("chaddr", self.chaddr, _CHADDR_FIELD_SIZE)
        if self.hlen != len(self.chaddr):
            raise DHCPValueError(
                f"hlen={self.hlen} is not the length of chaddr "
                f"({len(self.chaddr)} octets)"
            )

        data = bytearray(28)
        _HEADER_STRUCT.pack_into(
            data,
            0,
            self.op.value,
            int(self.htype),
            # 16, not 255: `chaddr` is a 16-octet field, so a larger `hlen` is a
            # lie the receiver acts on -- it reads past chaddr into `sname`.
            # `decode` already rejects it with the same bound, and the two
            # disagreed: hlen=17 encoded happily and would not decode back.
            _check_header_int("hlen", self.hlen, _CHADDR_FIELD_SIZE),
            _check_header_int("hops", self.hops, 0xFF),
            _check_header_int("xid", self.xid, 0xFFFFFFFF),
            # `secs` is clamped rather than rejected: it is an elapsed time the
            # client reports, an overlong one is not a caller error, and RFC
            # 2131 s4.4.1 only requires it to be monotonic within an exchange.
            min(0xFFFF, max(0, int(self.secs.total_seconds()))),
            int(self.flags),
            int(self.ciaddr),
            int(self.yiaddr),
            int(self.siaddr),
            int(self.giaddr),
        )
        # No trailing `[:width]` slice: it was the silent truncation, and
        # `_check_bootp_field` above has already refused anything longer.
        data.extend(self.chaddr.ljust(_CHADDR_FIELD_SIZE, b"\x00"))
        data.extend(sname_bytes.ljust(_SNAME_FIELD_SIZE, b"\x00"))
        data.extend(file_bytes.ljust(_FILE_FIELD_SIZE, b"\x00"))
        data.extend(self.MAGIC_COOKIE)
        data.extend(options_field)

        # Pad to the minimal BOOTP message. These are PAD octets after END, which
        # every parser skips, but their absence is not inert: RFC 1542 s2.1 has a
        # relay agent verify the datagram could hold 300 octets and silently
        # discard it otherwise. Every message pydhcp emits with few options -- all
        # five client builders, and the server's NAK -- is under that unpadded
        # (measured at 244-250 octets), while ISC dhclient was measured padding
        # to exactly 300 on the wire.
        floor = min(
            _const.BOOTP_MIN_PACKET_SIZE, max_packetsize - _const.UDP_MIN_PACKET_SIZE
        )
        if len(data) < floor:
            data.extend(bytes(floor - len(data)))
        return bytes(data)

    def __bytes__(self) -> bytes:
        return self.encode()
