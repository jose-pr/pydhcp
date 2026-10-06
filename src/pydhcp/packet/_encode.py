"""Encoding a DHCP message for the wire: strict, with RFC 3396 overload packing."""

from __future__ import annotations

import typing as _ty

from ..exceptions import DHCPValueError
from .. import _constants as _const, _nvt as _nvt
from ..options._codes import DHCPOptionCode
from ..options import _codecs as _type
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

    def _pack_options(
        self, max_options_field_size: int
    ) -> "tuple[_ty.Union[bytes, bytearray], _ty.Union[bytes, bytearray], _ty.Union[bytes, bytearray]]":
        """Lay the options out, overloading `sname`/`file` only as needed.

        Returns ``(options_field, sname_bytes, file_bytes)``. Each overload
        choice is *tried*, cheapest first, and the first that packs completely
        wins:

        1. no overload;
        2. choices that relocate no occupied field -- overloading an empty
           `sname` or `file` costs only its END octet -- smallest first;
        3. choices that move an occupied `sname`/`file` into option 66/67, which
           costs ``2 + len(value)`` octets of the options field, and which a
           PXE client reads less reliably than the fixed field.

        The overload field used to be picked from the overshoot alone (1-64
        octets over -> `sname`, 65-128 -> `file`, more -> both), ignoring
        whether the field was free. Measured: options one octet over the
        576-octet budget, with a 56-octet `sname` and an empty `file`, chose
        `sname`, moved it into option 66 (58 octets), overflowed, and raised --
        while the empty 128-octet `file` would have held everything. Within an
        equal cost the old preference (`sname`, then `file`, then both) stands,
        so every message that encoded before encodes the same way.

        Nothing may be left over: silently dropping options produces a reply
        the client accepts and acts on while missing (possibly) its server
        identifier or routes.
        """
        overload_type = _type.OptionOverload
        base = self.options.copy()
        # Whether THIS encode overloads is decided here, so drop any marker the
        # message is carrying. A decoded packet keeps its sender's OPTION_OVERLOAD,
        # and re-encoding it (a relay forwarding a PXE reply, say) would otherwise
        # tell the receiver to parse sname/file as options while they hold the
        # literal server name and boot file that decode moved out of them.
        if int(DHCPOptionCode.OPTION_OVERLOAD) in base:
            del base[int(DHCPOptionCode.OPTION_OVERLOAD)]
        sname_bytes: _ty.Union[bytes, bytearray] = _nvt.encode(self.sname)
        file_bytes: _ty.Union[bytes, bytearray] = _nvt.encode(self.file)
        if len(base.encode()) > max_options_field_size + 128 + 64:
            raise OverflowError("DHCP options exceed maximum packet size")

        def relocations(choice: _type.OptionOverload) -> int:
            return int(bool(choice & overload_type.FILE and self.file)) + int(
                bool(choice & overload_type.SNAME and self.sname)
            )

        # `sorted` is stable, so equal costs keep this order: sname, file, both.
        candidates = [overload_type.NONE] + sorted(
            (overload_type.SNAME, overload_type.FILE, overload_type.BOTH),
            key=relocations,
        )
        left_over = 0
        for choice in candidates:
            options = base.copy()
            if choice & overload_type.FILE and self.file:
                if DHCPOptionCode.BOOTFILE_NAME not in options:
                    options[DHCPOptionCode.BOOTFILE_NAME] = self.file
                    options._options.move_to_end(
                        int(DHCPOptionCode.BOOTFILE_NAME), False
                    )
            if choice & overload_type.SNAME and self.sname:
                if DHCPOptionCode.TFTP_SERVER not in options:
                    options[DHCPOptionCode.TFTP_SERVER] = self.sname
                    options._options.move_to_end(int(DHCPOptionCode.TFTP_SERVER), False)
            if choice is not overload_type.NONE:
                options._options[int(DHCPOptionCode.OPTION_OVERLOAD)] = bytearray(
                    [choice.value]
                )
                options._options.move_to_end(int(DHCPOptionCode.OPTION_OVERLOAD), False)
            # DHCP_MESSAGE_TYPE leads the options field whether or not we
            # overload, ahead of OPTION_OVERLOAD. RFC 2131 s3 walks the protocol
            # by message type, and receivers read option 53 before parsing the
            # rest -- it is what tells one whether the packet is even for it.
            try:
                options._options.move_to_end(
                    int(DHCPOptionCode.DHCP_MESSAGE_TYPE), False
                )
            except KeyError:
                pass

            if choice is overload_type.NONE:
                field = options.encode()
                if len(field) <= max_options_field_size:
                    return field, sname_bytes, file_bytes
                continue

            field, leftover = options.partial_encode(max_options_field_size)
            packed_file, packed_sname = file_bytes, sname_bytes
            if choice & overload_type.FILE and leftover is not None:
                packed_file, leftover = leftover.partial_encode(128)
            if choice & overload_type.SNAME and leftover is not None:
                packed_sname, leftover = leftover.partial_encode(64)
            if leftover is None:
                return field, packed_sname, packed_file
            left_over = len(leftover)

        raise OverflowError(
            "DHCP options exceed maximum packet size: "
            f"{left_over} option(s) did not fit"
        )

    def encode(self, max_packetsize: int = _const.DHCP_MIN_LEGAL_PACKET_SIZE) -> bytes:
        """Serialize the message, fitting it into `max_packetsize` octets.

        `max_packetsize` is the whole **IP datagram**, not the DHCP message, so
        the options field gets what is left after a fixed overhead:

            max_options_field_size = max_packetsize - 268
            268 = 20 (IPv4) + 8 (UDP) + 236 (fixed header) + 4 (magic cookie)

        The default, `DHCP_MIN_LEGAL_PACKET_SIZE` (576), is RFC 2131 s2's
        minimum datagram and leaves 308 octets for options. **269** is the floor
        -- 268 of overhead plus the one octet the END marker needs -- and
        anything below it raises `ValueError`, **including an explicit 0**: the
        argument used to run through `max_packetsize or DHCP_MIN_LEGAL_PACKET_SIZE`,
        so `encode(0)` quietly encoded to 576 instead. Silently using a number
        other than the one the caller named is the failure mode this module has
        spent the most time removing, and a caller passing 0 has a wrong belief
        worth reporting.

        Carrying any option at all needs 272: one option costs a code octet, a
        length octet and at least one more before END. Between 269 and 271 only
        an option-less message encodes, which is not a legal DHCP message
        anyway (RFC 2131 s3 requires option 53), so the floor is left at the
        arithmetic 269 rather than raising it to 272 and refusing calls that
        work today.

        Note that 576 is *not* a lower bound here. RFC 2132 s9.10's 576 minimum
        constrains what a client may advertise in option 57, which the server
        clamps on receipt; it does not constrain this API, and `encode(280)` is
        a legitimate call (it is tested).

        The result is padded up to `BOOTP_MIN_PACKET_SIZE` (300) with PAD octets
        after END, or to `max_packetsize` when that is smaller.

        Raises:
            ValueError: `max_packetsize` is below 269, or a header field is out
                of range, or `sname`/`file`/`chaddr` does not fit its fixed
                field.
            OverflowError: the options do not fit even with overloading.
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
        options_field, sname_bytes, file_bytes = self._pack_options(
            max_packetsize - _ENCODE_FIXED_OVERHEAD
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
        # five client builders, and the server's NAK -- was under that, measured
        # at 244-250 octets, while ISC dhclient was measured padding to exactly
        # 300 on the wire.
        floor = min(_const.BOOTP_MIN_PACKET_SIZE, max_packetsize)
        if len(data) < floor:
            data.extend(bytes(floor - len(data)))
        return bytes(data)

    def __bytes__(self) -> bytes:
        return self.encode()
