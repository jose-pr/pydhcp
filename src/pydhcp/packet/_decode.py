"""Decoding a DHCP message from the wire: liberal, lossless."""

from __future__ import annotations

import datetime as _dt
import typing as _ty

from . import enums as _enum
from .. import network as _net
from ..options import DhcpOptionCode, DhcpOptions, type as _type
from ._fields import (
    _MessageFields,
    _FIXED_HEADER_SIZE,
    _MAGIC_COOKIE_END,
    _HEADER_STRUCT,
    _decode_bootp_field,
)

#: The class `decode` is called on: it constructs `cls(...)`, so
#: `DhcpMessage.decode` is typed `DhcpMessage` and a subclass's is typed as
#: that subclass.
_Decoded = _ty.TypeVar("_Decoded", bound="_MessageDecode")


class _MessageDecode(_MessageFields):
    """`decode`."""

    @classmethod
    def decode(
        cls: "type[_Decoded]", data: _ty.Union[bytes, bytearray, memoryview]
    ) -> _Decoded:
        if not isinstance(data, memoryview):
            data = memoryview(data)
        if len(data) < _FIXED_HEADER_SIZE:
            raise ValueError(
                f"Packet is too short for DHCP fixed header: got {len(data)} bytes, need at least {_FIXED_HEADER_SIZE}"
            )
        if len(data) < _MAGIC_COOKIE_END:
            raise ValueError(
                f"Packet is too short for DHCP magic cookie at offset 236: got {len(data)} bytes, need at least {_MAGIC_COOKIE_END}"
            )
        (
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
        ) = _HEADER_STRUCT.unpack_from(data, 0)
        if hlen > 16:
            raise ValueError(f"Hardware address length {hlen} exceeds maximum of 16")
        op = _enum.OpCode(op)
        # Never rewritten: an unnamed type keeps its octet, so a relay forwards
        # the htype it received. The warning went too -- it fired once per
        # packet, which let one client flood the log.
        htype = _enum.HardwareAddressType(htype)
        secs = _dt.timedelta(seconds=secs)
        flags = _enum.Flags(flags & _enum.Flags.BROADCAST.value)
        ciaddr = _net.IPv4(ciaddr)
        yiaddr = _net.IPv4(yiaddr)
        siaddr = _net.IPv4(siaddr)
        giaddr = _net.IPv4(giaddr)
        chaddr = data[28 : 28 + hlen].tobytes()
        sname_data = data[44:108]
        file_data = data[108:236]

        if cls.MAGIC_COOKIE != data[236:240]:
            raise ValueError(
                f"Invalid magic cookie at offset 236: expected {cls.MAGIC_COOKIE.hex()}, got {data[236:240].hex()}"
            )

        options = DhcpOptions()
        remaining_opts = options.decode(data[240:], base_offset=240)
        if remaining_opts and remaining_opts[0] != 255:
            raise ValueError(
                f"Bad options terminator: expected 255 (END), got {remaining_opts[0]}"
            )

        overload = options.get(
            DhcpOptionCode.OPTION_OVERLOAD,
            default=_type.OptionOverload.NONE,
            decode=_type.OptionOverload,
        )

        # rfc3396 order
        if overload is not None and bool(
            overload.value & _type.OptionOverload.FILE.value
        ):
            options.decode(file_data, base_offset=108)
            file_raw: _ty.Optional[memoryview] = None
        else:
            file_raw = file_data

        if overload is not None and bool(
            overload.value & _type.OptionOverload.SNAME.value
        ):
            options.decode(sname_data, base_offset=44)
            sname_raw: _ty.Optional[memoryview] = None
        else:
            sname_raw = sname_data

        # Option 52 is *framing*, like PAD and END, and `decode` has just
        # consumed it: the options it pointed at have been moved out of
        # sname/file, and those fields now hold their literal values. Keeping
        # it left the decoded message asserting something untrue about itself
        # -- "my sname/file hold options" -- and broke round-tripping, which is
        # how a property test caught it: a message encoded at a size that
        # overloads came back carrying an option its original never had.
        #
        # `encode()` already deletes it for exactly this reason, so that a
        # relay forwarding a decoded reply does not tell the receiver to parse
        # sname/file as options. Dropping it here means that compensation is
        # no longer load-bearing.
        if int(DhcpOptionCode.OPTION_OVERLOAD) in options:
            del options[int(DhcpOptionCode.OPTION_OVERLOAD)]

        sname_str: str = ""
        if sname_raw is not None:
            sname_str = _decode_bootp_field(sname_raw, "sname")
        else:
            # Same reasoning as option 52 above, one level down. `encode` moves
            # `sname` into option 66 when it overloads the field, because the
            # field itself is carrying option fragments. Reading it back into
            # `sname` and *leaving* the option behind hands the caller the name
            # twice, under two spellings -- and the decoded message then no
            # longer matches the one that was encoded. Consume it, so the pair
            # stays inverse.
            tftp_val = options.get(
                DhcpOptionCode.TFTP_SERVER, default="", decode=_type.String
            )
            if tftp_val is not None:
                sname_str = str(tftp_val)
            if int(DhcpOptionCode.TFTP_SERVER) in options:
                del options[int(DhcpOptionCode.TFTP_SERVER)]

        file_str: str = ""
        if file_raw is not None:
            file_str = _decode_bootp_field(file_raw, "file")
        else:
            # As with option 66 above: option 67 is where `encode` parked
            # `file` to free the field for option fragments, so decode takes
            # it back out rather than reporting it in both places.
            bootfile_val = options.get(
                DhcpOptionCode.BOOTFILE_NAME, default="", decode=_type.String
            )
            if bootfile_val is not None:
                file_str = str(bootfile_val)
            if int(DhcpOptionCode.BOOTFILE_NAME) in options:
                del options[int(DhcpOptionCode.BOOTFILE_NAME)]

        # opts -> file -> sname

        # `cls`, not `DhcpMessage`: this is a classmethod, and hardcoding the
        # base made every subclass decode to a plain `DhcpMessage` while
        # `from_mapping` (which already used `cls`) returned the subclass.
        return cls(
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname_str,
            file_str,
            options,
        )
