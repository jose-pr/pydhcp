"""Decoding a DHCP message from the wire: liberal, lossless."""

from __future__ import annotations

import ipaddress as _ipaddress
import datetime as _dt
import typing as _ty

from ..exceptions import DHCPDecodeError
from . import _enums as _enum

from ..options._codes import DHCPOptionCode
from ..options import DHCPOptions
from ..options import _codecs as _type
from ._fields import (
    _MessageFields,
    _FIXED_HEADER_SIZE,
    _MAGIC_COOKIE_END,
    _HEADER_STRUCT,
    _decode_bootp_field,
)

#: The class `decode` is called on: it constructs `cls(...)`, so
#: `DHCPMessage.decode` is typed `DHCPMessage` and a subclass's is typed as
#: that subclass.
_Decoded = _ty.TypeVar("_Decoded", bound="_MessageDecode")


class _MessageDecode(_MessageFields):
    """`decode`."""

    @classmethod
    def decode(
        cls: "type[_Decoded]", data: _ty.Union[bytes, bytearray, memoryview]
    ) -> _Decoded:
        """Parse one wire message.

        Liberal on receive, deliberately: there is no minimum size (a 241-octet
        message -- fixed header, magic cookie, END -- decodes), an `htype` with no
        IANA name is kept as an unnamed member rather than rewritten, `hlen = 0` is
        accepted (RFC 4390 requires it for IPoIB), and `sname`/`file` text that is
        not valid UTF-8 is preserved octet for octet. A relay must forward what it
        received. RFC 2132 s9.3 overload is honoured: options packed into `file`
        and `sname` are read back and the fields take their literal values from
        options 67/66. A missing END marker is accepted, in the options field and
        in an overloaded field alike (RFC 2131 s4.1 requires one; a message
        without it keeps what arrived). Constructs `cls`, so
        a subclass decodes to itself.

        Raises:
            DHCPDecodeError: shorter than the fixed header or magic cookie, a
                wrong magic cookie, `op` that is neither request nor reply, or
                `hlen > 16`. A `ValueError` too.
        """
        if not isinstance(data, memoryview):
            data = memoryview(data)
        if len(data) < _FIXED_HEADER_SIZE:
            raise DHCPDecodeError(
                f"Packet is too short for DHCP fixed header: got {len(data)} bytes, need at least {_FIXED_HEADER_SIZE}"
            )
        if len(data) < _MAGIC_COOKIE_END:
            raise DHCPDecodeError(
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
            raise DHCPDecodeError(
                f"Hardware address length {hlen} exceeds maximum of 16"
            )
        try:
            op = _enum.DHCPOpcode(op)
        except ValueError as exc:
            raise DHCPDecodeError(str(exc)) from exc
        # Never rewritten: an unnamed type keeps its octet, so a relay forwards
        # the htype it received. The warning went too -- it fired once per
        # packet, which let one client flood the log.
        htype = _enum.HardwareAddressType(htype)
        secs = _dt.timedelta(seconds=secs)
        # The reserved bits are kept: a relay forwards what it received.
        flags = _enum.DHCPFlags(flags)
        ciaddr = _ipaddress.IPv4Address(ciaddr)
        yiaddr = _ipaddress.IPv4Address(yiaddr)
        siaddr = _ipaddress.IPv4Address(siaddr)
        giaddr = _ipaddress.IPv4Address(giaddr)
        chaddr = data[28 : 28 + hlen].tobytes()
        sname_data = data[44:108]
        file_data = data[108:236]

        if cls.MAGIC_COOKIE != data[236:240]:
            raise DHCPDecodeError(
                f"Invalid magic cookie at offset 236: expected {cls.MAGIC_COOKIE.hex()}, got {data[236:240].hex()}"
            )

        options = DHCPOptions()
        options._decode_into(data[240:], base_offset=240)

        overload = options.get(
            DHCPOptionCode.OPTION_OVERLOAD,
            default=_type.OptionOverload.NONE,
            decode=_type.OptionOverload,
        )

        # rfc3396 order
        if overload is not None and bool(
            overload.value & _type.OptionOverload.FILE.value
        ):
            options._decode_into(file_data, base_offset=108)
            file_raw: _ty.Optional[memoryview] = None
        else:
            file_raw = file_data

        if overload is not None and bool(
            overload.value & _type.OptionOverload.SNAME.value
        ):
            options._decode_into(sname_data, base_offset=44)
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
        if int(DHCPOptionCode.OPTION_OVERLOAD) in options:
            del options[int(DHCPOptionCode.OPTION_OVERLOAD)]

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
                DHCPOptionCode.TFTP_SERVER, default="", decode=_type.String
            )
            if tftp_val is not None:
                sname_str = str(tftp_val)
            if int(DHCPOptionCode.TFTP_SERVER) in options:
                del options[int(DHCPOptionCode.TFTP_SERVER)]

        file_str: str = ""
        if file_raw is not None:
            file_str = _decode_bootp_field(file_raw, "file")
        else:
            # As with option 66 above: option 67 is where `encode` parked
            # `file` to free the field for option fragments, so decode takes
            # it back out rather than reporting it in both places.
            bootfile_val = options.get(
                DHCPOptionCode.BOOTFILE_NAME, default="", decode=_type.String
            )
            if bootfile_val is not None:
                file_str = str(bootfile_val)
            if int(DHCPOptionCode.BOOTFILE_NAME) in options:
                del options[int(DHCPOptionCode.BOOTFILE_NAME)]

        # opts -> file -> sname

        # `cls`, not `DHCPMessage`: this is a classmethod, and hardcoding the
        # base made every subclass decode to a plain `DHCPMessage` while
        # `from_mapping` (which already used `cls`) returned the subclass.
        return cls(
            op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=ciaddr,
            yiaddr=yiaddr,
            siaddr=siaddr,
            giaddr=giaddr,
            chaddr=chaddr,
            sname=sname_str,
            file=file_str,
            options=options,
        )
