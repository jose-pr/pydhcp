from ..options import DhcpOptionCode, DhcpOptions, BaseDhcpOptionCode
from ..options import type as _type
from .. import network as _net, constants as _const, nvt as _nvt
from . import enums as _enum
from ..log import LOGGER
import struct as _struct
import enum as _enum_base
import typing as _ty
import dataclasses as _data
import datetime as _dt
import textwrap as _tw

_NULL = 0x00.to_bytes(1, "big")


class NoClientIdentity(ValueError):
    """Raised when a message carries nothing that identifies its client.

    A `ValueError` subclass so existing `except ValueError` handlers keep
    working, but distinguishable for callers that want to drop the message
    rather than fail.
    """


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
    raise ValueError(
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
        raise ValueError(
            f"{field} is {len(value)} octets and does not fit its "
            f"{width}-octet BOOTP field"
        )


def _strip_hex_text(value: str) -> str:
    return "".join(ch for ch in value if ch not in " \t\r\n:")


def _enum_name(value: _ty.Any) -> _ty.Any:
    """Name an enum value for structured output, or fall back to its number.

    `.name` is None for a value with no member -- an OPTION_OVERLOAD of 4, say,
    or any flag combination the enum does not spell. Emitting that put a null
    where a string belongs and the document would not load back.
    """
    if isinstance(value, _enum_base.Enum):
        return value.name if value.name is not None else _enum_value_of(value)
    return value


def _enum_value_of(value: _ty.Any) -> _ty.Any:
    inner = getattr(value, "value", value)
    return int(inner) if isinstance(inner, int) else inner


def _coerce_enum_value(enum_type: type[_ty.Any], value: _ty.Any) -> _ty.Any:
    if isinstance(value, str):
        try:
            return enum_type[value]
        except KeyError:
            pass
    return enum_type(value)


def _coerce_int(value: _ty.Any) -> int:
    if isinstance(value, bool):
        return int(value)
    return int(value)


def _coerce_chaddr(value: _ty.Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if not isinstance(value, str):
        raise TypeError("chaddr must be text or bytes-like")
    return bytes.fromhex(_strip_hex_text(value))


def _decode_option_value(
    code: int, value: bytearray, codemap: type[BaseDhcpOptionCode]
) -> _ty.Any:
    try:
        option_code = codemap.from_code(code)
    except Exception:
        return _type.Bytes(value).__json__()
    option_type = option_code.get_type()
    decoded = option_type._dhcp_decode(value)
    return _enum_name(
        decoded.__json__() if isinstance(decoded, _type.DhcpOptionType) else decoded
    )


def _coerce_option_value(
    option_type: type[_type.DhcpOptionType],
    value: _ty.Any,
) -> _ty.Any:
    if isinstance(value, str) and issubclass(option_type, _enum_base.Enum):
        return _coerce_enum_value(option_type, value)
    return value


def _coerce_option_code(raw_code: _ty.Any, codemap: type[BaseDhcpOptionCode]) -> int:
    if isinstance(raw_code, int):
        return raw_code
    if isinstance(raw_code, str):
        if raw_code.isdigit():
            return int(raw_code)
        try:
            return int(codemap[raw_code])  # type: ignore[index]
        except Exception:
            pass
    return int(raw_code)


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
class DhcpMessage:
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

    def to_mapping(self) -> dict[str, _ty.Any]:
        options: dict[str, _ty.Any] = {}
        for code, value in self.options._options.items():
            try:
                code_obj = self.options._codemap.from_code(code)
                # The numeric code when there is no name. `label()` answers
                # "UNKNOWN" for every unnamed code, so two of them collided on
                # one key and the document then failed to load on int("UNKNOWN").
                key = (
                    code_obj.label()
                    if getattr(code_obj, "_name_", None) is not None
                    else str(int(code))
                )
                option_type = code_obj.get_type()
                decoded = option_type._dhcp_decode(value)
                option_value = _enum_name(
                    decoded.__json__()
                    if isinstance(decoded, _type.DhcpOptionType)
                    else decoded
                )
                if not self._survives_round_trip(code, option_value, value):
                    # The readable form would come back as different octets --
                    # text holding a byte that is not valid UTF-8, a payload the
                    # codec normalizes, a length the codec does not preserve.
                    # Better an opaque value that reloads exactly than a pretty
                    # one that silently does not.
                    option_value = {self.HEX_VALUE_KEY: bytes(value).hex()}
            except Exception:
                # Also the self-describing form, not a bare hex string: a bare
                # one is ambiguous for a numeric option. A 2-octet
                # IP_ADDRESS_LEASE_TIME was emitted as "1234" and read back as
                # the decimal 1234, so the reloaded packet carried 000004d2 --
                # different octets, no error.
                key = str(code)
                option_value = {self.HEX_VALUE_KEY: bytes(value).hex()}
            options[key] = option_value

        return {
            "op": self.op.name,
            # label(), not .name: an unnamed hardware type has no .name at all,
            # so a mapping would carry a null where a string is expected and
            # from_mapping() could not read it back.
            "htype": self.htype.label(),
            "hlen": self.hlen,
            "hops": self.hops,
            "xid": self.xid,
            "secs": int(self.secs.total_seconds()),
            "flags": self.flags.name,
            "ciaddr": str(self.ciaddr),
            "yiaddr": str(self.yiaddr),
            "siaddr": str(self.siaddr),
            "giaddr": str(self.giaddr),
            "chaddr": self.chaddr.hex(":").upper(),
            # Display form: a mapping is written out as JSON/YAML/TOML/INI, and
            # a preserved octet cannot be encoded by a strict serializer.
            "sname": _nvt.display(self.sname),
            "file": _nvt.display(self.file),
            "options": options,
        }

    def _survives_round_trip(
        self, code: int, option_value: _ty.Any, original: _ty.Any
    ) -> bool:
        """Whether loading `option_value` back yields the original octets.

        Goes through a `DhcpOptions` keyed by the *real* code and the same
        codemap, because that is the path `from_mapping` takes. Probing under a
        different code silently measures a different codec -- code 0 is `PAD`,
        which is unregistered and falls back to `Bytes`, so everything looked
        lossy and every option came out as hex.
        """
        try:
            option_type = self.options._codemap.from_code(code).get_type()
            probe = DhcpOptions(codemap=self.options._codemap)
            probe[code] = _coerce_option_value(option_type, option_value)
            return bytes(probe.get(code, decode=False) or b"") == bytes(original)
        except Exception:
            return False

    @classmethod
    def from_mapping(cls, data: _ty.Mapping[str, _ty.Any]) -> "DhcpMessage":
        options = DhcpOptions()
        raw_options = data.get("options", {})
        if not isinstance(raw_options, _ty.Mapping):
            raise TypeError("options must be a mapping")

        for raw_code, raw_value in raw_options.items():
            code = _coerce_option_code(raw_code, options._codemap)
            if isinstance(raw_value, _ty.Mapping) and set(raw_value) == {
                cls.HEX_VALUE_KEY
            }:
                options[code] = bytearray.fromhex(
                    _strip_hex_text(str(raw_value[cls.HEX_VALUE_KEY]))
                )
                continue
            try:
                code_obj = options._codemap.from_code(code)
                option_type = code_obj.get_type()
                value = _coerce_option_value(option_type, raw_value)
                options[code] = value
            except Exception:
                if isinstance(raw_value, str):
                    raw_bytes = bytearray.fromhex(_strip_hex_text(raw_value))
                elif isinstance(raw_value, (bytes, bytearray, memoryview)):
                    raw_bytes = bytearray(raw_value)
                else:
                    raise TypeError(
                        f"Unsupported value for unknown option {raw_code!r}"
                    ) from None
                options[code] = raw_bytes

        return cls(
            op=_coerce_enum_value(_enum.OpCode, data["op"]),
            htype=_coerce_enum_value(_enum.HardwareAddressType, data["htype"]),
            hlen=_coerce_int(data["hlen"]),
            hops=_coerce_int(data["hops"]),
            xid=_coerce_int(data["xid"]),
            secs=_dt.timedelta(seconds=_coerce_int(data["secs"])),
            flags=_coerce_enum_value(_enum.Flags, data["flags"]),
            ciaddr=_net.IPv4(data["ciaddr"]),
            yiaddr=_net.IPv4(data["yiaddr"]),
            siaddr=_net.IPv4(data["siaddr"]),
            giaddr=_net.IPv4(data["giaddr"]),
            chaddr=_coerce_chaddr(data["chaddr"]),
            sname=str(data["sname"]),
            file=str(data["file"]),
            options=options,
        )

    @classmethod
    def decode(cls, data: _ty.Union[bytes, bytearray, memoryview]) -> "DhcpMessage":
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

        sname_str: str = ""
        if sname_raw is not None:
            sname_str = _decode_bootp_field(sname_raw, "sname")
        else:
            tftp_val = options.get(
                DhcpOptionCode.TFTP_SERVER, default="", decode=_type.String
            )
            if tftp_val is not None:
                sname_str = str(tftp_val)

        file_str: str = ""
        if file_raw is not None:
            file_str = _decode_bootp_field(file_raw, "file")
        else:
            bootfile_val = options.get(
                DhcpOptionCode.BOOTFILE_NAME, default="", decode=_type.String
            )
            if bootfile_val is not None:
                file_str = str(bootfile_val)

        # opts -> file -> sname

        return DhcpMessage(
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

    def encode(
        self, max_packetsize: int = _const.DHCP_MIN_LEGAL_PACKET_SIZE
    ) -> bytearray:
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
        max_options_field_size = max_packetsize - _ENCODE_FIXED_OVERHEAD

        options = self.options.copy()
        # Whether THIS encode overloads is decided below, so drop any marker the
        # message is carrying. A decoded packet keeps its sender's OPTION_OVERLOAD,
        # and re-encoding it (a relay forwarding a PXE reply, say) would otherwise
        # tell the receiver to parse sname/file as options while they hold the
        # literal server name and boot file that decode moved out of them.
        if int(DhcpOptionCode.OPTION_OVERLOAD) in options:
            del options[int(DhcpOptionCode.OPTION_OVERLOAD)]
        sname_bytes: _ty.Union[bytes, bytearray] = _nvt.encode(self.sname)
        file_bytes: _ty.Union[bytes, bytearray] = _nvt.encode(self.file)
        options_field: _ty.Union[bytes, bytearray] = options.encode()
        if len(options_field) > max_options_field_size + 128 + 64:
            raise OverflowError("DHCP options exceed maximum packet size")
        elif len(options_field) > max_options_field_size + 128:
            if self.file and DhcpOptionCode.BOOTFILE_NAME not in options:
                options[DhcpOptionCode.BOOTFILE_NAME] = self.file
                options._options.move_to_end(int(DhcpOptionCode.BOOTFILE_NAME), False)
            if self.sname and DhcpOptionCode.TFTP_SERVER not in options:
                options[DhcpOptionCode.TFTP_SERVER] = self.sname
                options._options.move_to_end(int(DhcpOptionCode.TFTP_SERVER), False)
            overload = _type.OptionOverload.BOTH
        elif len(options_field) > max_options_field_size + 64:
            if self.file and DhcpOptionCode.BOOTFILE_NAME not in options:
                options[DhcpOptionCode.BOOTFILE_NAME] = self.file
                options._options.move_to_end(int(DhcpOptionCode.BOOTFILE_NAME), False)
            overload = _type.OptionOverload.FILE
        elif len(options_field) > max_options_field_size:
            if self.sname and DhcpOptionCode.TFTP_SERVER not in options:
                options[DhcpOptionCode.TFTP_SERVER] = self.sname
                options._options.move_to_end(int(DhcpOptionCode.TFTP_SERVER), False)
            overload = _type.OptionOverload.SNAME
        else:
            overload = _type.OptionOverload.NONE

        if overload is not _type.OptionOverload.NONE:
            options._options[int(DhcpOptionCode.OPTION_OVERLOAD)] = bytearray(
                [overload.value]
            )
            options._options.move_to_end(int(DhcpOptionCode.OPTION_OVERLOAD), False)

        # DHCP_MESSAGE_TYPE leads the options field on BOTH paths. RFC 2131 s3
        # walks the protocol by message type, and implementations do read option
        # 53 before parsing the rest -- it is what tells a receiver whether the
        # packet is even for it. This move was already here, and led on neither
        # path: the non-overload path kept the `options.encode()` taken above
        # for sizing, which predates the move, while the overload path then put
        # OPTION_OVERLOAD in front of it (measured 2026-09-20: code 52 was the
        # first TLV after the cookie). Hence both the placement after the
        # overload marker and the re-encode below -- two encodes of the same
        # message used to disagree on the wire depending on whether it happened
        # to overload.
        try:
            options._options.move_to_end(int(DhcpOptionCode.DHCP_MESSAGE_TYPE), False)
        except KeyError:
            pass

        if overload is not _type.OptionOverload.NONE:
            options_field, leftover = options.partial_encode(max_options_field_size)

            if (
                bool(overload.value & _type.OptionOverload.FILE.value)
                and leftover is not None
            ):
                file_bytes, leftover = leftover.partial_encode(128)
            if (
                bool(overload.value & _type.OptionOverload.SNAME.value)
                and leftover is not None
            ):
                sname_bytes, leftover = leftover.partial_encode(64)

            # Nothing may be left once every field has been packed: silently
            # dropping options produces a reply the client accepts and acts on
            # while missing (possibly) its server identifier or routes.
            if leftover is not None:
                raise OverflowError(
                    "DHCP options exceed maximum packet size: "
                    f"{len(leftover)} option(s) did not fit"
                )
        else:
            # The encode above measured the size; this one carries the order.
            options_field = options.encode()

        # Validate what is actually packed, not what the caller set: encode()
        # legitimately *moves* a long sname/file out into options 66 and 67 when
        # it overloads, and `sname_bytes`/`file_bytes` are then the option
        # fragments `partial_encode` produced, already bounded by the field
        # width it was given.
        _check_bootp_field("sname", sname_bytes, _SNAME_FIELD_SIZE)
        _check_bootp_field("file", file_bytes, _FILE_FIELD_SIZE)
        _check_bootp_field("chaddr", self.chaddr, _CHADDR_FIELD_SIZE)

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
            self.flags.value,
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
        return data

    def client_id(
        self, func: _ty.Optional[_ty.Callable[["DhcpMessage"], bytearray]] = None
    ) -> str:
        """Stable identity for this client, used to key leases.

        Option 61 when present, else the hardware type and address. Raises
        `NoClientIdentity` when the message carries neither: `hlen` may legally
        be 0 (RFC 4390 requires exactly that for IPoIB, which supplies option 61
        instead), and the old fallback then produced the hardware-type octet
        alone -- one identifier, `"01"`, shared by every such client. Two of them
        would take over each other's lease, and a RELEASE from either would free
        both.
        """
        cid = self.options.get(DhcpOptionCode.CLIENT_IDENTIFIER, decode=False)
        if not cid:
            if func:
                cid = func(self)
            if not cid:
                if not self.chaddr:
                    raise NoClientIdentity(
                        "message has neither a client identifier (option 61) nor "
                        f"a hardware address (hlen=0, htype={self.htype.label()})"
                    )
                cid = bytearray([self.htype.value])
                cid.extend(self.chaddr)
        return cid.hex(":").upper()

    def dumps(self, codemap: _ty.Optional[type[BaseDhcpOptionCode]] = None) -> str:
        lines = []
        for name, value in [
            ("OP", self.op.name),
            ("Time Since Boot", str(self.secs)),
            ("Hops", str(self.hops)),
            ("Transaction ID", str(self.xid)),
            ("Flags", self.flags.name),
            ("Client Current Address", str(self.ciaddr)),
            ("Allocated Address", str(self.yiaddr)),
            ("Gateway Address", str(self.giaddr)),
            ("Hardware Address", f"{self.htype.name}({self.htype.dumps(self.chaddr)})"),
            ("Next Server (siaddr)", str(self.siaddr)),
            ("Server Host Name", _nvt.display(self.sname)),
            ("Bootfile", _nvt.display(self.file)),
        ]:
            lines.append(f"{name: <40}: {value}")
        lines.append(f"OPTIONS:")
        _codemap = codemap or self.options._codemap
        for _code, _raw in self.options._options.items():
            # Render per option, never as a batch: an unregistered code (93 of 254 are
            # not enum members) or one malformed payload must not cost the whole dump.
            # Same fallback `to_mapping` uses.
            try:
                code = _codemap.from_code(_code)
                opt_val: _ty.Any = code.get_type()._dhcp_decode(_raw)
            except Exception:
                code = _code  # type: ignore[assignment]
                opt_val = _type.Bytes(_raw)
            if isinstance(opt_val, list):
                decoded_str = "\n".join([repr(i) for i in opt_val])
            else:
                decoded_str = repr(opt_val)
            decoded_lines = decoded_str.splitlines()
            SPACE = " " * 42
            if decoded_lines:
                first = _tw.fill(
                    decoded_lines[0],
                    width=100,
                    initial_indent="",
                    subsequent_indent=SPACE,
                )
            else:
                first = ""
            lines.append(f"  {repr(code): <38}: {first}")
            for line in decoded_lines[1:]:
                lines.append(
                    _tw.fill(
                        line, width=100, initial_indent=SPACE, subsequent_indent=SPACE
                    )
                )

        return "\n".join(lines)

    def log_str(self, src: _ty.Any, dst: _ty.Any) -> str:
        return (
            f"{self.op.name} XID={self.xid:08X} Src: {src} Dst: {dst}\n"
            f"{self.dumps()}"
        )

    def __contains__(self, __key: object) -> bool:
        return self.options.__contains__(__key)

    def log(self, src: _ty.Any, dst: _ty.Any, level: int) -> None:
        """Log the packet at `level`.

        Never raises and never does work the level does not call for: callers on the
        receive and send paths invoke this before handling or sending, so a failure
        here would silently cost a packet its handler or its reply.
        """
        if not LOGGER.isEnabledFor(level):
            return
        try:
            header = (
                f"{'#' * 10} {self.op.name} XID={self.xid:08X} "
                f"Src: {src} Dst: {dst} {'#' * 10}"
            )
            LOGGER.log(level, f"\n{header}\n{self.dumps()}\n{'#' * len(header)}")
        except Exception:  # pragma: no cover - defensive, dumps() is already tolerant
            LOGGER.log(level, "Could not format packet for logging", exc_info=True)
