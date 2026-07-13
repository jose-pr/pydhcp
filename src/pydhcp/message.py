from .options import DhcpOptions, BaseDhcpOptionCode
from . import optiontype as _type, netutils as _net, enum as _enum, constants as _const
from .log import LOGGER
import struct as _struct
import enum as _enum_base
import typing as _ty
import dataclasses as _data
import datetime as _dt
import textwrap as _tw

_NULL = 0x00.to_bytes(1, "big")
_FIXED_HEADER_SIZE = 236
_MAGIC_COOKIE_END = 240


def _strip_hex_text(value: str) -> str:
    return "".join(ch for ch in value if ch not in " \t\r\n:")


def _enum_name(value: _ty.Any) -> _ty.Any:
    if isinstance(value, _enum_base.Enum):
        return value.name
    return value


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


def _decode_option_value(code: int, value: bytearray, codemap: type[BaseDhcpOptionCode]) -> _ty.Any:
    try:
        option_code = codemap.from_code(code)
    except Exception:
        return _type.Bytes(value).__json__()
    option_type = option_code.get_type()
    decoded = option_type._dhcp_decode(value)
    return _enum_name(decoded.__json__() if isinstance(decoded, _type.DhcpOptionType) else decoded)


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
            return int(codemap[raw_code])
        except Exception:
            pass
    return int(raw_code)


@_data.dataclass
class DhcpMessage:
    MIN_LEGAL_SIZE = _const.DHCP_MIN_LEGAL_PACKET_SIZE - _const.UDP_MIN_PACKET_SIZE
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

    def to_mapping(self) -> dict[str, _ty.Any]:
        options: dict[str, _ty.Any] = {}
        for code, value in self.options._options.items():
            try:
                code_obj = self.options._codemap.from_code(code)
                key = code_obj.name
                option_type = code_obj.get_type()
                decoded = option_type._dhcp_decode(value)
                option_value = decoded.__json__() if isinstance(decoded, _type.DhcpOptionType) else decoded
            except Exception:
                key = str(code)
                option_value = _type.Bytes(value).__json__()
            options[key] = _enum_name(option_value)

        return {
            "op": self.op.name,
            "htype": self.htype.name,
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
            "sname": self.sname,
            "file": self.file,
            "options": options,
        }

    @classmethod
    def from_mapping(cls, data: _ty.Mapping[str, _ty.Any]) -> "DhcpMessage":
        options = DhcpOptions()
        raw_options = data.get("options", {})
        if not isinstance(raw_options, _ty.Mapping):
            raise TypeError("options must be a mapping")

        for raw_code, raw_value in raw_options.items():
            code = _coerce_option_code(raw_code, options._codemap)
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
                    raise TypeError(f"Unsupported value for unknown option {raw_code!r}") from None
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
        ) = _struct.unpack_from("!BBBBIHHIIII", data, 0)
        if hlen > 16:
            raise ValueError(f"Hardware address length {hlen} exceeds maximum of 16")
        op = _enum.OpCode(op)
        try:
            htype = _enum.HardwareAddressType(htype)
        except ValueError:
            LOGGER.warning(f"Unknown hardware type {htype}, using ETHERNET")
            htype = _enum.HardwareAddressType.ETHERNET
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
            raise ValueError(f"Bad options terminator: expected 255 (END), got {remaining_opts[0]}")

        overload = options.get(
            _enum.DhcpOptionCode.OPTION_OVERLOAD,
            default=_type.OptionOverload.NONE,
            decode=_type.OptionOverload,
        )

        # rfc3396 order
        if overload is not None and bool(overload.value & _type.OptionOverload.FILE.value):
            options.decode(file_data, base_offset=108)
            file_raw: _ty.Optional[memoryview] = None
        else:
            file_raw = file_data

        if overload is not None and bool(overload.value & _type.OptionOverload.SNAME.value):
            options.decode(sname_data, base_offset=44)
            sname_raw: _ty.Optional[memoryview] = None
        else:
            sname_raw = sname_data

        sname_str: str = ""
        if sname_raw is not None:
            sname_str = sname_raw.tobytes().split(_NULL, 1)[0].decode()
        else:
            tftp_val = options.get(
                _enum.DhcpOptionCode.TFTP_SERVER, default="", decode=_type.String
            )
            if tftp_val is not None:
                sname_str = str(tftp_val)

        file_str: str = ""
        if file_raw is not None:
            file_str = file_raw.tobytes().split(_NULL, 1)[0].decode()
        else:
            bootfile_val = options.get(
                _enum.DhcpOptionCode.BOOTFILE_NAME, default="", decode=_type.String
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

    def encode(self, max_packetsize: int = _const.DHCP_MIN_LEGAL_PACKET_SIZE) -> bytearray:
        max_packetsize = int(max_packetsize or _const.DHCP_MIN_LEGAL_PACKET_SIZE)
        max_options_field_size = max_packetsize - 264 - len(self.MAGIC_COOKIE)
        if max_options_field_size < 0:
            raise ValueError(f"{max_packetsize} is too small for a DHCP packet")

        options = DhcpOptions(self.options._codemap)
        options._options = _ty.OrderedDict(
            (code, bytearray(value)) for code, value in self.options._options.items()
        )
        sname_bytes: _ty.Union[bytes, bytearray] = self.sname.encode()
        file_bytes: _ty.Union[bytes, bytearray] = self.file.encode()
        options_field: _ty.Union[bytes, bytearray] = options.encode()
        if len(options_field) > max_options_field_size + 128 + 64:
            raise OverflowError("DHCP options exceed maximum packet size")
        elif len(options_field) > max_options_field_size + 128:
            if self.file and _enum.DhcpOptionCode.BOOTFILE_NAME not in options:
                options[_enum.DhcpOptionCode.BOOTFILE_NAME] = self.file
                options._options.move_to_end(
                    int(_enum.DhcpOptionCode.BOOTFILE_NAME), False
                )
            if self.sname and _enum.DhcpOptionCode.TFTP_SERVER not in options:
                options[_enum.DhcpOptionCode.TFTP_SERVER] = self.sname
                options._options.move_to_end(
                    int(_enum.DhcpOptionCode.TFTP_SERVER), False
                )
            overload = _type.OptionOverload.BOTH
        elif len(options_field) > max_options_field_size + 64:
            if self.file and _enum.DhcpOptionCode.BOOTFILE_NAME not in options:
                options[_enum.DhcpOptionCode.BOOTFILE_NAME] = self.file
                options._options.move_to_end(
                    int(_enum.DhcpOptionCode.BOOTFILE_NAME), False
                )
            overload = _type.OptionOverload.FILE
        elif len(options_field) > max_options_field_size:
            if self.sname and _enum.DhcpOptionCode.TFTP_SERVER not in options:
                options[_enum.DhcpOptionCode.TFTP_SERVER] = self.sname
                options._options.move_to_end(
                    int(_enum.DhcpOptionCode.TFTP_SERVER), False
                )
            overload = _type.OptionOverload.SNAME
        else:
            overload = _type.OptionOverload.NONE

        try:
            options._options.move_to_end(
                int(_enum.DhcpOptionCode.DHCP_MESSAGE_TYPE), False
            )
        except KeyError:
            pass

        if overload is not _type.OptionOverload.NONE:
            options._options[
                int(_enum.DhcpOptionCode.OPTION_OVERLOAD)
            ] = bytearray([overload.value])
            options._options.move_to_end(
                int(_enum.DhcpOptionCode.OPTION_OVERLOAD), False
            )
            options_field, leftover = options.partial_encode(max_options_field_size)

            if bool(overload.value & _type.OptionOverload.FILE.value) and leftover is not None:
                file_bytes, leftover = leftover.partial_encode(128)
            if bool(overload.value & _type.OptionOverload.SNAME.value) and leftover is not None:
                sname_bytes, leftover = leftover.partial_encode(64)

        data = bytearray(28)
        _struct.pack_into(
            "!BBBBIHHIIII",
            data,
            0,
            self.op.value,
            int(self.htype),
            self.hlen,
            self.hops,
            self.xid,
            min(0xFFFF, max(0, int(self.secs.total_seconds()))),
            self.flags.value,
            int(self.ciaddr),
            int(self.yiaddr),
            int(self.siaddr),
            int(self.giaddr),
        )
        data.extend(self.chaddr.ljust(16, b"\x00")[:16])
        data.extend(sname_bytes.ljust(64, b"\x00")[:64])
        data.extend(file_bytes.ljust(128, b"\x00")[:128])
        data.extend(self.MAGIC_COOKIE)
        data.extend(options_field)
        return data

    def client_id(self, func: _ty.Optional[_ty.Callable[["DhcpMessage"], bytearray]] = None) -> str:
        cid = self.options.get(_enum.DhcpOptionCode.CLIENT_IDENTIFIER, decode=False)
        if not cid:
            if func:
                cid = func(self)
            if not cid:
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
            ("Server Address", str(self.siaddr)),
            ("Next Server", str(self.siaddr)),
            ("Server Host Name", self.sname),
            ("Bootfile", self.file),
        ]:
            lines.append(f"{name: <40}: {value}")
        lines.append(f"OPTIONS:")
        for code, opt_val in self.options.items(decoded=codemap or True):
            if isinstance(opt_val, list):
                decoded_str = "\n".join([repr(i) for i in opt_val])
            else:
                decoded_str = repr(opt_val)
            decoded_lines = decoded_str.splitlines()
            SPACE = " " * 42
            if decoded_lines:
                first = _tw.fill(
                    decoded_lines[0], width=100, initial_indent="", subsequent_indent=SPACE
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
        header = f"{'#' * 10} {self.op.name} XID={self.xid:08X} Src: {src} Dst: {dst} {'#' * 10}"
        LOGGER.log(level, f"\n{header}\n{self.dumps()}\n{'#' * len(header)}")
