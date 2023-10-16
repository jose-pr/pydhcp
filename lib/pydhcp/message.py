from .options import DhcpOptions, StringDhcpOptionType
from .iana import (
    OpCode,
    HardwareAddressType,
    Flags,
    MAGIC_COOKIE,
    DhcpOptionCode,
    OptionOverload,
)
from .netutils import IPAddress

import enum as _enum
import struct as _struct
import typing as _ty
import dataclasses as _data


_NULL = 0x00.to_bytes(1)


def _codemap(code, value: bytearray):
    ty = DhcpOptionCode.get_type(code)
    value = ty.decode(value)
    try:
        name = DhcpOptionCode(code).name
    except:
        name = "UNKNOWN"
    return (f"[{int(code):0>3}]{name:<40}", value)


@_data.dataclass
class DhcpMessage:
    op: OpCode  # One byte
    """Message op code / message type"""
    htype: HardwareAddressType
    """Hardware address type, see ARP section in "Assigned Numbers" RFC"""
    hlen: int  # One byte
    """Hardware address length"""
    hops: int  # One byte
    """Client sets to zero, optionally used by relay agents when booting via a relay agent."""
    xid: int  # 4 bytes
    """Transaction ID, a random number chosen by the
    client, used by the client and server to associate
    messages and responses between a client and a server."""
    secs: int  # 2 bytes
    """Filled in by client, seconds elapsed since client
    began address acquisition or renewal process."""
    flags: Flags  # 2 bytes
    """Only use for the BROADCAST flag in clients"""
    ciaddr: IPAddress
    """Client IP address; only filled in if client is in
    BOUND, RENEW or REBINDING state and can respond
    to ARP requests."""
    yiaddr: IPAddress
    """'your' (client) IP address."""
    siaddr: IPAddress
    """IP address of next server to use in bootstrap;
    returned in DHCPOFFER, DHCPACK by server."""
    giaddr: IPAddress
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

    @classmethod
    def decode(cls, data: memoryview):
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
        op = OpCode(op)
        try:
            htype = HardwareAddressType(htype)
        except:
            pass
        flags = Flags(flags)
        ciaddr = IPAddress(ciaddr)
        yiaddr = IPAddress(yiaddr)
        siaddr = IPAddress(siaddr)
        giaddr = IPAddress(giaddr)
        chaddr = data[28 : 28 + hlen].tobytes()
        sname = data[44:108]
        file = data[108:236]

        if MAGIC_COOKIE != data[236:240]:
            raise Exception("Bad Magic Cookie")

        options = DhcpOptions()
        if options.decode(data[240:])[0] != 255:
            raise Exception("Bad Options end")

        overload = options.get(DhcpOptionCode.OPTION_OVERLOAD, decode=False)
        overload = OptionOverload(overload[0] if overload else 0)

        # rfc3396 order
        if OptionOverload.FILE in overload:
            options.decode(file)
            file = None

        if OptionOverload.SNAME in overload:
            options.decode(sname)
            sname = None

        if sname is not None:
            sname = sname.tobytes().split(_NULL, 1)[0].decode()
        else:
            sname = str(
                options.get(DhcpOptionCode.TFTP_SERVER, decode=StringDhcpOptionType)
                or ""
            )

        if file is not None:
            file = file.tobytes().split(_NULL, 1)[0].decode()
        else:
            file = str(
                options.get(DhcpOptionCode.BOOTFILE_NAME, decode=StringDhcpOptionType)
                or ""
            )

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
            sname,
            file,
            options,
        )

    def encode(self, maxsize: int = 576):
        maxsize = maxsize or 576
        data = bytearray(12)
        sname = self.sname.encode()
        file = self.file.encode()
        _struct.pack_into(
            "!BBBBIHH",
            data,
            0,
            self.op.value,
            int(self.htype),
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags.value
        )
        for ip in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr]:
            data.extend(ip.packed)

        data.extend(self.chaddr.ljust(16, b'\x00')[:16])
        data.extend(sname.ljust(64, b"\x00")[:64])
        data.extend(file.ljust(128, b"\x00")[:128])
        data.extend(MAGIC_COOKIE)
        data.extend(self.options.encode())
        #
        # TODO overload sname/file
        return data

    def client_id(self, func: _ty.Callable[["DhcpMessage"], bytearray] = None):
        cid = self.options.get(DhcpOptionCode.CLIENT_IDENTIFIER, decode=False)
        if not cid:
            if func:
                cid = func(self)
            if not cid:
                cid = bytearray([self.htype.value])
                cid.extend(self.chaddr)
        return cid.hex(":").upper()

    def dumps(self, codemap: _ty.Callable[[int, bytearray], tuple[str, str]] = None):
        lines = []
        lines.append(f"OP: {self.op.name}")
        lines.append(f"Hardware Type: {self.htype.name}")
        lines.append(f"Hops: {self.hops}")
        lines.append(f"Transaction ID: {self.xid}")
        lines.append(f"Flags: {self.flags.name}")
        lines.append(f"Client Current Address: {self.ciaddr}")
        lines.append(f"Allocated Address: {self.yiaddr}")
        lines.append(f"Gateway Address: {self.giaddr}")
        lines.append(f"Hardware Address: {self.htype.dumps(self.chaddr)}")
        lines.append(f"Server Address: {self.siaddr}")
        lines.append(f"Server Hostname: {self.sname}")
        lines.append(f"Bootfile: {self.file}")
        lines.append(f"OPTIONS:")
        codemap = codemap or _codemap
        for code, value in self.options.items():
            code, value = codemap(code, value)
            lines.append(f"{code}: {value}")
        return "\n".join(lines)

    def __contains__(self, __key: object) -> bool:
        return self.options.__contains__(__key)
