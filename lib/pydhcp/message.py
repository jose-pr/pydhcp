from .options import DhcpOptions, DhcpOptionCodeMap
from . import optiontype
from .iana import (
    OpCode,
    HardwareAddressType,
    Flags,
    MAGIC_COOKIE,
    DhcpOptionCode,
    OptionOverload,
    DHCP_MIN_LEGAL_PACKET_SIZE,
)
from .netutils import IPAddress
from .log import LOGGER

import enum as _enum
import struct as _struct
import typing as _ty
import dataclasses as _data
import datetime as _dt
import textwrap as _tw

_NULL = 0x00.to_bytes(1)

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
    secs: _dt.timedelta  # 2 bytes
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
        if not isinstance(data, memoryview):
            data = memoryview(data)
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
        secs = _dt.timedelta(seconds=secs)
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
                options.get(DhcpOptionCode.TFTP_SERVER, decode=optiontype.String)
                or ""
            )

        if file is not None:
            file = file.tobytes().split(_NULL, 1)[0].decode()
        else:
            file = str(
                options.get(DhcpOptionCode.BOOTFILE_NAME, decode=optiontype.String)
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

    def encode(self, max_packetsize: int = DHCP_MIN_LEGAL_PACKET_SIZE):
        max_packetsize = int(max_packetsize or DHCP_MIN_LEGAL_PACKET_SIZE)
        max_options_field_size = max_packetsize - 264 - len(MAGIC_COOKIE)
        if max_options_field_size < 0:
            raise Exception(f"{max_packetsize} is to small for a DHCP packet")

        sname = self.sname.encode()
        file = self.file.encode()
        options_field = self.options.encode()
        if len(options_field) > max_options_field_size + 128:
            if self.file and DhcpOptionCode.BOOTFILE_NAME not in self.options:
                self.options[DhcpOptionCode.BOOTFILE_NAME] = optiontype.String(self.file)
                
                self.options._options.move_to_end(
                    int(DhcpOptionCode.BOOTFILE_NAME), False
                )
            if self.sname and DhcpOptionCode.TFTP_SERVER not in self.options:
                self.options[DhcpOptionCode.TFTP_SERVER] = optiontype.String(self.sname)
                
                self.options._options.move_to_end(
                    int(DhcpOptionCode.TFTP_SERVER), False
                )
            overload = OptionOverload.BOTH
        elif len(options_field) > max_options_field_size:
            if self.file:
                self.options[DhcpOptionCode.BOOTFILE_NAME] = optiontype.String(
                    self.file
                )
                self.options._options.move_to_end(
                    int(DhcpOptionCode.BOOTFILE_NAME), False
                )
            overload = OptionOverload.FILE
        else:
            overload = OptionOverload.NONE

        try:
            self.options._options.move_to_end(DhcpOptionCode.DHCP_MESSAGE_TYPE, False)
        except KeyError:
            pass


        if overload is not OptionOverload.NONE:
            self.options._options[DhcpOptionCode.OPTION_OVERLOAD] = bytearray(
                [overload.value]
            )
            self.options._options.move_to_end(DhcpOptionCode.OPTION_OVERLOAD, False)
            options_field, options = self.options.partial_encode(max_options_field_size)

            if OptionOverload.FILE in overload:
                file, options = options.partial_encode(128)
            if OptionOverload.SNAME in overload:
                sname, options = self.options.partial_encode(64)

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
            self.secs.seconds,
            self.flags.value,
            int(self.ciaddr),
            int(self.yiaddr),
            int(self.siaddr),
            int(self.giaddr),
        )
        data.extend(self.chaddr.ljust(16, b"\x00")[:16])
        data.extend(sname.ljust(64, b"\x00")[:64])
        data.extend(file.ljust(128, b"\x00")[:128])
        data.extend(MAGIC_COOKIE)
        data.extend(options_field)
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

    def dumps(self, codemap: type[DhcpOptionCodeMap] = None):
        lines = []
        for name, value in [
            ('OP', self.op.name),
            ('Time Since Boot', self.secs),
            ('Hops', self.hops),
            ('Transaction ID', self.xid),
            ('Flags',self.flags.name),
            ('Client Current Address', self.ciaddr),
            ('Allocated Address', self.yiaddr),
            ('Gateway Address',self.giaddr),
            ('Hardware Address',f"{self.htype.name}({self.htype.dumps(self.chaddr)})"),
            ('Server Address',self.siaddr),
            ('Bootfile',self.file),
        ]:
            lines.append(f"{name: <40}: {value}")
        lines.append(f"OPTIONS:")
        for code, value in self.options.items(decoded=codemap or True):
            if isinstance(value, optiontype.List):
                decoded = '\n'.join([str(i) for i in value])
            else:
                decoded = repr(value)
            decoded = decoded.splitlines()
            SPACE = ' '*42
            if decoded:
                first =_tw.fill(decoded[0], width=100, initial_indent='', subsequent_indent=SPACE)
            else:
                first = ''
            lines.append(f"  {repr(code): <38}: {first}")
            for line in decoded[1:]:
                lines.append(_tw.fill(line, width=100, initial_indent=SPACE, subsequent_indent=SPACE))

        return "\n".join(lines)
    
    def log(self, src, dst, level):
        header = f"{"#" * 10} {self.op.name} Src: {src} Dst: {dst} {"#" * 10}"
        LOGGER.log(level, f"\n{header}\n{self.dumps()}\n{"#" * len(header)}")

    
    def __contains__(self, __key: object):
        return self.options.__contains__(__key)
