"""Option 175, iPXE's encapsulated options: the sub-option names and the container.

The sub-option numbers and layouts are iPXE's, from `src/include/ipxe/dhcp.h` (the
`DHCP_EB_*` options) and `src/include/ipxe/features.h` (the `DHCP_EB_FEATURE_*`
flags) in https://github.com/ipxe/ipxe. iPXE sends option 175 in every request,
so its presence is how a server tells iPXE from a PXE ROM.
"""

from __future__ import annotations

import typing as _ty

from ..exceptions import DHCPValueError
from ._codecs._base import OptionCodec, _Record, _set
from ._codecs._scalar import I8, U8, Bytes, String, _octets
from ._codecs._vendor import EncapsulatedOptions, TLVOption
from ._codes import OptionCodeEnum

__all__ = ["IPXEBusID", "IPXEOption", "IPXEOptions", "IPXEVersion"]


class IPXEOption(OptionCodeEnum):
    """The sub-options of option 175, named as iPXE's `DHCP_EB_*` constants are."""

    PRIORITY = 0x01
    KEEP_SAN = 0x08
    SKIP_SAN_BOOT = 0x09
    # The features this build of iPXE has, each sent as a one-octet 1.
    PXE_EXT = 0x10
    ISCSI = 0x11
    AOE = 0x12
    HTTP = 0x13
    HTTPS = 0x14
    TFTP = 0x15
    FTP = 0x16
    DNS = 0x17
    BZIMAGE = 0x18
    MULTIBOOT = 0x19
    SLAM = 0x1A
    SRP = 0x1B
    NBI = 0x20
    PXE = 0x21
    ELF = 0x22
    COMBOOT = 0x23
    EFI = 0x24
    FCOE = 0x25
    VLAN = 0x26
    MENU = 0x27
    SDI = 0x28
    NFS = 0x29
    SCRIPTLET = 0x51
    SYSLOGS_SERVER = 0x55
    TRUST = 0x5A
    CERT = 0x5B
    KEY = 0x5C
    CROSS_CERT = 0x5D
    NO_PXEDHCP = 0xB0
    BUS_ID = 0xB1
    USE_CACHED = 0xB2
    SAN_RETRY = 0xBB
    SAN_FILENAME = 0xBC
    SAN_DRIVE = 0xBD
    USERNAME = 0xBE
    PASSWORD = 0xBF
    REVERSE_USERNAME = 0xC0
    REVERSE_PASSWORD = 0xC1
    UID = 0xC2
    GID = 0xC3
    VERSION = 0xEB

    def is_feature(self) -> bool:
        """Whether this sub-option is one of iPXE's feature flags (0x10 to 0x29)."""
        return 0x10 <= int(self) <= 0x29


class IPXEBusID(_Record):
    """`BUS_ID`: the bus type octet, then what that bus identifies the NIC by.

    For PCI (type 1) that is the vendor and device, two big-endian octets each,
    which `vendor` and `device` read; any other bus is kept as its octets.
    """

    __slots__ = ("bus_type", "ident")
    _FIELDS = __slots__

    bus_type: int
    ident: Bytes

    PCI = 1

    def __init__(self, bus_type: int, ident: _ty.Any) -> None:
        _set(self, "bus_type", int(U8(bus_type)))
        _set(self, "ident", _octets(ident))

    @classmethod
    def pci(cls, vendor: int, device: int) -> "IPXEBusID":
        return cls(
            cls.PCI, int(vendor).to_bytes(2, "big") + int(device).to_bytes(2, "big")
        )

    @property
    def vendor(self) -> _ty.Optional[int]:
        """The PCI vendor ID, or None for another bus."""
        if self.bus_type != self.PCI or len(self.ident) != 4:
            return None
        return int.from_bytes(self.ident[:2], "big")

    @property
    def device(self) -> _ty.Optional[int]:
        """The PCI device ID, or None for another bus."""
        if self.bus_type != self.PCI or len(self.ident) != 4:
            return None
        return int.from_bytes(self.ident[2:], "big")

    @classmethod
    def unpack_from(cls, option: memoryview) -> "tuple[IPXEBusID, int]":
        if not option:
            raise DHCPValueError("IPXEBusID needs a bus type octet")
        return cls(option[0], bytes(option[1:])), len(option)

    def pack_into(self, data: bytearray) -> int:
        data.append(self.bus_type)
        data.extend(self.ident)
        return 1 + len(self.ident)

    def to_json(self) -> list[_ty.Any]:
        return [self.bus_type, self.ident.to_json()]

    def display_text(self) -> str:
        if self.vendor is not None:
            return f"PCI {self.vendor:04x}:{self.device:04x}"
        return f"bus {self.bus_type} {self.ident.hex()}"


class IPXEVersion(_Record):
    """`VERSION`: iPXE's major, minor and patch numbers, one octet each."""

    __slots__ = ("major", "minor", "patch")
    _FIELDS = __slots__

    major: int
    minor: int
    patch: int

    def __init__(self, major: _ty.Any, minor: _ty.Any = 0, patch: _ty.Any = 0) -> None:
        if isinstance(major, str):
            parts = major.split(".")
            if len(parts) != 3:
                raise DHCPValueError(
                    f"an iPXE version is major.minor.patch, not {major!r}"
                )
            major, minor, patch = parts
        _set(self, "major", int(U8(major)))
        _set(self, "minor", int(U8(minor)))
        _set(self, "patch", int(U8(patch)))

    @classmethod
    def fixed_size(cls) -> int:
        return 3

    @classmethod
    def unpack_from(cls, option: memoryview) -> "tuple[IPXEVersion, int]":
        return cls(option[0], option[1], option[2]), 3

    def pack_into(self, data: bytearray) -> int:
        data.extend((self.major, self.minor, self.patch))
        return 3

    def to_json(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def display_text(self) -> str:
        return self.to_json()


for _code in IPXEOption:
    if _code.is_feature() or _code in (
        IPXEOption.KEEP_SAN,
        IPXEOption.SKIP_SAN_BOOT,
        IPXEOption.NO_PXEDHCP,
        IPXEOption.USE_CACHED,
        IPXEOption.SAN_RETRY,
        IPXEOption.SAN_DRIVE,
    ):
        _code.register_type(U8)
IPXEOption.PRIORITY.register_type(I8)
IPXEOption.BUS_ID.register_type(IPXEBusID)
IPXEOption.VERSION.register_type(IPXEVersion)
for _code in (
    IPXEOption.SCRIPTLET,
    IPXEOption.SYSLOGS_SERVER,
    IPXEOption.SAN_FILENAME,
    IPXEOption.USERNAME,
    IPXEOption.PASSWORD,
    IPXEOption.REVERSE_USERNAME,
    IPXEOption.REVERSE_PASSWORD,
):
    _code.register_type(String)
# TRUST, CERT, KEY, CROSS_CERT, UID, GID and any unnamed code stay opaque Bytes.


class IPXEOptions(EncapsulatedOptions):
    """Option 175: iPXE's sub-options, kept as the octets they arrived as.

    `get` reads one by its `IPXEOption` codec; `to_json` writes `[name, value]`
    pairs a document can hold, and reading takes them back. A sub-option is built
    from `(code, value)` where the code is a number or a name `IPXEOption.resolve`
    reads and the value octets, a codec value, or what its codec's `from_json` takes.
    """

    @classmethod
    def _normalize(cls, item: _ty.Any) -> TLVOption:
        if isinstance(item, TLVOption):
            return item
        first, second = item
        code = IPXEOption.resolve(first)
        if isinstance(second, (bytes, bytearray, memoryview)):
            return TLVOption(int(code), second)
        if isinstance(second, dict) and set(second) == {"hex"}:
            return TLVOption(int(code), bytes.fromhex(str(second["hex"])))
        codec = code.get_type()
        value = second if isinstance(second, codec) else _from_json(codec, second)
        return TLVOption(int(code), _ty.cast(OptionCodec, value).pack())

    def get(self, code: _ty.Union[str, int], default: _ty.Any = None) -> _ty.Any:
        """The first sub-option `code` names, decoded by its codec, or `default`.

        Octets its codec refuses come back as `Bytes`, never as an error.
        """
        wanted = IPXEOption.resolve(code)
        for option in self:
            if option.code == int(wanted):
                return _decoded(wanted, option.value)
        return default

    def features(self) -> "list[IPXEOption]":
        """The feature flags present, in the order they were sent."""
        found = []
        for option in self:
            code = IPXEOption(option.code)
            if code.is_feature():
                found.append(code)
        return found

    def to_json(self) -> list[_ty.Any]:
        written: list[_ty.Any] = []
        for option in self:
            code = IPXEOption(option.code)
            key: _ty.Any = code.label() if code.name is not None else option.code
            value = _decoded(code, option.value)
            readable = value.to_json()
            if isinstance(value, Bytes) or _repacked(code, readable) != bytes(
                option.value
            ):
                readable = {"hex": option.value.hex()}
            written.append([key, readable])
        return written

    @classmethod
    def from_json(cls, data: _ty.Any) -> _ty.Any:
        """What `to_json` writes, or the hex text of a document written while
        this option had no codec of its own."""
        if isinstance(data, str):
            return cls.unpack(Bytes.parse(data))
        return super().from_json(data)

    def _item_text(self, option: TLVOption) -> str:
        """One sub-option as the message display shows it: HTTPS=U8(1)."""
        code = IPXEOption(option.code)
        name = code.label() if code.name is not None else str(option.code)
        return f"{name}={_display(_decoded(code, option.value))}"

    def display_text(self) -> str:
        return ", ".join(self._item_text(option) for option in self)


def _decoded(code: IPXEOption, octets: _ty.Any) -> _ty.Any:
    try:
        return code.get_type().unpack(octets)
    except (ValueError, TypeError):
        return Bytes(octets)


def _repacked(code: IPXEOption, readable: _ty.Any) -> _ty.Optional[bytes]:
    try:
        return bytes(_from_json(code.get_type(), readable).pack())
    except (ValueError, TypeError):
        return None


def _from_json(codec: _ty.Any, data: _ty.Any) -> _ty.Any:
    read = getattr(codec, "from_json", None)
    return read(data) if read is not None else codec(data)


def _display(value: _ty.Any) -> str:
    text = getattr(value, "display_text", None)
    return text() if text is not None else repr(value)
