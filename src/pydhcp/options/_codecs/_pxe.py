"""The PXE options of RFC 4578: client architecture (93), network interface (94)
and machine identifier (97)."""

from __future__ import annotations

import enum as _enum
import typing as _ty
import uuid as _uuid

from ...exceptions import DHCPDecodeError, DHCPValueError
from ._base import DHCPOptionType, _Record, _set
from ._scalar import U8, Bytes, _octets

__all__ = ["ClientArchitecture", "ClientMachineID", "ClientNDI"]

_ClientArchitectureT = _ty.TypeVar("_ClientArchitectureT", bound="ClientArchitecture")


class ClientArchitecture(DHCPOptionType, _enum.IntEnum):
    """One entry of option 93: the IANA "Processor Architecture Types" registry.

    RFC 4578 s2.1 started the list; IANA's registry, which RFC 5970 shares with
    DHCPv6, corrects it (7 is x64 UEFI and 9 is EBC) and extends it. A number the
    registry does not name is an unnamed member carrying it, never refused.
    """

    X86_BIOS = 0x00
    NEC_PC98 = 0x01
    ITANIUM = 0x02
    DEC_ALPHA = 0x03
    ARC_X86 = 0x04
    INTEL_LEAN_CLIENT = 0x05
    X86_UEFI = 0x06
    X64_UEFI = 0x07
    EFI_XSCALE = 0x08
    EBC = 0x09
    ARM32_UEFI = 0x0A
    ARM64_UEFI = 0x0B
    POWERPC_OPEN_FIRMWARE = 0x0C
    POWERPC_EPAPR = 0x0D
    POWER_OPAL_V3 = 0x0E
    X86_UEFI_HTTP = 0x0F
    X64_UEFI_HTTP = 0x10
    EBC_HTTP = 0x11
    ARM32_UEFI_HTTP = 0x12
    ARM64_UEFI_HTTP = 0x13
    X86_BIOS_HTTP = 0x14
    ARM32_UBOOT = 0x15
    ARM64_UBOOT = 0x16
    ARM32_UBOOT_HTTP = 0x17
    ARM64_UBOOT_HTTP = 0x18
    RISCV32_UEFI = 0x19
    RISCV32_UEFI_HTTP = 0x1A
    RISCV64_UEFI = 0x1B
    RISCV64_UEFI_HTTP = 0x1C
    RISCV128_UEFI = 0x1D
    RISCV128_UEFI_HTTP = 0x1E
    S390_BASIC = 0x1F
    S390_EXTENDED = 0x20
    MIPS32_UEFI = 0x21
    MIPS64_UEFI = 0x22
    SUNWAY32_UEFI = 0x23
    SUNWAY64_UEFI = 0x24
    LOONGARCH32_UEFI = 0x25
    LOONGARCH32_UEFI_HTTP = 0x26
    LOONGARCH64_UEFI = 0x27
    LOONGARCH64_UEFI_HTTP = 0x28
    ARM_RPIBOOT = 0x29

    @classmethod
    def _missing_(cls, value: object) -> "_ty.Optional[ClientArchitecture]":
        """An unnamed member for a number the registry does not name (0 to 65535)."""
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        if not 0 <= value <= 0xFFFF:
            return None
        pseudo = _UNNAMED.get(value)
        if pseudo is None:
            pseudo = int.__new__(cls, value)
            pseudo._name_ = None  # type: ignore[assignment]
            pseudo._value_ = value
            pseudo = _UNNAMED.setdefault(value, pseudo)
        return pseudo

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        return 2

    @classmethod
    def unpack_from(
        cls: type[_ClientArchitectureT], option: memoryview
    ) -> tuple[_ClientArchitectureT, int]:
        if len(option) < 2:
            raise DHCPDecodeError("a client architecture is 2 octets (RFC 4578 s2.1)")
        return cls(int.from_bytes(option[:2], "big")), 2

    def pack_into(self, data: bytearray) -> int:
        data.extend(int(self).to_bytes(2, "big"))
        return 2

    def is_http(self) -> bool:
        """Whether this is one of the registry's "boot from http" architectures."""
        return self._name_ is not None and self._name_.endswith("_HTTP")

    def to_json(self) -> _ty.Any:
        """The member's name, or the number when it has none."""
        return self._name_ if self._name_ is not None else int(self)

    def label(self) -> str:
        """The member's name, or `ARCH_<n>` for a number that has none."""
        return self._name_ or f"ARCH_{self.value}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}.{self.label()}"

    def __str__(self) -> str:
        return self.label()

    def display_text(self) -> str:
        return self.label()


#: The unnamed members made so far, one per number at most.
_UNNAMED: "dict[int, ClientArchitecture]" = {}


class ClientNDI(_Record):
    """Option 94 (RFC 4578 s2.2): the network interface type and its revision.

    Type 1 is UNDI, the only one defined; `major` and `minor` are its revision
    (`ClientNDI(1, 3, 16)` is UNDI 3.16).
    """

    __slots__ = ("type", "major", "minor")
    _FIELDS = __slots__

    type: int
    major: int
    minor: int

    UNDI = 1

    def __init__(self, type: _ty.Any, major: _ty.Any, minor: _ty.Any) -> None:
        _set(self, "type", int(U8(type)))
        _set(self, "major", int(U8(major)))
        _set(self, "minor", int(U8(minor)))

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        return 3

    @classmethod
    def unpack_from(cls, option: memoryview) -> "tuple[ClientNDI, int]":
        return cls(option[0], option[1], option[2]), 3

    def pack_into(self, data: bytearray) -> int:
        data.extend((self.type, self.major, self.minor))
        return 3

    def to_json(self) -> list[int]:
        return [self.type, self.major, self.minor]

    @classmethod
    def from_json(cls, data: _ty.Any) -> _ty.Any:
        """What `to_json` writes, or the hex text of a document written while
        this option had no codec of its own."""
        if isinstance(data, str):
            return cls.unpack(Bytes.parse(data))
        return super().from_json(data)

    def display_text(self) -> str:
        kind = "UNDI" if self.type == self.UNDI else f"type {self.type}"
        return f"{kind} {self.major}.{self.minor}"


class ClientMachineID(_Record):
    """Option 97 (RFC 4578 s2.3): a type octet, then the machine identifier.

    Type 0, the only one defined, is a 16-octet GUID, which `uuid` reads in the
    order the octets arrived. Any other type or length is kept as received;
    sending a type 0 that is not 16 octets raises `DHCPValueError`.
    """

    __slots__ = ("type", "ident")
    _FIELDS = __slots__

    type: int
    ident: Bytes

    GUID = 0

    def __init__(self, type: _ty.Any, ident: _ty.Any) -> None:
        _set(self, "type", int(U8(type)))
        _set(self, "ident", _octets(ident))

    @classmethod
    def from_uuid(cls, value: _ty.Union[_uuid.UUID, str]) -> "ClientMachineID":
        """A type 0 identifier holding `value`'s 16 octets."""
        return cls(cls.GUID, _uuid.UUID(str(value)).bytes)

    @property
    def uuid(self) -> _ty.Optional[_uuid.UUID]:
        """The GUID as a `uuid.UUID`, or None when this is not a 16-octet type 0."""
        if self.type != self.GUID or len(self.ident) != 16:
            return None
        return _uuid.UUID(bytes=bytes(self.ident))

    @classmethod
    def unpack_from(cls, option: memoryview) -> "tuple[ClientMachineID, int]":
        if not option:
            raise DHCPDecodeError("a client machine identifier needs a type octet")
        return cls(option[0], bytes(option[1:])), len(option)

    def pack_into(self, data: bytearray) -> int:
        if self.type == self.GUID and len(self.ident) != 16:
            raise DHCPValueError(
                f"a type 0 machine identifier is a 16-octet GUID, not {len(self.ident)} "
                "octets (RFC 4578 s2.3)"
            )
        data.append(self.type)
        data.extend(self.ident)
        return 1 + len(self.ident)

    def to_json(self) -> list[_ty.Any]:
        return [self.type, self.ident.to_json()]

    @classmethod
    def from_json(cls, data: _ty.Any) -> _ty.Any:
        """What `to_json` writes, or the hex text of a document written while
        this option had no codec of its own."""
        if isinstance(data, str):
            return cls.unpack(Bytes.parse(data))
        return super().from_json(data)

    def display_text(self) -> str:
        found = self.uuid
        return (
            f"GUID {found}"
            if found is not None
            else f"type {self.type} {self.ident.hex()}"
        )
