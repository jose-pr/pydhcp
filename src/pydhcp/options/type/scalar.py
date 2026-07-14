from __future__ import annotations
from collections.abc import Iterable
import typing as _ty
import enum as _enum
from ...log import LOGGER

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from .base import DhcpOptionType


class Bytes(DhcpOptionType, bytes):
    """Opaque byte payload."""
    def __new__(cls, src: _ty.Optional[_ty.Union[bytes, bytearray, memoryview, str]] = None) -> Self:
        if isinstance(src, str):
            return cls.fromhex(src)
        if src is None:
            return super().__new__(cls)
        return super().__new__(cls, src)

    def __repr__(self) -> str:
        return str(bytes(self))

    def __str__(self) -> str:
        return self.hex().upper()

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        return cls(option), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        data.extend(self)
        return len(self)

    def __json__(self) -> str:
        return self.hex()


class UriList(DhcpOptionType, list[str]):
    """List of UTF-8 URIs encoded as repeated U16-length-prefixed entries."""

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> str:
        if isinstance(item, str):
            return item
        return str(item)

    def append(self, item: _ty.Any) -> None:
        return list.append(self, self._normalize(item))

    def extend(self, __iterable: Iterable[_ty.Any]) -> None:
        list.extend(self, [self._normalize(item) for item in __iterable])

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        self = cls()
        idx = 0
        size = len(option)
        while idx < size:
            if idx + 2 > size:
                raise ValueError(f"{cls.__name__} option is truncated")
            length = int.from_bytes(option[idx : idx + 2], "big")
            idx += 2
            if idx + length > size:
                raise ValueError(f"{cls.__name__} option is truncated")
            payload = option[idx : idx + length].tobytes()
            try:
                decoded = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"{cls.__name__} option contains invalid UTF-8") from exc
            self.append(decoded)
            idx += length
        return self, size

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for item in self:
            encoded = item.encode("utf-8")
            if len(encoded) > 0xFFFF:
                raise ValueError(f"{type(self).__name__} entry exceeds 65535 bytes")
            data.extend(len(encoded).to_bytes(2, "big"))
            data.extend(encoded)
            written += len(encoded) + 2
        return written

    def __json__(self) -> list[str]:
        return list(self)


class String(DhcpOptionType, str):
    """RFC 2132 NVT-ASCII string with null termination on the wire."""
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        text, _, _ = option.tobytes().partition(b"\x00")
        try:
            decoded_text = text.decode("utf-8")
        except UnicodeDecodeError:
            LOGGER.warning(f"Option contains invalid UTF-8: {text.hex()}")
            decoded_text = text.decode("utf-8", errors="replace")
        return cls(decoded_text), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        text = self.encode()
        data.extend(text)
        return len(text)


class Boolean(DhcpOptionType, int):
    """Boolean option encoded as a single octet."""
    def __new__(cls, val: _ty.Any) -> Self:
        if val:
            val = 1
        else:
            val = 0
        return super().__new__(cls, val)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        return cls(option[0]), 1

    def _dhcp_write(self, data: bytearray) -> int:
        data.append(self)
        return 1

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return 1

    def __repr__(self) -> str:
        return f"Boolean({bool(self)!r})"

    def __json__(self) -> bool:
        return self.__bool__()


class BaseFixedLengthInteger(DhcpOptionType, int):
    NUMBER_OF_BYTES: int
    SIGNED: bool = False

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        option_part = option[: cls.NUMBER_OF_BYTES]
        if len(option_part) != cls.NUMBER_OF_BYTES:
            raise ValueError()
        return cls(int.from_bytes(option_part, "big", signed=cls.SIGNED)), cls.NUMBER_OF_BYTES

    def _dhcp_write(self, data: bytearray) -> int:
        self._validate()
        data.extend(self.to_bytes(self.NUMBER_OF_BYTES, "big", signed=self.SIGNED))
        return self.NUMBER_OF_BYTES

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return cls.NUMBER_OF_BYTES

    def _validate(self) -> None:
        if self.bit_length() > self.NUMBER_OF_BYTES * 8:
            raise ValueError("Number is too big")
        if not self.SIGNED and self < 0:
            raise ValueError("Value must not be signed")

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)!r})"


class FixedLengthInteger(BaseFixedLengthInteger):
    def __new__(cls, val: _ty.Any) -> Self:
        val_obj = int.__new__(cls, val)
        val_obj._validate()
        return val_obj


class U8(FixedLengthInteger):
    """Unsigned 8-bit integer."""
    NUMBER_OF_BYTES = 1
    SIGNED = False


class U16(FixedLengthInteger):
    """Unsigned 16-bit integer."""
    NUMBER_OF_BYTES = 2
    SIGNED = False


class U32(FixedLengthInteger):
    """Unsigned 32-bit integer."""
    NUMBER_OF_BYTES = 4
    SIGNED = False


class I32(FixedLengthInteger):
    """Signed 32-bit integer."""
    NUMBER_OF_BYTES = 4
    SIGNED = True


class ClientIdentifier(Bytes):
    """RFC 2132 client identifier."""
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 2:
            raise ValueError(option)
        return super()._dhcp_read(option)

    def __repr__(self) -> str:
        ty_val = self[0]
        addr = self[1:]
        ty_str = str(ty_val)
        try:
            from ...packet.enums import HardwareAddressType

            ty_str = HardwareAddressType(ty_val).name
        except ValueError:
            ...
        maybe = f"{ty_str}({addr.hex(':').upper()})"

        return f"{maybe}|{self}"

    def __str__(self) -> str:
        return self.hex(":").upper()


class OptionOverload(DhcpOptionType, _enum.IntFlag):
    """RFC 2132 option-overload selector."""
    NONE = 0
    FILE = 1
    SNAME = 2
    BOTH = FILE | SNAME

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        option_part = option[:1]
        if len(option_part) != 1:
            raise ValueError()
        return cls(option_part[0]), 1

    def _dhcp_write(self, data: bytearray) -> int:
        data.append(self.value)
        return 1

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return 1
