from __future__ import annotations
from collections.abc import Iterable
import typing as _ty

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from .base import DhcpOptionType
from .scalar import Bytes


class _LengthPrefixedOpaqueList(DhcpOptionType, list[_ty.Any]):
    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> Bytes:
        if isinstance(item, Bytes):
            if not item:
                raise ValueError(f"{cls.__name__} entries must be non-empty")
            return item
        if isinstance(item, str):
            raise TypeError(f"{cls.__name__} entries must be opaque bytes")
        item_bytes: Bytes = Bytes(item)
        if not item_bytes:
            raise ValueError(f"{cls.__name__} entries must be non-empty")
        return item_bytes

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
            length = option[idx]
            idx += 1
            if length == 0:
                raise ValueError(f"{cls.__name__} option contains a zero-length entry")
            if idx + length > size:
                raise ValueError(f"{cls.__name__} option is truncated")
            self.append(Bytes(option[idx : idx + length]))
            idx += length
        return self, size

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for item in self:
            if not len(item):
                raise ValueError(f"{type(self).__name__} entries must be non-empty")
            if len(item) > 255:
                raise ValueError(f"{type(self).__name__} entry exceeds 255 bytes")
            data.append(len(item))
            data.extend(item)
            written += len(item) + 1
        return written

    def __json__(self) -> list[str]:
        return [item.__json__() for item in self]


class UserClass(_LengthPrefixedOpaqueList):
    """RFC 3004 user-class opaque byte list."""


class TlvOption(DhcpOptionType):
    def __init__(self, code: int, value: _ty.Union[bytes, bytearray, memoryview, Bytes]) -> None:
        self.code = int(code)
        self.value = Bytes(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code}, value={self.value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TlvOption):
            return NotImplemented
        return (self.code, self.value) == (other.code, other.value)

    def __json__(self) -> list[_ty.Any]:
        return [self.code, self.value.__json__()]

    def _dhcp_write(self, data: bytearray) -> int:
        data.append(self.code)
        data.append(len(self.value))
        data.extend(self.value)
        return len(self.value) + 2


class EncapsulatedOptions(DhcpOptionType, list[TlvOption]):
    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> TlvOption:
        if isinstance(item, TlvOption):
            return item
        code, value = item
        return TlvOption(code, value)

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
            code = option[idx]
            idx += 1
            if code == 0:
                continue
            if code == 255:
                break
            if idx >= size:
                raise ValueError(f"{cls.__name__} option is truncated: missing length")
            length = option[idx]
            idx += 1
            if idx + length > size:
                raise ValueError(f"{cls.__name__} option is truncated")
            self.append(TlvOption(code, option[idx : idx + length]))
            idx += length
        return self, idx

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for item in self:
            written += item._dhcp_write(data)
        return written

    def __json__(self) -> list[list[_ty.Any]]:
        return [item.__json__() for item in self]


class VendorSpecificInformation(Bytes):
    """Opaque vendor-specific payload for option 43."""


class RelayAgentInformation(EncapsulatedOptions):
    """RFC 3046 relay-agent sub-options."""


class ViVendorSpecificInformationRecord(DhcpOptionType):
    def __init__(
        self,
        enterprise_number: int,
        value: _ty.Union[bytes, bytearray, memoryview, Bytes],
    ) -> None:
        self.enterprise_number = int(enterprise_number)
        self.value = Bytes(value)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(enterprise_number={self.enterprise_number}, "
            f"value={self.value!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ViVendorSpecificInformationRecord):
            return NotImplemented
        return (self.enterprise_number, self.value) == (other.enterprise_number, other.value)

    def __json__(self) -> list[_ty.Any]:
        return [self.enterprise_number, self.value.__json__()]

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 5:
            raise ValueError(f"{cls.__name__} option is truncated")
        enterprise_number = int.from_bytes(option[:4], "big")
        length = option[4]
        if len(option) < 5 + length:
            raise ValueError(f"{cls.__name__} option is truncated")
        return cls(enterprise_number, option[5 : 5 + length]), 5 + length

    def _dhcp_write(self, data: bytearray) -> int:
        if self.enterprise_number < 0 or self.enterprise_number > 0xFFFFFFFF:
            raise ValueError(f"{type(self).__name__} enterprise_number must fit in 32 bits")
        if len(self.value) > 255:
            raise ValueError(f"{type(self).__name__} entry exceeds 255 bytes")
        data.extend(self.enterprise_number.to_bytes(4, "big"))
        data.append(len(self.value))
        data.extend(self.value)
        return 5 + len(self.value)


class ViVendorSpecificInformation(DhcpOptionType, list[ViVendorSpecificInformationRecord]):
    """RFC 3925 vendor-identifying vendor-specific information records."""

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> ViVendorSpecificInformationRecord:
        if isinstance(item, ViVendorSpecificInformationRecord):
            return item
        enterprise_number, value = item
        return ViVendorSpecificInformationRecord(enterprise_number, value)

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
            record, read = ViVendorSpecificInformationRecord._dhcp_read(option[idx:])
            self.append(record)
            idx += read
        return self, size

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for item in self:
            written += item._dhcp_write(data)
        return written

    def __json__(self) -> list[list[_ty.Any]]:
        return [item.__json__() for item in self]


class ViVendorClassRecord(DhcpOptionType):
    def __init__(self, enterprise_number: int, value: _ty.Any) -> None:
        self.enterprise_number = int(enterprise_number)
        if isinstance(value, UserClass):
            self.value = value
        else:
            self.value = UserClass(value)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(enterprise_number={self.enterprise_number}, "
            f"value={self.value!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ViVendorClassRecord):
            return NotImplemented
        return (self.enterprise_number, self.value) == (other.enterprise_number, other.value)

    def __json__(self) -> list[_ty.Any]:
        return [self.enterprise_number, self.value.__json__()]

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 5:
            raise ValueError(f"{cls.__name__} option is truncated")
        enterprise_number = int.from_bytes(option[:4], "big")
        length = option[4]
        if len(option) < 5 + length:
            raise ValueError(f"{cls.__name__} option is truncated")
        payload, read = UserClass._dhcp_read(option[5 : 5 + length])
        if read != length:
            raise ValueError(f"{cls.__name__} option is truncated")
        return cls(enterprise_number, payload), 5 + length

    def _dhcp_write(self, data: bytearray) -> int:
        if self.enterprise_number < 0 or self.enterprise_number > 0xFFFFFFFF:
            raise ValueError(f"{type(self).__name__} enterprise_number must fit in 32 bits")
        payload = bytearray()
        payload_len = self.value._dhcp_write(payload)
        if payload_len > 255:
            raise ValueError(f"{type(self).__name__} entry exceeds 255 bytes")
        data.extend(self.enterprise_number.to_bytes(4, "big"))
        data.append(payload_len)
        data.extend(payload)
        return 5 + payload_len


class ViVendorClass(DhcpOptionType, list[ViVendorClassRecord]):
    """RFC 3925 vendor-identifying vendor class records."""

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> ViVendorClassRecord:
        if isinstance(item, ViVendorClassRecord):
            return item
        enterprise_number, value = item
        return ViVendorClassRecord(enterprise_number, value)

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
            record, read = ViVendorClassRecord._dhcp_read(option[idx:])
            self.append(record)
            idx += read
        return self, size

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for item in self:
            written += item._dhcp_write(data)
        return written

    def __json__(self) -> list[list[_ty.Any]]:
        return [item.__json__() for item in self]
