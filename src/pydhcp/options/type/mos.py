from __future__ import annotations
from collections.abc import Iterable
import typing as _ty

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from .base import DhcpOptionType, List
from .net import IPv4Address
from .scalar import Bytes


class _MoSLabelList(DhcpOptionType, list[str]):
    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @staticmethod
    def _encode_domain(domain: str) -> bytes:
        labels = domain.split(".")
        data = bytearray()
        for label in labels:
            if not label:
                raise ValueError("MoS FQDN entries must not contain empty labels")
            label_bytes = label.encode()
            if len(label_bytes) > 63:
                raise ValueError("MoS FQDN label exceeds 63 bytes")
            data.append(len(label_bytes))
            data.extend(label_bytes)
        data.append(0)
        return bytes(data)

    @classmethod
    def _decode_domain(cls, option: memoryview, start: int) -> tuple[str, int]:
        labels: list[str] = []
        idx = start
        size = len(option)
        while True:
            if idx >= size:
                raise ValueError(f"{cls.__name__} option is truncated")
            length = option[idx]
            idx += 1
            if length == 0:
                return ".".join(labels), idx - start
            if idx + length > size:
                raise ValueError(f"{cls.__name__} option is truncated")
            labels.append(option[idx : idx + length].tobytes().decode())
            idx += length

    @classmethod
    def _normalize(cls, item: _ty.Any) -> str:
        normalized: str
        if isinstance(item, str):
            normalized = item
        else:
            normalized = str(item)
        cls._encode_domain(normalized)
        return normalized

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
            domain, read = cls._decode_domain(option, idx)
            self.append(domain)
            idx += read
        return self, size

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for item in self:
            encoded = self._encode_domain(item)
            data.extend(encoded)
            written += len(encoded)
        return written

    def __json__(self) -> list[str]:
        return list(self)


class _MoSSubOption(DhcpOptionType):
    def __init__(self, code: int, value: _ty.Any) -> None:
        self.code = int(code)
        self.value = self._normalize_value(self.code, value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _MoSSubOption):
            return NotImplemented
        return (self.code, self.value) == (other.code, other.value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, value={self.value!r})"

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        return value

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        return Bytes(payload)

    def _write_payload(self, data: bytearray) -> int:
        payload = self.value
        if isinstance(payload, DhcpOptionType):
            return payload._dhcp_write(data)
        payload_bytes = Bytes(payload)
        data.extend(payload_bytes)
        return len(payload_bytes)

    @classmethod
    def _from_payload(cls: type[Self], code: int, payload: memoryview) -> Self:
        return cls(code, cls._read_payload(payload))

    def _dhcp_write(self, data: bytearray) -> int:
        payload = bytearray()
        payload_len = self._write_payload(payload)
        if payload_len > 255:
            raise ValueError(f"{type(self).__name__} entry exceeds 255 bytes")
        data.append(self.code)
        data.append(payload_len)
        data.extend(payload)
        return payload_len + 2

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 2:
            raise ValueError(f"{cls.__name__} option is truncated")
        code = option[0]
        length = option[1]
        if len(option) < 2 + length:
            raise ValueError(f"{cls.__name__} option is truncated")
        return cls._from_payload(code, option[2 : 2 + length]), 2 + length

    def __json__(self) -> list[_ty.Any]:
        value = self.value
        if isinstance(value, DhcpOptionType):
            value = value.__json__()
        return [self.code, value]


class _MoSIpv4AddressSubOption(_MoSSubOption):
    _KNOWN_CODES = {1, 2, 3}

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if code not in cls._KNOWN_CODES:
            return Bytes(value)
        if isinstance(value, List):
            return value
        return List[IPv4Address](value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        if len(payload) % 4:
            raise ValueError(f"{cls.__name__} option is truncated")
        return List[IPv4Address]([payload[i : i + 4].tobytes() for i in range(0, len(payload), 4)])

    @classmethod
    def _from_payload(cls: type[Self], code: int, payload: memoryview) -> Self:
        if code not in cls._KNOWN_CODES:
            return cls(code, Bytes(payload))
        return cls(code, cls._read_payload(payload))

    def _write_payload(self, data: bytearray) -> int:
        if self.code not in self._KNOWN_CODES:
            return Bytes(self.value)._dhcp_write(data)
        payload = _ty.cast(DhcpOptionType, self.value)
        return payload._dhcp_write(data)


class _MoSFqdnSubOption(_MoSSubOption):
    _KNOWN_CODES = {1, 2, 3}

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if code not in cls._KNOWN_CODES:
            return Bytes(value)
        if isinstance(value, _MoSLabelList):
            return value
        return _MoSLabelList(value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        return _MoSLabelList._dhcp_read(payload)[0]

    @classmethod
    def _from_payload(cls: type[Self], code: int, payload: memoryview) -> Self:
        if code not in cls._KNOWN_CODES:
            return cls(code, Bytes(payload))
        return cls(code, cls._read_payload(payload))

    def _write_payload(self, data: bytearray) -> int:
        if self.code not in self._KNOWN_CODES:
            return Bytes(self.value)._dhcp_write(data)
        payload = _ty.cast(DhcpOptionType, self.value)
        return payload._dhcp_write(data)


class MoSIpv4AddressRecord(_MoSIpv4AddressSubOption):
    """RFC 5678 MoS sub-option record carrying IPv4 addresses."""


class MoSFqdnRecord(_MoSFqdnSubOption):
    """RFC 5678 MoS sub-option record carrying FQDN label sequences."""


class _MoSOptionBase(DhcpOptionType, list[_MoSSubOption]):
    _RECORD_TYPE: type[_MoSSubOption] = _MoSSubOption

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> _MoSSubOption:
        if isinstance(item, cls._RECORD_TYPE):
            return item
        code, value = item
        return cls._RECORD_TYPE(code, value)

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
            record, read = cls._RECORD_TYPE._dhcp_read(option[idx:])
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


class MoSIpv4AddressList(_MoSOptionBase):
    """RFC 5678 MoS option carrying IPv4 address sub-options."""

    _RECORD_TYPE = MoSIpv4AddressRecord


class MoSFqdnList(_MoSOptionBase):
    """RFC 5678 MoS option carrying FQDN sub-options."""

    _RECORD_TYPE = MoSFqdnRecord
