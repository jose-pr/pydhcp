from __future__ import annotations
import typing as _ty


from ...exceptions import DHCPDecodeError, DHCPValueError
from ._base import (
    DHCPOptionType,
    List,
    RecordList,
    _NormalizedList,
    _Record,
    _set,
    frozen,
)
from ._domain import decode_domain_name, encode_domain_name
from ._addresses import IPv4AddressOption
from ._scalar import Bytes, _octets

_MoSLabelListT = _ty.TypeVar("_MoSLabelListT", bound="_MoSLabelList")


class _MoSLabelList(_NormalizedList[str]):
    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @staticmethod
    def _encode_domain(domain: str) -> bytes:
        return encode_domain_name(domain, "MoS FQDN entry")

    @classmethod
    def _decode_domain(cls, option: memoryview, start: int) -> tuple[str, int]:
        return decode_domain_name(option, start, cls.__name__)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> str:
        normalized: str
        if isinstance(item, str):
            normalized = item
        else:
            normalized = str(item)
        cls._encode_domain(normalized)
        return normalized

    @classmethod
    def unpack_from(
        cls: type[_MoSLabelListT], option: memoryview
    ) -> tuple[_MoSLabelListT, int]:
        self = cls()
        idx = 0
        size = len(option)
        while idx < size:
            domain, read = cls._decode_domain(option, idx)
            self.append(domain)
            idx += read
        return self, size

    def pack_into(self, data: bytearray) -> int:
        written = 0
        for item in self:
            encoded = self._encode_domain(item)
            data.extend(encoded)
            written += len(encoded)
        return written

    def to_json(self) -> list[str]:
        return list(self)


_MoSSubOptionT = _ty.TypeVar("_MoSSubOptionT", bound="_MoSSubOption")


class _MoSSubOption(_Record):
    __slots__ = ("code", "value")
    _FIELDS = __slots__

    code: int
    value: _ty.Any

    def __init__(self, code: int, value: _ty.Any) -> None:
        _set(self, "code", int(code))
        _set(self, "value", frozen(self._normalize_value(int(code), value)))

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        return value

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        return _octets(payload)

    def _write_payload(self, data: bytearray) -> int:
        payload = self.value
        if isinstance(payload, DHCPOptionType):
            return payload.pack_into(data)
        payload_bytes = _octets(payload)
        data.extend(payload_bytes)
        return len(payload_bytes)

    @classmethod
    def _from_payload(
        cls: type[_MoSSubOptionT], code: int, payload: memoryview
    ) -> _MoSSubOptionT:
        return cls(code, cls._read_payload(payload))

    def pack_into(self, data: bytearray) -> int:
        payload = bytearray()
        payload_len = self._write_payload(payload)
        if payload_len > 255:
            raise DHCPValueError(f"{type(self).__name__} entry exceeds 255 bytes")
        data.append(self.code)
        data.append(payload_len)
        data.extend(payload)
        return payload_len + 2

    @classmethod
    def unpack_from(
        cls: type[_MoSSubOptionT], option: memoryview
    ) -> tuple[_MoSSubOptionT, int]:
        if len(option) < 2:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        code = option[0]
        length = option[1]
        if len(option) < 2 + length:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        return cls._from_payload(code, option[2 : 2 + length]), 2 + length

    def to_json(self) -> list[_ty.Any]:
        value = self.value
        if isinstance(value, DHCPOptionType):
            value = value.to_json()
        return [self.code, value]


_MoSIPv4AddressSubOptionT = _ty.TypeVar(
    "_MoSIPv4AddressSubOptionT", bound="_MoSIPv4AddressSubOption"
)


class _MoSIPv4AddressSubOption(_MoSSubOption):
    _KNOWN_CODES = {1, 2, 3}

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if code not in cls._KNOWN_CODES:
            return _octets(value)
        if isinstance(value, List):
            return value
        return List[IPv4AddressOption](value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        if len(payload) % 4:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        return List[IPv4AddressOption](
            [payload[i : i + 4].tobytes() for i in range(0, len(payload), 4)]
        )

    @classmethod
    def _from_payload(
        cls: type[_MoSIPv4AddressSubOptionT], code: int, payload: memoryview
    ) -> _MoSIPv4AddressSubOptionT:
        if code not in cls._KNOWN_CODES:
            return cls(code, _octets(payload))
        return cls(code, cls._read_payload(payload))

    def _write_payload(self, data: bytearray) -> int:
        if self.code not in self._KNOWN_CODES:
            return _octets(self.value).pack_into(data)
        payload = _ty.cast(DHCPOptionType, self.value)
        return payload.pack_into(data)


_MoSFQDNSubOptionT = _ty.TypeVar("_MoSFQDNSubOptionT", bound="_MoSFQDNSubOption")


class _MoSFQDNSubOption(_MoSSubOption):
    _KNOWN_CODES = {1, 2, 3}

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if code not in cls._KNOWN_CODES:
            return _octets(value)
        if isinstance(value, _MoSLabelList):
            return value
        return _MoSLabelList(value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        return _MoSLabelList.unpack_from(payload)[0]

    @classmethod
    def _from_payload(
        cls: type[_MoSFQDNSubOptionT], code: int, payload: memoryview
    ) -> _MoSFQDNSubOptionT:
        if code not in cls._KNOWN_CODES:
            return cls(code, _octets(payload))
        return cls(code, cls._read_payload(payload))

    def _write_payload(self, data: bytearray) -> int:
        if self.code not in self._KNOWN_CODES:
            return _octets(self.value).pack_into(data)
        payload = _ty.cast(DHCPOptionType, self.value)
        return payload.pack_into(data)


class MoSIPv4AddressRecord(_MoSIPv4AddressSubOption):
    """RFC 5678 MoS sub-option record carrying IPv4 addresses."""


class MoSFQDNRecord(_MoSFQDNSubOption):
    """RFC 5678 MoS sub-option record carrying FQDN label sequences."""


class MoSIPv4AddressList(RecordList[MoSIPv4AddressRecord]):
    """RFC 5678 MoS option carrying IPv4 address sub-options."""


class MoSFQDNList(RecordList[MoSFQDNRecord]):
    """RFC 5678 MoS option carrying FQDN sub-options."""
