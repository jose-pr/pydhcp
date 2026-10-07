from __future__ import annotations
import typing as _ty


from ...exceptions import DHCPDecodeError, DHCPValueError
from ._base import DHCPOptionType, RecordList, _NormalizedList, _Record, _set, frozen
from ._scalar import Bytes, _octets

_LengthPrefixedOpaqueListT = _ty.TypeVar(
    "_LengthPrefixedOpaqueListT", bound="_LengthPrefixedOpaqueList"
)


class _LengthPrefixedOpaqueList(_NormalizedList[Bytes]):
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
                raise DHCPValueError(f"{cls.__name__} entries must be non-empty")
            return item
        if isinstance(item, str):
            raise TypeError(f"{cls.__name__} entries must be opaque bytes")
        item_bytes: Bytes = _octets(item)
        if not item_bytes:
            raise DHCPValueError(f"{cls.__name__} entries must be non-empty")
        return item_bytes

    @classmethod
    def unpack_from(
        cls: type[_LengthPrefixedOpaqueListT], option: memoryview
    ) -> tuple[_LengthPrefixedOpaqueListT, int]:
        self = cls()
        idx = 0
        size = len(option)
        while idx < size:
            length = option[idx]
            idx += 1
            if length == 0:
                raise DHCPDecodeError(
                    f"{cls.__name__} option contains a zero-length entry"
                )
            if idx + length > size:
                raise DHCPDecodeError(f"{cls.__name__} option is truncated")
            self.append(_octets(option[idx : idx + length]))
            idx += length
        return self, size

    def pack_into(self, data: bytearray) -> int:
        written = 0
        for item in self:
            if not len(item):
                raise DHCPValueError(f"{type(self).__name__} entries must be non-empty")
            if len(item) > 255:
                raise DHCPValueError(f"{type(self).__name__} entry exceeds 255 bytes")
            data.append(len(item))
            data.extend(item)
            written += len(item) + 1
        return written

    def to_json(self) -> list[str]:
        return [item.to_json() for item in self]


class UserClass(_LengthPrefixedOpaqueList):
    """RFC 3004 user-class opaque byte list."""


class TLVOption(_Record):
    __slots__ = ("code", "value")
    _FIELDS = __slots__

    code: int
    value: Bytes

    def __init__(
        self, code: int, value: _ty.Union[bytes, bytearray, memoryview, Bytes]
    ) -> None:
        code = int(code)
        octets = _octets(value)
        if not 0 <= code <= 255:
            raise DHCPValueError(
                f"sub-option code {code} does not fit one octet (0 to 255)"
            )
        if len(octets) > 255:
            raise DHCPValueError(
                f"sub-option {code} is {len(octets)} octets; "
                "a sub-option holds at most 255"
            )
        _set(self, "code", code)
        _set(self, "value", octets)

    def to_json(self) -> list[_ty.Any]:
        return [self.code, self.value.to_json()]

    def pack_into(self, data: bytearray) -> int:
        data.append(self.code)
        data.append(len(self.value))
        data.extend(self.value)
        return len(self.value) + 2


_EncapsulatedOptionsT = _ty.TypeVar(
    "_EncapsulatedOptionsT", bound="EncapsulatedOptions"
)


class EncapsulatedOptions(RecordList[TLVOption]):
    """TLV container for building vendor-specific sub-option payloads."""

    # Only the *read* framing is its own: unlike a plain record list this one
    # honours the PAD (0) and END (255) markers that appear inside an
    # encapsulated options field, so it cannot share `List.unpack_from`.
    @classmethod
    def unpack_from(
        cls: type[_EncapsulatedOptionsT], option: memoryview
    ) -> tuple[_EncapsulatedOptionsT, int]:
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
                raise DHCPDecodeError(
                    f"{cls.__name__} option is truncated: missing length"
                )
            length = option[idx]
            idx += 1
            if idx + length > size:
                raise DHCPDecodeError(f"{cls.__name__} option is truncated")
            self.append(TLVOption(code, option[idx : idx + length]))
            idx += length
        return self, idx


class VendorSpecificInformation(Bytes):
    """Opaque vendor-specific payload for option 43."""


class RelayAgentInformation(EncapsulatedOptions):
    """RFC 3046 relay-agent sub-options.

    Plain code, length, value tuples: RFC 3046 s2.0 defines no pad sub-option
    and no terminating 255, so 0 and 255 are sub-option codes like any other.
    """

    @classmethod
    def unpack_from(
        cls: type[_EncapsulatedOptionsT], option: memoryview
    ) -> tuple[_EncapsulatedOptionsT, int]:
        self = cls()
        idx = 0
        size = len(option)
        while idx < size:
            if idx + 2 > size:
                raise DHCPDecodeError(
                    f"{cls.__name__} option is truncated: missing length"
                )
            code = option[idx]
            length = option[idx + 1]
            idx += 2
            if idx + length > size:
                raise DHCPDecodeError(f"{cls.__name__} option is truncated")
            self.append(TLVOption(code, option[idx : idx + length]))
            idx += length
        return self, size


_VIVendorSpecificInformationRecordT = _ty.TypeVar(
    "_VIVendorSpecificInformationRecordT", bound="VIVendorSpecificInformationRecord"
)


class VIVendorSpecificInformationRecord(_Record):
    __slots__ = ("enterprise_number", "value")
    _FIELDS = __slots__

    enterprise_number: int
    value: Bytes

    def __init__(
        self,
        enterprise_number: int,
        value: _ty.Union[bytes, bytearray, memoryview, Bytes],
    ) -> None:
        _set(self, "enterprise_number", int(enterprise_number))
        _set(self, "value", _octets(value))

    def to_json(self) -> list[_ty.Any]:
        return [self.enterprise_number, self.value.to_json()]

    @classmethod
    def unpack_from(
        cls: type[_VIVendorSpecificInformationRecordT], option: memoryview
    ) -> tuple[_VIVendorSpecificInformationRecordT, int]:
        if len(option) < 5:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        enterprise_number = int.from_bytes(option[:4], "big")
        length = option[4]
        if len(option) < 5 + length:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        return cls(enterprise_number, option[5 : 5 + length]), 5 + length

    def pack_into(self, data: bytearray) -> int:
        if self.enterprise_number < 0 or self.enterprise_number > 0xFFFFFFFF:
            raise DHCPValueError(
                f"{type(self).__name__} enterprise_number must fit in 32 bits"
            )
        if len(self.value) > 255:
            raise DHCPValueError(f"{type(self).__name__} entry exceeds 255 bytes")
        data.extend(self.enterprise_number.to_bytes(4, "big"))
        data.append(len(self.value))
        data.extend(self.value)
        return 5 + len(self.value)


class VIVendorSpecificInformation(RecordList[VIVendorSpecificInformationRecord]):
    """RFC 3925 vendor-identifying vendor-specific information records."""


_VIVendorClassRecordT = _ty.TypeVar(
    "_VIVendorClassRecordT", bound="VIVendorClassRecord"
)


class VIVendorClassRecord(_Record):
    __slots__ = ("enterprise_number", "value")
    _FIELDS = __slots__

    enterprise_number: int
    value: UserClass

    def __init__(self, enterprise_number: int, value: _ty.Any) -> None:
        if isinstance(value, (list, tuple)) and not isinstance(value, UserClass):
            # `to_json` writes each entry as hex text.
            value = [_octets(item) if isinstance(item, str) else item for item in value]
        _set(self, "enterprise_number", int(enterprise_number))
        _set(
            self,
            "value",
            frozen(value if isinstance(value, UserClass) else UserClass(value)),
        )

    def to_json(self) -> list[_ty.Any]:
        return [self.enterprise_number, self.value.to_json()]

    @classmethod
    def unpack_from(
        cls: type[_VIVendorClassRecordT], option: memoryview
    ) -> tuple[_VIVendorClassRecordT, int]:
        if len(option) < 5:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        enterprise_number = int.from_bytes(option[:4], "big")
        length = option[4]
        if len(option) < 5 + length:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        payload, read = UserClass.unpack_from(option[5 : 5 + length])
        if read != length:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        return cls(enterprise_number, payload), 5 + length

    def pack_into(self, data: bytearray) -> int:
        if self.enterprise_number < 0 or self.enterprise_number > 0xFFFFFFFF:
            raise DHCPValueError(
                f"{type(self).__name__} enterprise_number must fit in 32 bits"
            )
        payload = bytearray()
        payload_len = self.value.pack_into(payload)
        if payload_len > 255:
            raise DHCPValueError(f"{type(self).__name__} entry exceeds 255 bytes")
        data.extend(self.enterprise_number.to_bytes(4, "big"))
        data.append(payload_len)
        data.extend(payload)
        return 5 + payload_len


class VIVendorClass(RecordList[VIVendorClassRecord]):
    """RFC 3925 vendor-identifying vendor class records."""
