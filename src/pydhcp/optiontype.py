from __future__ import annotations
from collections.abc import Iterable
import typing as _ty
from . import _utils
import enum as _enum
from .log import LOGGER

if _ty.TYPE_CHECKING:
    from typing_extensions import Self
    from ._options import BaseDhcpOptionCode

from .netutils import IPv4 as _IP, IPv4Interface as _Interface, IPv4Network as _Network


class DhcpOptionType:
    """Protocol for DHCP option payload codecs.

    Implementations decode with `_dhcp_read`, encode with `_dhcp_write`, and may
    advertise a fixed size with `_dhcp_len_hint`. The encode/decode pair should
    round-trip the same Python value.
    """
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        raise NotImplementedError()

    def _dhcp_write(self, buffer: bytearray) -> int:
        raise NotImplementedError()

    def _dhcp_encode(self) -> bytes:
        encoded = bytearray()
        _wrote = self._dhcp_write(encoded)
        return bytes(encoded)

    def __json__(self) -> _ty.Any:
        return self

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return None

    @classmethod
    def _dhcp_decode(cls, option: memoryview | bytes | bytearray) -> "Self":
        hint = cls._dhcp_len_hint()
        todecode = len(option)
        option = memoryview(option) if not isinstance(option, memoryview) else option
        if hint:
            if todecode != hint:
                raise ValueError("Wrong option size")
        decoded, read = cls._dhcp_read(option)
        if read != todecode:
            raise ValueError("Couldnt decode whole option")
        return decoded


_T = _ty.TypeVar("_T", bound=DhcpOptionType)
_C = _ty.TypeVar("_C", bound="BaseDhcpOptionCode")


class List(DhcpOptionType, list[_T], metaclass=_utils.GenericMeta):
    """Typed DHCP option list container."""
    _args_: _ty.ClassVar[tuple[_T]]

    def __init__(self, *items: _ty.Any):
        for _items in items:
            self.extend(_items if isinstance(_items, (tuple, list)) else (_items,))

    @classmethod
    def _normalize(cls, item: _ty.Any) -> _T:
        ty = cls._args_[0]
        if isinstance(item, _ty.cast(_ty.Any, ty)):
            return _ty.cast(_T, item)
        return _ty.cast(_T, _ty.cast(_ty.Any, ty)(item))

    def __setitem__(self, idx: _ty.Any, item: _T) -> None:  # type: ignore[override]
        return list.__setitem__(self, idx, self._normalize(item))

    def append(self, item: _T) -> None:
        return list.append(self, self._normalize(item))

    def extend(self, __iterable: Iterable[_T]) -> None:
        list.extend(
            self,
            [self._normalize(item) for item in __iterable],
        )

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        _l = len(option)
        self = cls()
        ty = self._args_[0]
        while option:
            item, l = ty._dhcp_read(option)
            self.append(item)
            option = option[l:]
        return self, _l

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for item in self:
            written += item._dhcp_write(data)
        return written

    def __json__(self) -> list[_ty.Any]:
        return [item.__json__() for item in self]


class DhcpOptionCodes(List[_C]):  # type: ignore[type-var]
    """List of option codes used by parameter-request-list style options."""
    @classmethod
    def _normalize(cls, item: _ty.Any) -> _ty.Any:
        ty = cls._args_[0]
        if isinstance(item, _ty.cast(_ty.Any, ty)):
            return item
        try:
            return _ty.cast(_ty.Any, ty)(item)
        except (TypeError, ValueError):
            ...
        item_int = int(item)
        if item_int > 255:
            raise ValueError()
        return item_int

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        return cls(option.tolist()), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        data.extend(_ty.cast(_ty.Iterable[int], self))
        return len(self)


class IPv4Address(DhcpOptionType, _IP):
    """A single IPv4 address carried in network byte order."""
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        return cls(option[:4].tobytes()), 4

    def _dhcp_write(self, data: bytearray) -> int:
        data.extend(self.packed)
        return 4

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return 4

    def __repr__(self) -> str:
        return str(self)

    def __json__(self) -> str:
        return str(self)


class ClasslessRoute(DhcpOptionType):
    """RFC 3442 classless static route entry."""
    def __init__(self, gateway: _IP, network: _Network) -> None:
        self.gateway = _IP(gateway)
        self.network = _Network(network)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 1:
            raise ValueError("ClasslessRoute option is truncated: missing prefix length")
        cidr = option[0]
        if cidr > 32:
            raise ValueError(f"ClasslessRoute prefix length {cidr} exceeds 32")
        last = 1 + (cidr + 7) // 8
        if len(option) < last + 4:
            raise ValueError(
                f"ClasslessRoute option is truncated: needs {last + 4} bytes, got {len(option)}"
            )
        net_bytes = option[1:last].tobytes() + b"\x00\x00\x00\x00"
        network = _Network((net_bytes[:4], cidr))
        gateway = _IP(option[last : last + 4].tobytes())
        return cls(gateway, network), last + 4

    def _dhcp_write(self, data: bytearray) -> int:
        cidr = self.network.prefixlen
        last = (cidr + 7) // 8
        network = self.network.network_address.packed[:last]
        data.append(cidr)
        data.extend(network)
        data.extend(self.gateway.packed)
        return last + 5

    def __repr__(self) -> str:
        return f"ClasslessRoute(gateway={self.gateway}, network={self.network})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ClasslessRoute):
            return NotImplemented
        return (self.gateway, self.network) == (other.gateway, other.network)

    def __json__(self) -> list[_ty.Any]:
        return [str(self.gateway), str(self.network)]


class _IPv4PairList(DhcpOptionType, list[tuple[_IP, _IP]]):
    _SECOND_LABEL: str = "second"

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> tuple[_IP, _IP]:
        left, right = item
        return _IP(left), _IP(right)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) % 8:
            raise ValueError(f"{cls.__name__} option is truncated: expected 8-byte records")
        self = cls()
        for idx in range(0, len(option), 8):
            left = _IP(option[idx : idx + 4].tobytes())
            right = _IP(option[idx + 4 : idx + 8].tobytes())
            self.append((left, right))
        return self, len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        for left, right in self:
            data.extend(left.packed)
            data.extend(right.packed)
        return len(self) * 8

    def append(self, item: _ty.Any) -> None:
        return list.append(self, self._normalize(item))

    def extend(self, __iterable: Iterable[_ty.Any]) -> None:
        list.extend(self, [self._normalize(item) for item in __iterable])

    def __json__(self) -> list[list[str]]:
        return [[str(left), str(right)] for left, right in self]


class PolicyFilter(_IPv4PairList):
    """List of IPv4 destination/mask pairs for policy filtering."""


class StaticRoute(_IPv4PairList):
    """List of IPv4 destination/router pairs for static routing."""

    @classmethod
    def _normalize(cls, item: _ty.Any) -> tuple[_IP, _IP]:
        left, right = super()._normalize(item)
        if left == _IP("0.0.0.0"):
            raise ValueError("StaticRoute does not allow a default-route destination")
        return left, right


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


class RdnssSelection(DhcpOptionType):
    """RFC 6731 RDNSS selection payload."""

    def __init__(self, flags: int, primary: _IP, secondary: _IP, domains: DomainList | None = None) -> None:
        self.flags = int(flags)
        self.primary = _IP(primary)
        self.secondary = _IP(secondary)
        self.domains = self._normalize_domains(domains or [])

    @staticmethod
    def _normalize_domains(domains: _ty.Iterable[str]) -> DomainList:
        normalized = DomainList(domains)
        if normalized and normalized[-1] == "":
            normalized.pop()
        return normalized

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 9:
            raise ValueError(f"{cls.__name__} option is truncated")
        flags = option[0]
        primary = _IP(option[1:5].tobytes())
        secondary = _IP(option[5:9].tobytes())
        domains, read = DomainList._dhcp_read(option[9:])
        return cls(flags, primary, secondary, domains), 9 + read

    def _dhcp_write(self, data: bytearray) -> int:
        encoded = self.domains._dhcp_encode()
        data.append(self.flags)
        data.extend(self.primary.packed)
        data.extend(self.secondary.packed)
        data.extend(encoded)
        return 9 + len(encoded)

    def __repr__(self) -> str:
        return (
            f"RdnssSelection(flags={self.flags!r}, primary={self.primary}, "
            f"secondary={self.secondary}, domains={self.domains!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RdnssSelection):
            return NotImplemented
        return (
            self.flags,
            self.primary,
            self.secondary,
            list(self.domains),
        ) == (
            other.flags,
            other.primary,
            other.secondary,
            list(other.domains),
        )

    def __json__(self) -> list[_ty.Any]:
        return [self.flags, str(self.primary), str(self.secondary), self.domains.__json__()]


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


class DomainList(DhcpOptionType, list[str]):
    """RFC 1035 domain-name list with compression support."""
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        view = memoryview(option)
        self = cls()
        if not option:
            return self, 0
        components: dict[int, str | int | None] = _ty.OrderedDict()
        domains: list[int] = [0]
        id = 0
        size = len(view)
        while id < size:
            ptr_or_len = view[id]
            id += 1
            if ptr_or_len == 0x00:
                components[id - 1] = None
                domains.append(id)
                continue
            is_ptr = ptr_or_len & 0xC0
            if is_ptr:
                if is_ptr != 0xC0:
                    raise ValueError()
                components[id - 1] = ((0x3F & ptr_or_len) << 8) | view[id]
                id += 1
            else:
                dc = view[id : ptr_or_len + id]
                if len(dc) != ptr_or_len:
                    raise ValueError()
                components[id - 1] = dc.tobytes().decode()
                id += ptr_or_len

        def get_dn(id: int) -> list[str]:
            result = []
            for idx, dc in components.items():
                if idx >= id:
                    if dc is None:
                        break
                    elif isinstance(dc, int):
                        result.extend(get_dn(dc))
                        break
                    result.append(dc)
            return result

        for domain in domains:
            self.append(".".join(get_dn(domain)))
        return self, len(option)

    def _dhcp_write(self, _data: bytearray) -> int:
        components: list[tuple[list[str], int]] = []
        data = bytearray()
        for domain_str in self:
            domain = domain_str.split(".")
            unique = domain
            parent: _ty.Optional[tuple[int, int]] = None
            for cn, cidx in components:
                pair = 1
                while pair < len(domain):
                    if domain[-pair:] != cn[-pair:]:
                        break
                    pair += 1
                pair -= 1
                if pair:
                    if parent:
                        _, _pair = parent
                        if pair <= _pair:
                            continue
                    for n in cn[:-pair]:
                        cidx += 1 + len(n)

                    parent = cidx, pair
                    unique = domain[:-pair]

            components.append((domain, len(data)))
            for comp in unique:
                data.append(len(comp))
                data.extend(comp.encode())
            if parent is None:
                data.append(0x00)
            else:
                data.extend((0xC000 | parent[0]).to_bytes(2, byteorder="big"))
        _data.extend(data)
        return len(data)


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
            from .enum import HardwareAddressType

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
