from __future__ import annotations

import typing as _ty

from . import netutils as _net
from .optiontype import Boolean, Bytes, DhcpOptionType, IPv4Address, List, U8

if _ty.TYPE_CHECKING:
    from typing_extensions import Self


def _encode_no_compression_domain(domain: str) -> bytes:
    labels = domain.split(".")
    if not labels or any(not label for label in labels):
        raise ValueError("CCC domain names must not contain empty labels")
    data = bytearray()
    for label in labels:
        label_bytes = label.encode("utf-8")
        if len(label_bytes) > 63:
            raise ValueError("CCC domain label exceeds 63 bytes")
        data.append(len(label_bytes))
        data.extend(label_bytes)
    data.append(0)
    return bytes(data)


def _decode_no_compression_domain(option: memoryview, start: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    idx = start
    size = len(option)
    while True:
        if idx >= size:
            raise ValueError("CCC domain name is truncated")
        length = option[idx]
        idx += 1
        if length == 0:
            return ".".join(labels), idx - start
        if idx + length > size:
            raise ValueError("CCC domain name is truncated")
        labels.append(option[idx : idx + length].tobytes().decode("utf-8"))
        idx += length


class _CccDomainText(DhcpOptionType, str):
    """No-compression RFC 1035 domain text used by CCC sub-options."""

    def __new__(cls, value: _ty.Any) -> Self:
        text = str(value)
        _encode_no_compression_domain(text)
        return str.__new__(cls, text)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        text, read = _decode_no_compression_domain(option)
        return cls(text), read

    def _dhcp_write(self, data: bytearray) -> int:
        encoded = _encode_no_compression_domain(str(self))
        data.extend(encoded)
        return len(encoded)

    def __json__(self) -> str:
        return str(self)


class CccProvisioningServerFqdn(_CccDomainText):
    """CCC provisioning server FQDN payload without DNS compression."""


class CccKerberosRealmName(_CccDomainText):
    """CCC Kerberos realm payload without DNS compression."""

    def __new__(cls, value: _ty.Any) -> Self:
        return super().__new__(cls, str(value).upper())


class CccProvisioningServerAddress(DhcpOptionType):
    """CCC sub-option 3 tagged union for IPv4 address or FQDN."""

    def __init__(self, value: _ty.Any) -> None:
        self.kind, self.value = self._normalize(value)

    @staticmethod
    def _normalize(value: _ty.Any) -> tuple[str, _ty.Any]:
        if isinstance(value, CccProvisioningServerAddress):
            return value.kind, value.value
        if isinstance(value, (list, tuple)) and len(value) == 2:
            kind, payload = value
            kind_name = str(kind).lower()
            if kind_name in {"ipv4", "address"}:
                return "ipv4", IPv4Address(payload)
            if kind_name in {"fqdn", "domain"}:
                return "fqdn", CccProvisioningServerFqdn(payload)
            raise ValueError("CCC provisioning server address kind must be ipv4 or fqdn")
        if isinstance(value, _net.IPv4):
            return "ipv4", IPv4Address(value)
        if isinstance(value, str):
            try:
                return "ipv4", IPv4Address(value)
            except Exception:
                return "fqdn", CccProvisioningServerFqdn(value)
        if isinstance(value, CccProvisioningServerFqdn):
            return "fqdn", value
        return "ipv4", IPv4Address(value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> "CccProvisioningServerAddress":
        if len(payload) < 1:
            raise ValueError("CCC provisioning server address is truncated")
        kind = payload[0]
        if kind == 1:
            if len(payload) != 5:
                raise ValueError("CCC provisioning server IPv4 payload must be 5 bytes")
            return cls(("ipv4", IPv4Address(payload[1:5].tobytes())))
        if kind == 0:
            text, read = _decode_no_compression_domain(payload, 1)
            if 1 + read != len(payload):
                raise ValueError("CCC provisioning server FQDN payload is truncated")
            return cls(("fqdn", CccProvisioningServerFqdn(text)))
        raise ValueError(f"CCC provisioning server address kind {kind} is unsupported")

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["CccProvisioningServerAddress", int]:
        return cls._read_payload(option), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        data.append(1 if self.kind == "ipv4" else 0)
        if self.kind == "ipv4":
            payload = _ty.cast(IPv4Address, self.value)
            data.extend(payload.packed)
            return 5
        payload = _ty.cast(CccProvisioningServerFqdn, self.value)
        encoded = payload._dhcp_encode()
        data.extend(encoded)
        return len(encoded) + 1

    def __repr__(self) -> str:
        return f"{type(self).__name__}(kind={self.kind!r}, value={self.value!r})"

    def __json__(self) -> list[_ty.Any]:
        return [self.kind, self.value.__json__() if isinstance(self.value, DhcpOptionType) else str(self.value)]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CccProvisioningServerAddress):
            return NotImplemented
        return (self.kind, self.value) == (other.kind, other.value)


class CccPrimaryDhcpServerAddress(IPv4Address):
    """CCC sub-option 1 primary DHCP server address."""


class CccSecondaryDhcpServerAddress(IPv4Address):
    """CCC sub-option 2 secondary DHCP server address."""


class CccAsReqAsRepBackoffRetry(DhcpOptionType):
    """CCC sub-option 4 AS-REQ/AS-REP backoff and retry tuple."""

    def __init__(self, initial_timeout: _ty.Any, maximum_timeout: _ty.Any, maximum_retry_count: _ty.Any) -> None:
        self.initial_timeout = int(initial_timeout)
        self.maximum_timeout = int(maximum_timeout)
        self.maximum_retry_count = int(maximum_retry_count)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) != 12:
            raise ValueError(f"{cls.__name__} option must contain 12 bytes")
        return (
            cls(
                int.from_bytes(option[0:4], "big"),
                int.from_bytes(option[4:8], "big"),
                int.from_bytes(option[8:12], "big"),
            ),
            12,
        )

    def _dhcp_write(self, data: bytearray) -> int:
        data.extend(self.initial_timeout.to_bytes(4, "big"))
        data.extend(self.maximum_timeout.to_bytes(4, "big"))
        data.extend(self.maximum_retry_count.to_bytes(4, "big"))
        return 12

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(initial_timeout={self.initial_timeout!r}, "
            f"maximum_timeout={self.maximum_timeout!r}, "
            f"maximum_retry_count={self.maximum_retry_count!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CccAsReqAsRepBackoffRetry):
            return NotImplemented
        return (
            self.initial_timeout,
            self.maximum_timeout,
            self.maximum_retry_count,
        ) == (
            other.initial_timeout,
            other.maximum_timeout,
            other.maximum_retry_count,
        )

    def __json__(self) -> list[int]:
        return [self.initial_timeout, self.maximum_timeout, self.maximum_retry_count]


class CccApReqApRepBackoffRetry(CccAsReqAsRepBackoffRetry):
    """CCC sub-option 5 AP-REQ/AP-REP backoff and retry tuple."""


class CccTicketGrantingServerUtilization(Boolean):
    """CCC sub-option 7 ticket-granting server utilization toggle."""


class CccProvisioningTimer(U8):
    """CCC sub-option 8 provisioning timer value."""


class CccSecurityTicketControl(DhcpOptionType, int):
    """CCC sub-option 9 security ticket control mask."""

    def __new__(cls, value: _ty.Any) -> Self:
        return int.__new__(cls, int(value))

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) != 2:
            raise ValueError(f"{cls.__name__} option must contain 2 bytes")
        return cls(int.from_bytes(option, "big")), 2

    def _dhcp_write(self, data: bytearray) -> int:
        if self < 0 or self > 0xFFFF:
            raise ValueError(f"{type(self).__name__} mask must fit in 16 bits")
        if int(self) & ~0x0003:
            raise ValueError(f"{type(self).__name__} reserved bits 2-15 must be zero")
        data.extend(int(self).to_bytes(2, "big"))
        return 2

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)!r})"

    def __json__(self) -> int:
        return int(self)


class CccKdcServerAddressList(List[IPv4Address]):
    """CCC sub-option 10 KDC server address list."""


class CccSubOption(DhcpOptionType):
    """Typed CCC sub-option record."""

    _PAYLOAD_TYPE: type[DhcpOptionType] = Bytes

    def __init__(self, code: int, value: _ty.Any) -> None:
        self.code = int(code)
        self.value = self._normalize_value(self.code, value)

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if isinstance(value, DhcpOptionType):
            return value
        return Bytes(value)

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

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, value={self.value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CccSubOption):
            return NotImplemented
        return (self.code, self.value) == (other.code, other.value)

    def __json__(self) -> list[_ty.Any]:
        value = self.value
        if isinstance(value, DhcpOptionType):
            value = value.__json__()
        else:
            value = Bytes(value).__json__()
        return [self.code, value]


class _CccFixedPayloadSubOption(CccSubOption):
    _PAYLOAD_TYPE: type[DhcpOptionType] = Bytes

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if isinstance(value, cls._PAYLOAD_TYPE):
            return value
        if isinstance(value, (list, tuple)):
            return cls._PAYLOAD_TYPE(*value)
        return cls._PAYLOAD_TYPE(value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        return cls._PAYLOAD_TYPE._dhcp_decode(payload)

    def _write_payload(self, data: bytearray) -> int:
        return _ty.cast(DhcpOptionType, self.value)._dhcp_write(data)


class CccPrimaryDhcpServerAddressSubOption(_CccFixedPayloadSubOption):
    _PAYLOAD_TYPE = CccPrimaryDhcpServerAddress


class CccSecondaryDhcpServerAddressSubOption(_CccFixedPayloadSubOption):
    _PAYLOAD_TYPE = CccSecondaryDhcpServerAddress


class CccProvisioningServerAddressSubOption(CccSubOption):
    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if isinstance(value, CccProvisioningServerAddress):
            return value
        return CccProvisioningServerAddress(value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        return CccProvisioningServerAddress._dhcp_decode(payload)

    def _write_payload(self, data: bytearray) -> int:
        return _ty.cast(CccProvisioningServerAddress, self.value)._dhcp_write(data)


class CccAsReqAsRepBackoffRetrySubOption(_CccFixedPayloadSubOption):
    _PAYLOAD_TYPE = CccAsReqAsRepBackoffRetry


class CccApReqApRepBackoffRetrySubOption(_CccFixedPayloadSubOption):
    _PAYLOAD_TYPE = CccApReqApRepBackoffRetry


class CccKerberosRealmNameSubOption(_CccFixedPayloadSubOption):
    _PAYLOAD_TYPE = CccKerberosRealmName


class CccTicketGrantingServerUtilizationSubOption(_CccFixedPayloadSubOption):
    _PAYLOAD_TYPE = CccTicketGrantingServerUtilization


class CccProvisioningTimerSubOption(_CccFixedPayloadSubOption):
    _PAYLOAD_TYPE = CccProvisioningTimer


class CccSecurityTicketControlSubOption(_CccFixedPayloadSubOption):
    _PAYLOAD_TYPE = CccSecurityTicketControl


class CccKdcServerAddressSubOption(_CccFixedPayloadSubOption):
    _PAYLOAD_TYPE = CccKdcServerAddressList


_CCC_SUBOPTION_TYPES: dict[int, type[CccSubOption]] = {
    1: CccPrimaryDhcpServerAddressSubOption,
    2: CccSecondaryDhcpServerAddressSubOption,
    3: CccProvisioningServerAddressSubOption,
    4: CccAsReqAsRepBackoffRetrySubOption,
    5: CccApReqApRepBackoffRetrySubOption,
    6: CccKerberosRealmNameSubOption,
    7: CccTicketGrantingServerUtilizationSubOption,
    8: CccProvisioningTimerSubOption,
    9: CccSecurityTicketControlSubOption,
    10: CccKdcServerAddressSubOption,
}


class CccOption(DhcpOptionType, list[CccSubOption]):
    """CCC option container preserving unknown sub-options."""

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> CccSubOption:
        if isinstance(item, CccSubOption):
            return item
        code, value = item
        record_type = _CCC_SUBOPTION_TYPES.get(int(code), CccSubOption)
        return record_type(int(code), value)

    def append(self, item: _ty.Any) -> None:
        return list.append(self, self._normalize(item))

    def extend(self, __iterable: _ty.Iterable[_ty.Any]) -> None:
        list.extend(self, [self._normalize(item) for item in __iterable])

    @classmethod
    def _read_record(cls, option: memoryview) -> tuple[CccSubOption, int]:
        if len(option) < 2:
            raise ValueError(f"{cls.__name__} option is truncated")
        code = option[0]
        length = option[1]
        if len(option) < 2 + length:
            raise ValueError(f"{cls.__name__} option is truncated")
        payload = option[2 : 2 + length]
        record_type = _CCC_SUBOPTION_TYPES.get(code, CccSubOption)
        return record_type._from_payload(code, payload), 2 + length

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        self = cls()
        idx = 0
        size = len(option)
        while idx < size:
            record, read = cls._read_record(option[idx:])
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
