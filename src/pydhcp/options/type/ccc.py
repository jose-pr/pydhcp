from __future__ import annotations

import typing as _ty

from ...exceptions import DHCPDecodeError, DHCPValueError
from ... import network as _net
from .base import DHCPOptionType, List, RecordList, hashable_payload
from .domain import decode_domain_name, encode_domain_name
from .addresses import IPv4AddressOption
from .scalar import Boolean, Bytes, U8


def _encode_no_compression_domain(domain: str) -> bytes:
    return encode_domain_name(domain, "CCC domain name")


def _decode_no_compression_domain(
    option: memoryview, start: int = 0
) -> tuple[str, int]:
    return decode_domain_name(option, start, "CCC domain name")


_CCCDomainTextT = _ty.TypeVar("_CCCDomainTextT", bound="_CCCDomainText")


class _CCCDomainText(DHCPOptionType, str):
    """No-compression RFC 1035 domain text used by CCC sub-options."""

    def __new__(cls: type[_CCCDomainTextT], value: _ty.Any) -> _CCCDomainTextT:
        text = str(value)
        _encode_no_compression_domain(text)
        return str.__new__(cls, text)

    @classmethod
    def _dhcp_read(
        cls: type[_CCCDomainTextT], option: memoryview
    ) -> tuple[_CCCDomainTextT, int]:
        text, read = _decode_no_compression_domain(option)
        return cls(text), read

    def _dhcp_write(self, data: bytearray) -> int:
        encoded = _encode_no_compression_domain(str(self))
        data.extend(encoded)
        return len(encoded)

    def __json__(self) -> str:
        return str(self)


class CCCProvisioningServerFQDN(_CCCDomainText):
    """CCC provisioning server FQDN payload without DNS compression."""


_CCCKerberosRealmNameT = _ty.TypeVar(
    "_CCCKerberosRealmNameT", bound="CCCKerberosRealmName"
)


class CCCKerberosRealmName(_CCCDomainText):
    """CCC Kerberos realm payload without DNS compression."""

    def __new__(
        cls: type[_CCCKerberosRealmNameT], value: _ty.Any
    ) -> _CCCKerberosRealmNameT:
        return super().__new__(cls, str(value).upper())


class CCCProvisioningServerAddress(DHCPOptionType):
    """CCC sub-option 3 tagged union for IPv4 address or FQDN."""

    def __init__(self, value: _ty.Any) -> None:
        self.kind, self.value = self._normalize(value)

    @staticmethod
    def _normalize(value: _ty.Any) -> tuple[str, _ty.Any]:
        if isinstance(value, CCCProvisioningServerAddress):
            return value.kind, value.value
        if isinstance(value, (list, tuple)) and len(value) == 2:
            kind, payload = value
            kind_name = str(kind).lower()
            if kind_name in {"ipv4", "address"}:
                return "ipv4", IPv4AddressOption(payload)
            if kind_name in {"fqdn", "domain"}:
                return "fqdn", CCCProvisioningServerFQDN(payload)
            raise DHCPValueError(
                "CCC provisioning server address kind must be ipv4 or fqdn"
            )
        if isinstance(value, _net.IPv4):
            return "ipv4", IPv4AddressOption(value)
        if isinstance(value, str):
            try:
                return "ipv4", IPv4AddressOption(value)
            except ValueError:
                # `ValueError` only: `ipaddress.AddressValueError` (its
                # subclass) is what a non-address string raises -- measured
                # across 'not-an-ip', '', 'www.example.com', '1.2.3.4.5' and
                # '999.1.1.1'. A bare `except Exception` also swallowed a
                # genuine defect in the codec and silently reclassified the
                # value as an FQDN.
                return "fqdn", CCCProvisioningServerFQDN(value)
        if isinstance(value, CCCProvisioningServerFQDN):
            return "fqdn", value
        return "ipv4", IPv4AddressOption(value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> "CCCProvisioningServerAddress":
        if len(payload) < 1:
            raise DHCPDecodeError("CCC provisioning server address is truncated")
        kind = payload[0]
        if kind == 1:
            if len(payload) != 5:
                raise DHCPDecodeError(
                    "CCC provisioning server IPv4 payload must be 5 bytes"
                )
            return cls(("ipv4", IPv4AddressOption(payload[1:5].tobytes())))
        if kind == 0:
            text, read = _decode_no_compression_domain(payload, 1)
            if 1 + read != len(payload):
                raise DHCPDecodeError(
                    "CCC provisioning server FQDN payload is truncated"
                )
            return cls(("fqdn", CCCProvisioningServerFQDN(text)))
        raise DHCPDecodeError(
            f"CCC provisioning server address kind {kind} is unsupported"
        )

    @classmethod
    def _dhcp_read(
        cls, option: memoryview
    ) -> tuple["CCCProvisioningServerAddress", int]:
        return cls._read_payload(option), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        data.append(1 if self.kind == "ipv4" else 0)
        if self.kind == "ipv4":
            ipv4_payload = _ty.cast(IPv4AddressOption, self.value)
            data.extend(ipv4_payload.packed)
            return 5
        fqdn_payload = _ty.cast(CCCProvisioningServerFQDN, self.value)
        encoded = fqdn_payload._dhcp_encode()
        data.extend(encoded)
        return len(encoded) + 1

    def __repr__(self) -> str:
        return f"{type(self).__name__}(kind={self.kind!r}, value={self.value!r})"

    def __json__(self) -> list[_ty.Any]:
        return [
            self.kind,
            (
                self.value.__json__()
                if isinstance(self.value, DHCPOptionType)
                else str(self.value)
            ),
        ]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CCCProvisioningServerAddress):
            return NotImplemented
        return (self.kind, self.value) == (other.kind, other.value)

    def __hash__(self) -> int:
        return hash((self.kind, self.value))


class CCCPrimaryDHCPServerAddress(IPv4AddressOption):
    """CCC sub-option 1 primary DHCP server address."""


class CCCSecondaryDHCPServerAddress(IPv4AddressOption):
    """CCC sub-option 2 secondary DHCP server address."""


_CCCASBackoffRetryT = _ty.TypeVar("_CCCASBackoffRetryT", bound="CCCASBackoffRetry")


class CCCASBackoffRetry(DHCPOptionType):
    """CCC sub-option 4 AS-REQ/AS-REP backoff and retry tuple."""

    def __init__(
        self,
        initial_timeout: _ty.Any,
        maximum_timeout: _ty.Any,
        maximum_retry_count: _ty.Any,
    ) -> None:
        self.initial_timeout = int(initial_timeout)
        self.maximum_timeout = int(maximum_timeout)
        self.maximum_retry_count = int(maximum_retry_count)

    @classmethod
    def _dhcp_read(
        cls: type[_CCCASBackoffRetryT], option: memoryview
    ) -> tuple[_CCCASBackoffRetryT, int]:
        if len(option) != 12:
            raise DHCPDecodeError(f"{cls.__name__} option must contain 12 bytes")
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
        if not isinstance(other, CCCASBackoffRetry):
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

    def __hash__(self) -> int:
        return hash(
            (self.initial_timeout, self.maximum_timeout, self.maximum_retry_count)
        )

    def __json__(self) -> list[int]:
        return [self.initial_timeout, self.maximum_timeout, self.maximum_retry_count]


class CCCAPBackoffRetry(CCCASBackoffRetry):
    """CCC sub-option 5 AP-REQ/AP-REP backoff and retry tuple."""


class CCCTicketGrantingServerUtilization(Boolean):
    """CCC sub-option 7 ticket-granting server utilization toggle."""


class CCCProvisioningTimer(U8):
    """CCC sub-option 8 provisioning timer value."""


_CCCSecurityTicketControlT = _ty.TypeVar(
    "_CCCSecurityTicketControlT", bound="CCCSecurityTicketControl"
)


class CCCSecurityTicketControl(DHCPOptionType, int):
    """CCC sub-option 9 security ticket control mask."""

    def __new__(
        cls: type[_CCCSecurityTicketControlT], value: _ty.Any
    ) -> _CCCSecurityTicketControlT:
        return int.__new__(cls, int(value))

    @classmethod
    def _dhcp_read(
        cls: type[_CCCSecurityTicketControlT], option: memoryview
    ) -> tuple[_CCCSecurityTicketControlT, int]:
        if len(option) != 2:
            raise DHCPDecodeError(f"{cls.__name__} option must contain 2 bytes")
        return cls(int.from_bytes(option, "big")), 2

    def _dhcp_write(self, data: bytearray) -> int:
        if self < 0 or self > 0xFFFF:
            raise DHCPValueError(f"{type(self).__name__} mask must fit in 16 bits")
        if int(self) & ~0x0003:
            raise DHCPValueError(
                f"{type(self).__name__} reserved bits 2-15 must be zero"
            )
        data.extend(int(self).to_bytes(2, "big"))
        return 2

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)!r})"

    def __json__(self) -> int:
        return int(self)


class CCCKDCServerAddressList(List[IPv4AddressOption]):
    """CCC sub-option 10 KDC server address list."""


_CCCSubOptionT = _ty.TypeVar("_CCCSubOptionT", bound="CCCSubOption")


class CCCSubOption(DHCPOptionType):
    """Typed CCC sub-option record."""

    _PAYLOAD_TYPE: type[DHCPOptionType] = Bytes

    def __init__(self, code: int, value: _ty.Any) -> None:
        self.code = int(code)
        self.value = self._normalize_value(self.code, value)

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if isinstance(value, DHCPOptionType):
            return value
        return Bytes(value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        return Bytes(payload)

    def _write_payload(self, data: bytearray) -> int:
        payload = self.value
        if isinstance(payload, DHCPOptionType):
            return payload._dhcp_write(data)
        payload_bytes = Bytes(payload)
        data.extend(payload_bytes)
        return len(payload_bytes)

    @classmethod
    def _from_payload(
        cls: type[_CCCSubOptionT], code: int, payload: memoryview
    ) -> _CCCSubOptionT:
        return cls(code, cls._read_payload(payload))

    def _dhcp_write(self, data: bytearray) -> int:
        payload = bytearray()
        payload_len = self._write_payload(payload)
        if payload_len > 255:
            raise DHCPValueError(f"{type(self).__name__} entry exceeds 255 bytes")
        data.append(self.code)
        data.append(payload_len)
        data.extend(payload)
        return payload_len + 2

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, value={self.value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CCCSubOption):
            return NotImplemented
        return (self.code, self.value) == (other.code, other.value)

    def __hash__(self) -> int:
        return hash((self.code, hashable_payload(self.value)))

    def __json__(self) -> list[_ty.Any]:
        value = self.value
        if isinstance(value, DHCPOptionType):
            value = value.__json__()
        else:
            value = Bytes(value).__json__()
        return [self.code, value]


class _CCCFixedPayloadSubOption(CCCSubOption):
    _PAYLOAD_TYPE: type[DHCPOptionType] = Bytes

    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if isinstance(value, cls._PAYLOAD_TYPE):
            return value
        if isinstance(value, (list, tuple)):
            return cls._PAYLOAD_TYPE(*value)
        return cls._PAYLOAD_TYPE(value)  # type: ignore[call-arg]

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        return cls._PAYLOAD_TYPE._dhcp_decode(payload)

    def _write_payload(self, data: bytearray) -> int:
        return _ty.cast(DHCPOptionType, self.value)._dhcp_write(data)


class CCCPrimaryDHCPServerAddressSubOption(_CCCFixedPayloadSubOption):
    _PAYLOAD_TYPE = CCCPrimaryDHCPServerAddress


class CCCSecondaryDHCPServerAddressSubOption(_CCCFixedPayloadSubOption):
    _PAYLOAD_TYPE = CCCSecondaryDHCPServerAddress


class CCCProvisioningServerAddressSubOption(CCCSubOption):
    @classmethod
    def _normalize_value(cls, code: int, value: _ty.Any) -> _ty.Any:
        if isinstance(value, CCCProvisioningServerAddress):
            return value
        return CCCProvisioningServerAddress(value)

    @classmethod
    def _read_payload(cls, payload: memoryview) -> _ty.Any:
        return CCCProvisioningServerAddress._dhcp_decode(payload)

    def _write_payload(self, data: bytearray) -> int:
        return _ty.cast(CCCProvisioningServerAddress, self.value)._dhcp_write(data)


class CCCASBackoffRetrySubOption(_CCCFixedPayloadSubOption):
    _PAYLOAD_TYPE = CCCASBackoffRetry


class CCCAPBackoffRetrySubOption(_CCCFixedPayloadSubOption):
    _PAYLOAD_TYPE = CCCAPBackoffRetry


class CCCKerberosRealmNameSubOption(_CCCFixedPayloadSubOption):
    _PAYLOAD_TYPE = CCCKerberosRealmName


class CCCTicketGrantingServerUtilizationSubOption(_CCCFixedPayloadSubOption):
    _PAYLOAD_TYPE = CCCTicketGrantingServerUtilization


class CCCProvisioningTimerSubOption(_CCCFixedPayloadSubOption):
    _PAYLOAD_TYPE = CCCProvisioningTimer


class CCCSecurityTicketControlSubOption(_CCCFixedPayloadSubOption):
    _PAYLOAD_TYPE = CCCSecurityTicketControl


class CCCKDCServerAddressSubOption(_CCCFixedPayloadSubOption):
    _PAYLOAD_TYPE = CCCKDCServerAddressList


_CCC_SUBOPTION_TYPES: dict[int, type[CCCSubOption]] = {
    1: CCCPrimaryDHCPServerAddressSubOption,
    2: CCCSecondaryDHCPServerAddressSubOption,
    3: CCCProvisioningServerAddressSubOption,
    4: CCCASBackoffRetrySubOption,
    5: CCCAPBackoffRetrySubOption,
    6: CCCKerberosRealmNameSubOption,
    7: CCCTicketGrantingServerUtilizationSubOption,
    8: CCCProvisioningTimerSubOption,
    9: CCCSecurityTicketControlSubOption,
    10: CCCKDCServerAddressSubOption,
}


_CCCOptionT = _ty.TypeVar("_CCCOptionT", bound="CCCOption")


class CCCOption(RecordList[CCCSubOption]):
    """CCC option container preserving unknown sub-options."""

    @classmethod
    def _normalize(cls, item: _ty.Any) -> CCCSubOption:
        # Its own, because the record class is chosen by the sub-option code
        # rather than fixed for the container: an unknown code must still round
        # trip, as the plain `CCCSubOption` fallback.
        if isinstance(item, CCCSubOption):
            return item
        code, value = item
        record_type = _CCC_SUBOPTION_TYPES.get(int(code), CCCSubOption)
        return record_type(int(code), value)

    @classmethod
    def _read_record(cls, option: memoryview) -> tuple[CCCSubOption, int]:
        if len(option) < 2:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        code = option[0]
        length = option[1]
        if len(option) < 2 + length:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        payload = option[2 : 2 + length]
        record_type = _CCC_SUBOPTION_TYPES.get(code, CCCSubOption)
        return record_type._from_payload(code, payload), 2 + length

    @classmethod
    def _dhcp_read(
        cls: type[_CCCOptionT], option: memoryview
    ) -> tuple[_CCCOptionT, int]:
        # Its own, because each record's class comes from `_read_record`'s code
        # lookup, not from the container's item type.
        self = cls()
        idx = 0
        size = len(option)
        while idx < size:
            record, read = cls._read_record(option[idx:])
            self.append(record)
            idx += read
        return self, size
