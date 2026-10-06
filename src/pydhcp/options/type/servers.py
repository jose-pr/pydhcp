"""Server-locator and status option codecs: RDNSS selection, SIP and PCP servers, status codes."""

from __future__ import annotations

import typing as _ty
from ...exceptions import DHCPDecodeError, DHCPValueError
from ... import nvt as _nvt
from ipaddress import IPv4Address as _IP
from .base import DHCPOptionType
from .domain import decode_domain_name, encode_domain_name
from collections.abc import Iterable


from .domains import UncompressedDomainList

_RDNSSSelectionT = _ty.TypeVar("_RDNSSSelectionT", bound="RDNSSSelection")


class RDNSSSelection(DHCPOptionType):
    """RFC 6731 RDNSS selection payload."""

    def __init__(
        self,
        flags: int,
        primary: _IP,
        secondary: _IP,
        domains: _ty.Any = None,
    ) -> None:
        self.flags = int(flags)
        self.primary = _IP(primary)
        self.secondary = _IP(secondary)
        self.domains = self._normalize_domains(domains or [])

    @staticmethod
    def _normalize_domains(domains: _ty.Any) -> UncompressedDomainList:
        # Uncompressed: RFC 6731 §4.3 defers to RFC 3315 §8, which forbids the
        # compressed form. A bare `str` is one domain here, not one per
        # character -- see `DomainList`.
        normalized = UncompressedDomainList(domains)
        if normalized and normalized[-1] == "":
            normalized.pop()
        return normalized

    @classmethod
    def _dhcp_read(
        cls: type[_RDNSSSelectionT], option: memoryview
    ) -> tuple[_RDNSSSelectionT, int]:
        if len(option) < 9:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        flags = option[0]
        primary = _IP(option[1:5].tobytes())
        secondary = _IP(option[5:9].tobytes())
        domains, read = UncompressedDomainList._dhcp_read(option[9:])
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
            f"RDNSSSelection(flags={self.flags!r}, primary={self.primary}, "
            f"secondary={self.secondary}, domains={self.domains!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RDNSSSelection):
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

    def __hash__(self) -> int:
        return hash((self.flags, self.primary, self.secondary, tuple(self.domains)))

    def __json__(self) -> list[_ty.Any]:
        return [
            self.flags,
            str(self.primary),
            str(self.secondary),
            self.domains.__json__(),
        ]


_SIPServersT = _ty.TypeVar("_SIPServersT", bound="SIPServers")


class SIPServers(DHCPOptionType):
    """RFC 3361 SIP servers: an encoding octet, then names or addresses.

    Encoding 0 is a list of RFC 1035 names, encoding 1 a list of IPv4 addresses.
    Registering this as a bare address list meant a conformant option could not
    be decoded at all, and an emitted one had no encoding octet -- so a SIP phone
    read the first address octet as the encoding and rejected the option.
    """

    ENCODING_DOMAIN = 0
    ENCODING_ADDRESS = 1

    # See ClientFQDN: declared to keep mypy out of a circular inference.
    encoding: int
    values: list[str]

    def __init__(
        self, values: _ty.Any = (), encoding: _ty.Optional[int] = None
    ) -> None:
        if isinstance(values, SIPServers):
            values, encoding = list(values.values), values.encoding
        elif isinstance(values, _ty.Mapping):
            mapping = values
            values = mapping.get("values", ())
            raw_encoding = mapping.get("encoding")
            if isinstance(raw_encoding, str):
                raw_encoding = (
                    self.ENCODING_ADDRESS
                    if raw_encoding == "address"
                    else self.ENCODING_DOMAIN
                )
            encoding = raw_encoding
        if isinstance(values, (str, bytes)):
            values = [values]
        items = [str(value) for value in values]
        if encoding is None:
            # Infer, so SIPServers(["192.0.2.1"]) does the obvious thing.
            encoding = self.ENCODING_ADDRESS
            for item in items:
                try:
                    _IP(item)
                except Exception:
                    encoding = self.ENCODING_DOMAIN
                    break
        if encoding not in (self.ENCODING_DOMAIN, self.ENCODING_ADDRESS):
            raise DHCPValueError(f"SIPServers encoding must be 0 or 1, got {encoding}")
        if encoding == self.ENCODING_ADDRESS:
            items = [str(_IP(item)) for item in items]
        self.encoding = int(encoding)
        self.values = items

    @classmethod
    def _dhcp_read(
        cls: type[_SIPServersT], option: memoryview
    ) -> tuple[_SIPServersT, int]:
        if len(option) < 1:
            raise DHCPDecodeError(
                "SIPServers option is truncated: missing encoding octet"
            )
        encoding = option[0]
        body = option[1:]
        if encoding == cls.ENCODING_ADDRESS:
            if len(body) % 4:
                raise DHCPDecodeError(
                    "SIPServers address list length must be a multiple of 4 plus one"
                )
            values = [
                str(_IP(body[idx : idx + 4].tobytes()))
                for idx in range(0, len(body), 4)
            ]
        elif encoding == cls.ENCODING_DOMAIN:
            values = []
            idx = 0
            while idx < len(body):
                name, read = decode_domain_name(body, idx, "SIPServers name")
                values.append(name)
                idx += read
        else:
            raise DHCPDecodeError(f"SIPServers encoding must be 0 or 1, got {encoding}")
        return cls(values, encoding), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        start = len(data)
        data.append(self.encoding)
        if self.encoding == self.ENCODING_ADDRESS:
            for value in self.values:
                data.extend(_IP(value).packed)
        else:
            for value in self.values:
                data.extend(encode_domain_name(value, "SIPServers name"))
        return len(data) - start

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SIPServers):
            return NotImplemented
        return (self.encoding, self.values) == (other.encoding, other.values)

    def __hash__(self) -> int:
        return hash((self.encoding, tuple(self.values)))

    def __repr__(self) -> str:
        kind = "address" if self.encoding == self.ENCODING_ADDRESS else "domain"
        return f"SIPServers({kind}, {self.values!r})"

    def __json__(self) -> dict[str, _ty.Any]:
        return {
            "encoding": (
                "address" if self.encoding == self.ENCODING_ADDRESS else "domain"
            ),
            "values": list(self.values),
        }


_StatusCodeT = _ty.TypeVar("_StatusCodeT", bound="StatusCode")


class StatusCode(DHCPOptionType):
    """RFC 6926 s6.2.2 status: one code octet, then an optional UTF-8 message.

    Registered as a bare `U8` the message made the option the wrong size, so a
    DHCPLEASEQUERY reply carrying one could not be decoded at all.
    """

    code: int
    message: str

    def __init__(self, code: _ty.Any = 0, message: _ty.Any = "") -> None:
        if isinstance(code, StatusCode):
            code, message = code.code, code.message
        elif isinstance(code, _ty.Mapping):
            mapping = code
            code = mapping.get("code", 0)
            message = mapping.get("message", message)
        elif isinstance(code, (tuple, list)) and len(code) == 2:
            code, message = code
        value = int(code)
        if not 0 <= value <= 255:
            raise DHCPValueError(f"StatusCode code must fit one octet, got {value}")
        self.code = value
        self.message = str(message or "")

    @classmethod
    def _dhcp_read(
        cls: type[_StatusCodeT], option: memoryview
    ) -> tuple[_StatusCodeT, int]:
        if len(option) < 1:
            raise DHCPDecodeError("StatusCode option is truncated: missing code octet")
        message = _nvt.decode(option[1:].tobytes(), "StatusCode message")
        return cls(option[0], message), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        encoded = _nvt.encode(self.message)
        data.append(self.code)
        data.extend(encoded)
        return 1 + len(encoded)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, StatusCode):
            return NotImplemented
        return (self.code, self.message) == (other.code, other.message)

    def __hash__(self) -> int:
        return hash((self.code, self.message))

    def __repr__(self) -> str:
        return f"StatusCode(code={self.code}, message={self.message!r})"

    def __json__(self) -> dict[str, _ty.Any]:
        return {"code": self.code, "message": _nvt.display(self.message)}


_PCPServerListT = _ty.TypeVar("_PCPServerListT", bound="PCPServerList")


class PCPServerList(DHCPOptionType, list[list[str]]):
    """RFC 7291 s4 PCP servers: one or more length-prefixed address lists.

    Each entry is a List-Length octet giving the octet count, then that many
    octets of IPv4 addresses; separate entries are separate PCP servers.
    Registered as a flat `List[IPv4AddressOption]` the length octet was read as
    address data, so a conformant option raised and an emitted one carried no
    length octet at all.
    """

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], (list, tuple)):
            entries = list(items[0])
            # PCPServerList(["192.0.2.1"]) means one server, not an entry of
            # nothing -- accept the flat spelling people will reach for.
            if entries and not isinstance(entries[0], (list, tuple)):
                entries = [entries]
        else:
            entries = list(items)
        for entry in entries:
            self.append(entry)

    @staticmethod
    def _normalize(entry: _ty.Any) -> list[str]:
        if isinstance(entry, (str, _IP)):
            entry = [entry]
        addresses = [str(_IP(address)) for address in entry]
        if not addresses:
            raise DHCPValueError("PCPServerList entry must hold at least one address")
        return addresses

    def append(self, entry: _ty.Any) -> None:
        list.append(self, self._normalize(entry))

    def extend(self, __iterable: Iterable[_ty.Any]) -> None:
        list.extend(self, [self._normalize(entry) for entry in __iterable])

    @classmethod
    def _dhcp_read(
        cls: type[_PCPServerListT], option: memoryview
    ) -> tuple[_PCPServerListT, int]:
        self = cls()
        idx = 0
        while idx < len(option):
            length = option[idx]
            idx += 1
            if length == 0 or length % 4:
                raise DHCPDecodeError(
                    "PCPServerList entry length must be a non-zero multiple of 4, "
                    f"got {length}"
                )
            if idx + length > len(option):
                raise DHCPDecodeError("PCPServerList option is truncated")
            self.append(
                [
                    str(_IP(option[pos : pos + 4].tobytes()))
                    for pos in range(idx, idx + length, 4)
                ]
            )
            idx += length
        if not self:
            raise DHCPDecodeError("PCPServerList option is empty")
        return self, len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for entry in self:
            data.append(len(entry) * 4)
            written += 1
            for address in entry:
                data.extend(_IP(address).packed)
                written += 4
        return written

    def __json__(self) -> list[list[str]]:
        return [list(entry) for entry in self]
