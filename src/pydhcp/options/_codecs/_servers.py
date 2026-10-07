"""Server-locator and status option codecs: RDNSS selection, SIP and PCP servers, status codes."""

from __future__ import annotations

import typing as _ty
from ...exceptions import DHCPDecodeError, DHCPValueError
from ... import _nvt as _nvt
from ipaddress import IPv4Address as _IP
from ._base import (
    _NormalizedList,
    _Record,
    _set,
    _TextForm,
    _text_argument,
    frozen,
)
from ._domain import encode_domain_name


from ._domains import UncompressedDomainList, read_names

_RDNSSSelectionT = _ty.TypeVar("_RDNSSSelectionT", bound="RDNSSSelection")


class RDNSSSelection(_Record):
    """RFC 6731 RDNSS selection payload."""

    __slots__ = ("flags", "primary", "secondary", "domains")
    _FIELDS = __slots__

    #: The two low bits, the preference; the other six are reserved.
    PREFERENCE_BITS = 0x03

    flags: int
    primary: _IP
    secondary: _IP
    domains: UncompressedDomainList

    def __init__(
        self,
        flags: _ty.Any,
        primary: _ty.Any = None,
        secondary: _ty.Any = None,
        domains: _ty.Any = None,
    ) -> None:
        if isinstance(flags, RDNSSSelection):
            flags, primary, secondary, domains = (
                flags.flags,
                flags.primary,
                flags.secondary,
                flags.domains,
            )
        elif isinstance(flags, (list, tuple)):
            # What `to_json` emits: [flags, primary, secondary, domains].
            if len(flags) not in (3, 4):
                raise TypeError(
                    "RDNSSSelection takes (flags, primary, secondary, domains) "
                    f"or one such sequence, got {len(flags)} items"
                )
            flags, primary, secondary, domains = (*flags, None)[:4]
        if primary is None or secondary is None:
            raise TypeError("RDNSSSelection needs a primary and a secondary address")
        _set(self, "flags", int(flags))
        _set(self, "primary", _IP(primary))
        _set(self, "secondary", _IP(secondary))
        _set(self, "domains", frozen(self._normalize_domains(domains or [])))

    @staticmethod
    def _normalize_domains(domains: _ty.Any) -> UncompressedDomainList:
        # Uncompressed: RFC 6731 §4.3 defers to RFC 3315 §8, which forbids the
        # compressed form. A bare `str` is one domain here, not one per
        # character -- see `DomainList`. The root name ("" or ".") stays: it
        # marks the default RDNSS.
        return UncompressedDomainList(domains)

    @classmethod
    def unpack_from(
        cls: type[_RDNSSSelectionT], option: memoryview
    ) -> tuple[_RDNSSSelectionT, int]:
        if len(option) < 9:
            raise DHCPDecodeError(f"{cls.__name__} option is truncated")
        # The six high bits are reserved and ignored on receipt (RFC 6731 s4.3).
        flags = option[0] & cls.PREFERENCE_BITS
        primary = _IP(option[1:5].tobytes())
        secondary = _IP(option[5:9].tobytes())
        domains, read = UncompressedDomainList.unpack_from(option[9:])
        return cls(flags, primary, secondary, domains), 9 + read

    def pack_into(self, data: bytearray) -> int:
        encoded = self.domains.pack()
        data.append(self.flags)
        data.extend(self.primary.packed)
        data.extend(self.secondary.packed)
        data.extend(encoded)
        return 9 + len(encoded)

    def to_json(self) -> list[_ty.Any]:
        return [
            self.flags,
            str(self.primary),
            str(self.secondary),
            self.domains.to_json(),
        ]


_SIPServersT = _ty.TypeVar("_SIPServersT", bound="SIPServers")


class SIPServers(_Record):
    """RFC 3361 SIP servers: an encoding octet, then names or addresses.

    Encoding 0 is a list of RFC 1035 names, encoding 1 a list of IPv4 addresses.
    Registered as a bare address list, a conformant option could not be decoded
    at all, and an emitted one would have no encoding octet -- so a SIP phone
    would read the first address octet as the encoding and reject the option.
    """

    __slots__ = ("values", "encoding")
    _FIELDS = __slots__

    ENCODING_DOMAIN = 0
    ENCODING_ADDRESS = 1

    # See ClientFQDN: declared to keep mypy out of a circular inference.
    encoding: int
    values: tuple[str, ...]

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
        _set(self, "encoding", int(encoding))
        _set(self, "values", tuple(items))

    @classmethod
    def unpack_from(
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
            # Compression is read (RFC 3361 s3.1: clients MUST support it) and
            # never sent. A pointer counts from the encoding octet, the start
            # of the option data, as RFC 3397's counts from the start of its.
            values, complete = read_names(body, "SIPServers name list", base=1)
            if not complete:
                raise DHCPDecodeError("SIPServers name list is truncated")
        else:
            raise DHCPDecodeError(f"SIPServers encoding must be 0 or 1, got {encoding}")
        return cls(values, encoding), len(option)

    def pack_into(self, data: bytearray) -> int:
        if not self.values:
            raise DHCPValueError(
                "SIPServers needs at least one name or address (RFC 3361 section 3)"
            )
        start = len(data)
        data.append(self.encoding)
        if self.encoding == self.ENCODING_ADDRESS:
            for value in self.values:
                data.extend(_IP(value).packed)
        else:
            for value in self.values:
                data.extend(encode_domain_name(value, "SIPServers name"))
        return len(data) - start

    def display_text(self) -> str:
        kind = "address" if self.encoding == self.ENCODING_ADDRESS else "domain"
        return f"SIPServers({kind}, {list(self.values)!r})"

    def to_json(self) -> dict[str, _ty.Any]:
        return {
            "encoding": (
                "address" if self.encoding == self.ENCODING_ADDRESS else "domain"
            ),
            "values": list(self.values),
        }


_StatusCodeT = _ty.TypeVar("_StatusCodeT", bound="StatusCode")


class StatusCode(_Record, _TextForm):
    """RFC 6926 s6.2.2 status: one code octet, then an optional UTF-8 message.

    Registered as a bare `U8` the message made the option the wrong size, so a
    DHCPLEASEQUERY reply carrying one could not be decoded at all.
    """

    __slots__ = ("code", "message")
    _FIELDS = __slots__

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
        _set(self, "code", value)
        _set(self, "message", str(message or ""))

    def __str__(self) -> str:
        return f"{self.code} {self.message}" if self.message else str(self.code)

    @classmethod
    def parse(cls: type[_StatusCodeT], text: str) -> _StatusCodeT:
        """Build from ``"<code>"`` or ``"<code> <message>"``, the text `str()` produces.

        The message is everything after the first space. Raises `DHCPValueError`
        for a code that is not a number in 0-255.
        """
        digits, _, message = _text_argument(cls, text).partition(" ")
        if not (digits.isascii() and digits.isdigit()):
            raise DHCPValueError(
                f"not a status code, {text!r}: it starts with a number"
            )
        return cls(int(digits), message)

    @classmethod
    def unpack_from(
        cls: type[_StatusCodeT], option: memoryview
    ) -> tuple[_StatusCodeT, int]:
        if len(option) < 1:
            raise DHCPDecodeError("StatusCode option is truncated: missing code octet")
        message = _nvt.decode(option[1:].tobytes(), "StatusCode message")
        return cls(option[0], message), len(option)

    def pack_into(self, data: bytearray) -> int:
        encoded = _nvt.encode(self.message)
        data.append(self.code)
        data.extend(encoded)
        return 1 + len(encoded)

    def to_json(self) -> dict[str, _ty.Any]:
        return {"code": self.code, "message": _nvt.display(self.message)}


_PCPServerListT = _ty.TypeVar("_PCPServerListT", bound="PCPServerList")


class PCPServerList(_NormalizedList[list[str]]):
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

    @classmethod
    def _normalize(cls, entry: _ty.Any) -> list[str]:
        if isinstance(entry, (str, _IP)):
            entry = [entry]
        addresses = [str(_IP(address)) for address in entry]
        if not addresses:
            raise DHCPValueError("PCPServerList entry must hold at least one address")
        if len(addresses) > 63:
            raise DHCPValueError(
                f"PCPServerList entry holds {len(addresses)} addresses; "
                "its length octet allows at most 63"
            )
        return addresses

    @classmethod
    def unpack_from(
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

    def pack_into(self, data: bytearray) -> int:
        written = 0
        for entry in self:
            data.append(len(entry) * 4)
            written += 1
            for address in entry:
                data.extend(_IP(address).packed)
                written += 4
        return written

    def to_json(self) -> list[list[str]]:
        return [list(entry) for entry in self]
