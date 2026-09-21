from __future__ import annotations
from collections.abc import Iterable
import typing as _ty

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from ...network import IPv4 as _IP, IPv4Network as _Network
from .base import DhcpOptionType
from .domain import decode_domain_name, encode_domain_name, split_domain_name
from ... import nvt as _nvt


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
    """RFC 3442 classless static route entry.

    Accepts either ``ClasslessRoute(gateway, network)`` or a single
    ``(gateway, network)`` pair / existing instance, so that the option's list
    container can normalize routes coming from JSON, YAML or a config file.
    """

    # Declared here so the pair-accepting constructor below can read
    # `other.gateway` without mypy hitting a circular inference.
    gateway: _IP
    network: _Network

    def __init__(self, gateway: _ty.Any, network: _ty.Optional[_ty.Any] = None) -> None:
        gw: _ty.Any
        net: _ty.Any
        if network is not None:
            gw, net = gateway, network
        elif isinstance(gateway, ClasslessRoute):
            gw, net = gateway.gateway, gateway.network
        else:
            try:
                gw, net = gateway
            except (TypeError, ValueError):
                raise TypeError(
                    "ClasslessRoute takes (gateway, network) or a single "
                    f"(gateway, network) pair, got {gateway!r}"
                ) from None
        self.gateway = _IP(gw)
        self.network = _Network(net)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 1:
            raise ValueError(
                "ClasslessRoute option is truncated: missing prefix length"
            )
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

    def __hash__(self) -> int:
        return hash((self.gateway, self.network))

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
            raise ValueError(
                f"{cls.__name__} option is truncated: expected 8-byte records"
            )
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


class DomainList(DhcpOptionType, list[str]):
    """RFC 1035 domain-name list with compression support.

    Normalizes like `List[T]` does, and for the same reason. With no
    `__init__` this inherited `list`'s, where a `str` argument is an
    *iterable of characters*: `DomainList("corp")` was `["c", "o", "r", "p"]`
    and `options[119] = "corp"` silently offered the client four
    single-letter search domains. A bare name is one entry; pass a list for
    several.
    """

    def __init__(self, *items: _ty.Any) -> None:
        # Same rule as `List.__init__`: a list/tuple argument is a sequence of
        # entries, anything else is a single entry.
        for group in items:
            self.extend(group if isinstance(group, (tuple, list)) else (group,))

    @staticmethod
    def _normalize(item: _ty.Any) -> str:
        if not isinstance(item, str):
            raise TypeError(
                f"domain-list entries must be str, not {type(item).__name__}"
            )
        return item

    def __setitem__(self, idx: _ty.Any, item: str) -> None:  # type: ignore[override]
        list.__setitem__(self, idx, self._normalize(item))

    def append(self, item: str) -> None:
        list.append(self, self._normalize(item))

    def extend(self, __iterable: Iterable[str]) -> None:
        list.extend(self, [self._normalize(item) for item in __iterable])

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        view = memoryview(option)
        self = cls()
        if not option:
            return self, 0
        # offset -> (kind, value, offset of the next component)
        #   kind "label": value is the decoded text
        #   kind "root" : value is None (a 0x00 terminator)
        #   kind "ptr"  : value is the target offset
        components: dict[int, tuple[str, _ty.Any, int]] = _ty.OrderedDict()
        domains: list[int] = [0]
        id = 0
        size = len(view)
        while id < size:
            start = id
            ptr_or_len = view[id]
            id += 1
            if ptr_or_len == 0x00:
                components[start] = ("root", None, id)
                if id < size:
                    domains.append(id)
                continue
            is_ptr = ptr_or_len & 0xC0
            if is_ptr:
                if is_ptr != 0xC0:
                    raise ValueError(
                        f"search list octet {ptr_or_len:#04x} at offset {start} sets a "
                        "reserved label-length prefix; RFC 1035 s4.1.4 defines only "
                        "00 (label) and 11 (compression pointer)"
                    )
                components[start] = (
                    "ptr",
                    ((0x3F & ptr_or_len) << 8) | view[id],
                    id + 1,
                )
                id += 1
                if id < size:
                    domains.append(id)
            else:
                dc = view[id : ptr_or_len + id]
                if len(dc) != ptr_or_len:
                    raise ValueError(
                        f"search list is truncated: a label declares {ptr_or_len} "
                        f"octets but only {len(dc)} remain"
                    )
                label = dc.tobytes().decode()
                if "." in label:
                    # Same reason as `domain.decode_domain_name`: these names
                    # are joined with ".", so a label already containing one
                    # re-encodes as a different number of labels than arrived.
                    raise ValueError(
                        f"search list has a label containing '.' ({label!r}), "
                        "which cannot be represented unambiguously in dotted form"
                    )
                components[start] = ("label", label, id + ptr_or_len)
                id += ptr_or_len

        def get_dn(start: int) -> list[str]:
            """Resolve one name by walking the component chain.

            Iterative, and every offset is visited at most once per name: a
            self-referential or mutually-referential compression pointer is a
            decode error, not a RecursionError, and the work is proportional to
            the name actually produced. The previous implementation rescanned
            every component for each name, which made decoding O(n^2) in the
            payload length and, since packets are decoded on the receive path,
            an unauthenticated CPU exhaustion vector.
            """
            result: list[str] = []
            seen: set[int] = set()
            offset = start
            while True:
                if offset in seen:
                    raise ValueError(
                        f"Cyclic domain-name compression pointer at offset {offset}"
                    )
                seen.add(offset)
                component = components.get(offset)
                if component is None:
                    break
                kind, value, nxt = component
                if kind == "root":
                    break
                if kind == "ptr":
                    offset = value
                    continue
                result.append(value)
                offset = nxt
            return result

        for domain in domains:
            self.append(".".join(get_dn(domain)))
        return self, len(option)

    def _dhcp_write(self, _data: bytearray) -> int:
        components: list[tuple[list[str], int]] = []
        data = bytearray()
        for domain_str in self:
            # Same rules as every other name in the package, even though the
            # encoding below is compressed and theirs is not: without this an
            # over-long label's length prefix sets the pointer flag bits and
            # this encoder emits bytes its own decoder rejects.
            domain = split_domain_name(domain_str, "search-list entry", allow_root=True)
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
                        # Octets, not characters. A compression pointer is a
                        # byte offset into the option, so counting characters
                        # here aimed every pointer past a non-ASCII label at the
                        # wrong byte.
                        cidx += 1 + len(n.encode())

                    parent = cidx, pair
                    unique = domain[:-pair]

            components.append((domain, len(data)))
            for comp in unique:
                # RFC 1035 3.1: a label's length octet counts OCTETS. This
                # counted characters, so `bücher.example` declared 6 for a
                # 7-octet label: the wire bytes were corrupt, and this encoder's
                # own decoder either raised a bare ValueError or read the
                # remainder as different labels entirely -- measured,
                # ['éé.x.com', 'y.x.com'] came back as ['<0xef><0xbf><0xbd>',
                # 'x.com', 'y']. `split_domain_name` validates in octets, so the
                # length check and the length written now agree.
                encoded = comp.encode()
                data.append(len(encoded))
                data.extend(encoded)
            if parent is None:
                data.append(0x00)
            else:
                data.extend((0xC000 | parent[0]).to_bytes(2, byteorder="big"))
        _data.extend(data)
        return len(data)


class UncompressedDomainList(DomainList):
    """A domain-name list for the options that forbid DNS name compression.

    RFC 3397's search list (option 119) is compressed on purpose. Two other
    options carrying a name list are not, and both were registered as plain
    `DomainList`, so pydhcp emitted a `0xC0` pointer into payloads whose own
    RFCs forbid one:

    * option 88, BCMCS controller domain names -- RFC 4280 §4.6: "The domain
      names MUST be concatenated and encoded using the technique described in
      Section 3.3 of [RFC1035]. DNS name compression MUST NOT be used."
    * option 146, RDNSS selection -- RFC 6731 §4.3 defers to RFC 3315 §8: "A
      domain name, or list of domain names, in DHCP MUST NOT be stored in
      compressed form, as described in section 4.1.4 of RFC 1035."

    Measured before the split, `["a.example.com", "b.example.com"]` encoded as
    `01 61 07 example 03 com 00 01 62 c0 02` for option 88 -- the second name
    ending in a pointer a conforming receiver is not required to follow.

    **Encode only.** Decoding stays `DomainList`'s: a pointer that arrives
    resolves unambiguously inside the option, and the receive path in this
    package is deliberately liberal, so refusing one would turn a readable
    packet from a non-conforming peer into a decode failure. The RFCs
    constrain what is sent, and that is what changes here.
    """

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for domain in self:
            # The shared encoder in `type/domain.py`, exactly as options 81,
            # 120, 122, 139 and 140 use it -- one set of name rules for the
            # whole package. `allow_root` keeps `DomainList`'s treatment of an
            # empty entry as the root name, a single zero octet.
            encoded = encode_domain_name(domain, "domain-list entry", allow_root=True)
            data.extend(encoded)
            written += len(encoded)
        return written


class RdnssSelection(DhcpOptionType):
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
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 9:
            raise ValueError(f"{cls.__name__} option is truncated")
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

    def __hash__(self) -> int:
        return hash((self.flags, self.primary, self.secondary, tuple(self.domains)))

    def __json__(self) -> list[_ty.Any]:
        return [
            self.flags,
            str(self.primary),
            str(self.secondary),
            self.domains.__json__(),
        ]


class ClientFqdn(DhcpOptionType):
    """RFC 4702 Client FQDN: flags, RCODE1, RCODE2, then the name.

    Registering this as a plain `String` lost data silently rather than loudly:
    `String` splits at the first NUL, so the form every Windows client sends
    (`00 00 00` then the name) decoded to the empty string, and a server reading
    it for DDNS saw no name at all. Emitting was the mirror image -- the first
    three characters of the name were read by the client as Flags/RCODE1/RCODE2.
    """

    #: The client requests that the server update the A RR (RFC 4702 s2.1).
    FLAG_S = 0x01
    #: The server overrode the client's S bit.
    FLAG_O = 0x02
    #: The name is in DNS wire format rather than ASCII.
    FLAG_E = 0x04
    #: The server should not perform any DNS update.
    FLAG_N = 0x08

    # Declared so the instance-accepting constructor can read `other.name`
    # without mypy hitting a circular inference.
    name: str
    flags: int
    rcode1: int
    rcode2: int

    def __init__(
        self,
        name: _ty.Any = "",
        flags: int = 0,
        rcode1: int = 0,
        rcode2: int = 0,
    ) -> None:
        if isinstance(name, ClientFqdn):
            name, flags, rcode1, rcode2 = (
                name.name,
                name.flags,
                name.rcode1,
                name.rcode2,
            )
        elif isinstance(name, _ty.Mapping):
            mapping = name
            name = mapping.get("name", "")
            flags = int(mapping.get("flags", 0))
            rcode1 = int(mapping.get("rcode1", 0))
            rcode2 = int(mapping.get("rcode2", 0))
        for label, value in (("flags", flags), ("rcode1", rcode1), ("rcode2", rcode2)):
            if not 0 <= int(value) <= 0xFF:
                raise ValueError(f"ClientFqdn {label} must fit in one octet")
        self.name = str(name)
        self.flags = int(flags)
        self.rcode1 = int(rcode1)
        self.rcode2 = int(rcode2)

    @property
    def encoded(self) -> bool:
        """Whether the name is carried in DNS wire format (the E bit)."""
        return bool(self.flags & self.FLAG_E)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 3:
            raise ValueError("ClientFqdn option is truncated: needs at least 3 octets")
        flags, rcode1, rcode2 = option[0], option[1], option[2]
        if flags & 0xF0:
            raise ValueError(f"ClientFqdn reserved flag bits set: {flags:#04x}")
        rest = option[3:]
        if flags & cls.FLAG_E:
            name, read = decode_domain_name(rest, 0, "ClientFqdn name")
            if read != len(rest):
                raise ValueError("ClientFqdn has trailing data after the name")
        else:
            name = rest.tobytes().split(b"\x00", 1)[0].decode("utf-8")
        return cls(name, flags, rcode1, rcode2), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        start = len(data)
        data.append(self.flags)
        data.append(self.rcode1)
        data.append(self.rcode2)
        if self.encoded:
            data.extend(
                encode_domain_name(self.name, "ClientFqdn name", allow_root=True)
            )
        else:
            data.extend(self.name.encode("utf-8"))
        return len(data) - start

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ClientFqdn):
            return NotImplemented
        return (self.name, self.flags, self.rcode1, self.rcode2) == (
            other.name,
            other.flags,
            other.rcode1,
            other.rcode2,
        )

    def __hash__(self) -> int:
        return hash((self.name, self.flags, self.rcode1, self.rcode2))

    def __repr__(self) -> str:
        return (
            f"ClientFqdn(name={self.name!r}, flags={self.flags:#04x}, "
            f"rcode1={self.rcode1}, rcode2={self.rcode2})"
        )

    def __json__(self) -> dict[str, _ty.Any]:
        return {
            "name": self.name,
            "flags": self.flags,
            "rcode1": self.rcode1,
            "rcode2": self.rcode2,
        }


class SipServers(DhcpOptionType):
    """RFC 3361 SIP servers: an encoding octet, then names or addresses.

    Encoding 0 is a list of RFC 1035 names, encoding 1 a list of IPv4 addresses.
    Registering this as a bare address list meant a conformant option could not
    be decoded at all, and an emitted one had no encoding octet -- so a SIP phone
    read the first address octet as the encoding and rejected the option.
    """

    ENCODING_DOMAIN = 0
    ENCODING_ADDRESS = 1

    # See ClientFqdn: declared to keep mypy out of a circular inference.
    encoding: int
    values: list[str]

    def __init__(
        self, values: _ty.Any = (), encoding: _ty.Optional[int] = None
    ) -> None:
        if isinstance(values, SipServers):
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
            # Infer, so SipServers(["192.0.2.1"]) does the obvious thing.
            encoding = self.ENCODING_ADDRESS
            for item in items:
                try:
                    _IP(item)
                except Exception:
                    encoding = self.ENCODING_DOMAIN
                    break
        if encoding not in (self.ENCODING_DOMAIN, self.ENCODING_ADDRESS):
            raise ValueError(f"SipServers encoding must be 0 or 1, got {encoding}")
        if encoding == self.ENCODING_ADDRESS:
            items = [str(_IP(item)) for item in items]
        self.encoding = int(encoding)
        self.values = items

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 1:
            raise ValueError("SipServers option is truncated: missing encoding octet")
        encoding = option[0]
        body = option[1:]
        if encoding == cls.ENCODING_ADDRESS:
            if len(body) % 4:
                raise ValueError(
                    "SipServers address list length must be a multiple of 4 plus one"
                )
            values = [
                str(_IP(body[idx : idx + 4].tobytes()))
                for idx in range(0, len(body), 4)
            ]
        elif encoding == cls.ENCODING_DOMAIN:
            values = []
            idx = 0
            while idx < len(body):
                name, read = decode_domain_name(body, idx, "SipServers name")
                values.append(name)
                idx += read
        else:
            raise ValueError(f"SipServers encoding must be 0 or 1, got {encoding}")
        return cls(values, encoding), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        start = len(data)
        data.append(self.encoding)
        if self.encoding == self.ENCODING_ADDRESS:
            for value in self.values:
                data.extend(_IP(value).packed)
        else:
            for value in self.values:
                data.extend(encode_domain_name(value, "SipServers name"))
        return len(data) - start

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SipServers):
            return NotImplemented
        return (self.encoding, self.values) == (other.encoding, other.values)

    def __hash__(self) -> int:
        return hash((self.encoding, tuple(self.values)))

    def __repr__(self) -> str:
        kind = "address" if self.encoding == self.ENCODING_ADDRESS else "domain"
        return f"SipServers({kind}, {self.values!r})"

    def __json__(self) -> dict[str, _ty.Any]:
        return {
            "encoding": (
                "address" if self.encoding == self.ENCODING_ADDRESS else "domain"
            ),
            "values": list(self.values),
        }


class DomainName(DhcpOptionType, str):
    """A single uncompressed RFC 1035 name, as an option payload.

    Options 147 (RFC 8973 s5.2) and 213 (RFC 5986 s3.2) carry a label sequence,
    not dotted text. Registered as `String` they decoded to the raw label bytes
    rather than to `example.com`, and emitted dotted text that a conforming
    receiver cannot parse.
    """

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        name, read = decode_domain_name(option, 0, cls.__name__)
        return cls(name), read

    def _dhcp_write(self, data: bytearray) -> int:
        encoded = encode_domain_name(str(self), type(self).__name__, allow_root=True)
        data.extend(encoded)
        return len(encoded)

    def __json__(self) -> str:
        return str(self)


class StatusCode(DhcpOptionType):
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
            raise ValueError(f"StatusCode code must fit one octet, got {value}")
        self.code = value
        self.message = str(message or "")

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 1:
            raise ValueError("StatusCode option is truncated: missing code octet")
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


class PcpServerList(DhcpOptionType, list[list[str]]):
    """RFC 7291 s4 PCP servers: one or more length-prefixed address lists.

    Each entry is a List-Length octet giving the octet count, then that many
    octets of IPv4 addresses; separate entries are separate PCP servers.
    Registered as a flat `List[IPv4Address]` the length octet was read as
    address data, so a conformant option raised and an emitted one carried no
    length octet at all.
    """

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], (list, tuple)):
            entries = list(items[0])
            # PcpServerList(["192.0.2.1"]) means one server, not an entry of
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
            raise ValueError("PcpServerList entry must hold at least one address")
        return addresses

    def append(self, entry: _ty.Any) -> None:
        list.append(self, self._normalize(entry))

    def extend(self, __iterable: Iterable[_ty.Any]) -> None:
        list.extend(self, [self._normalize(entry) for entry in __iterable])

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        self = cls()
        idx = 0
        while idx < len(option):
            length = option[idx]
            idx += 1
            if length == 0 or length % 4:
                raise ValueError(
                    "PcpServerList entry length must be a non-zero multiple of 4, "
                    f"got {length}"
                )
            if idx + length > len(option):
                raise ValueError("PcpServerList option is truncated")
            self.append(
                [
                    str(_IP(option[pos : pos + 4].tobytes()))
                    for pos in range(idx, idx + length, 4)
                ]
            )
            idx += length
        if not self:
            raise ValueError("PcpServerList option is empty")
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
