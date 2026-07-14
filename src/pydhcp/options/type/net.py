from __future__ import annotations
from collections.abc import Iterable
import typing as _ty

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from ...network import IPv4 as _IP, IPv4Interface as _Interface, IPv4Network as _Network
from .base import DhcpOptionType


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
                if id < size:
                    domains.append(id)
                continue
            is_ptr = ptr_or_len & 0xC0
            if is_ptr:
                if is_ptr != 0xC0:
                    raise ValueError()
                components[id - 1] = ((0x3F & ptr_or_len) << 8) | view[id]
                id += 1
                if id < size:
                    domains.append(id)
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
