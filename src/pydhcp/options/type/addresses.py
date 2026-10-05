"""Address-valued option codecs: one IPv4 address, classless routes, and address-pair lists."""

from __future__ import annotations

import typing as _ty
from ...exceptions import DHCPDecodeError, DHCPValueError
from ...network import IPv4 as _IP, IPv4Network as _Network
from .base import DhcpOptionType
from collections.abc import Iterable

_IPv4AddressT = _ty.TypeVar("_IPv4AddressT", bound="IPv4Address")


class IPv4Address(DhcpOptionType, _IP):
    """A single IPv4 address carried in network byte order."""

    @classmethod
    def _dhcp_read(
        cls: type[_IPv4AddressT], option: memoryview
    ) -> tuple[_IPv4AddressT, int]:
        if len(option) < 4:
            raise DHCPDecodeError(
                f"{cls.__name__} option is truncated: needs 4 octets, got {len(option)}"
            )
        return cls(option[:4].tobytes()), 4

    def _dhcp_write(self, data: bytearray) -> int:
        data.extend(self.packed)
        return 4

    @classmethod
    def _dhcp_len_hint(cls) -> _ty.Optional[int]:
        return 4

    def __repr__(self) -> str:
        return str(self)

    def __json__(self) -> str:
        return str(self)


_ClasslessRouteT = _ty.TypeVar("_ClasslessRouteT", bound="ClasslessRoute")


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
    def _dhcp_read(
        cls: type[_ClasslessRouteT], option: memoryview
    ) -> tuple[_ClasslessRouteT, int]:
        if len(option) < 1:
            raise DHCPDecodeError(
                "ClasslessRoute option is truncated: missing prefix length"
            )
        cidr = option[0]
        if cidr > 32:
            raise DHCPDecodeError(f"ClasslessRoute prefix length {cidr} exceeds 32")
        last = 1 + (cidr + 7) // 8
        if len(option) < last + 4:
            raise DHCPDecodeError(
                f"ClasslessRoute option is truncated: needs {last + 4} bytes, got {len(option)}"
            )
        net_bytes = option[1:last].tobytes() + b"\x00\x00\x00\x00"
        try:
            network = _Network((net_bytes[:4], cidr))
        except ValueError as exc:
            raise DHCPDecodeError(f"ClasslessRoute destination: {exc}") from exc
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


_IPv4PairListT = _ty.TypeVar("_IPv4PairListT", bound="_IPv4PairList")


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
    def _dhcp_read(
        cls: type[_IPv4PairListT], option: memoryview
    ) -> tuple[_IPv4PairListT, int]:
        if len(option) % 8:
            raise DHCPDecodeError(
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
            raise DHCPValueError(
                "StaticRoute does not allow a default-route destination"
            )
        return left, right
