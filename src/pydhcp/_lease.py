"""The lease value `pydhcp.lease.DHCPLease`."""

from __future__ import annotations

import datetime as _dt
import ipaddress as _ipaddress
import typing as _ty

from .exceptions import DHCPValueError
from .options import DHCPOptions
from .options._frozen import FrozenDHCPOptions

__all__ = ["DHCPLease"]

#: The options of a lease built with none; read-only, so one is shared.
_NO_OPTIONS = FrozenDHCPOptions(DHCPOptions())


class DHCPLease:
    """One address held by one client: a value, built once and never changed.

    `ip` is the address (never `None` and never `0.0.0.0`). `expires` is the
    instant the lease ends, a timezone-aware `datetime` held in UTC, or `None`
    for a lease that never ends; a naive `datetime` raises `DHCPValueError` and
    any other type `TypeError`. `options` is the configuration the lease carries:
    it is copied in, so the bag the caller holds is not the lease's, and it is
    read-only; `lease.options.copy()` is an ordinary bag to change. Two leases
    with the same address, expiry and option payloads are equal and hash equal.
    """

    __slots__ = ("ip", "expires", "options")

    ip: _ipaddress.IPv4Address
    expires: _ty.Optional[_dt.datetime]
    options: DHCPOptions

    def __init__(
        self,
        ip: _ty.Union[str, int, bytes, _ipaddress.IPv4Address],
        expires: _ty.Optional[_dt.datetime] = None,
        options: _ty.Optional[DHCPOptions] = None,
    ) -> None:
        if ip is None:
            raise TypeError("a lease needs an address")
        if isinstance(ip, _ipaddress.IPv4Address):
            address = ip
        else:
            try:
                address = _ipaddress.IPv4Address(ip)
            except ValueError as exc:
                raise DHCPValueError(str(exc)) from exc
        if address.is_unspecified:
            raise DHCPValueError("a lease needs an address, not 0.0.0.0")
        if expires is not None:
            if not isinstance(expires, _dt.datetime):
                raise TypeError(
                    "a lease expires at a timezone-aware datetime or never (None), "
                    f"not {type(expires).__name__}"
                )
            if expires.utcoffset() is None:
                raise DHCPValueError(
                    "a lease expires at a timezone-aware instant, not a naive "
                    "datetime; use datetime.now(timezone.utc)"
                )
            if expires.tzinfo is not _dt.timezone.utc:
                expires = expires.astimezone(_dt.timezone.utc)
        if options is None:
            options = _NO_OPTIONS
        elif not isinstance(options, FrozenDHCPOptions):
            options = FrozenDHCPOptions(options)
        _set = object.__setattr__
        _set(self, "ip", address)
        _set(self, "expires", expires)
        _set(self, "options", options)

    def __setattr__(self, name: str, value: _ty.Any) -> _ty.NoReturn:
        raise AttributeError("DHCPLease is read-only")

    def __delattr__(self, name: str) -> _ty.NoReturn:
        raise AttributeError("DHCPLease is read-only")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DHCPLease):
            return NotImplemented
        return (self.ip, self.expires, self.options) == (
            other.ip,
            other.expires,
            other.options,
        )

    def __hash__(self) -> int:
        return hash((self.ip, self.expires, self.options))

    def __repr__(self) -> str:
        return (
            f"DHCPLease(ip={self.ip!r}, expires={self.expires!r}, "
            f"options={self.options!r})"
        )

    def __reduce__(self) -> tuple[_ty.Any, ...]:
        return (type(self), (self.ip, self.expires, self.options))

    def __copy__(self) -> "DHCPLease":
        return self

    def __deepcopy__(self, memo: _ty.Dict[int, _ty.Any]) -> "DHCPLease":
        return self
