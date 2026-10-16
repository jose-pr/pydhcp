"""The lease value `pydhcp.lease.DHCPLease`."""

from __future__ import annotations

import datetime as _dt
import ipaddress as _ipaddress
import typing as _ty

from .. import _constants as _const, _nvt
from .._missing import MISSING as _MISSING, Missing as _Missing
from ..exceptions import DHCPValueError
from ..options import DHCPOptions
from ..options._codes import OptionCode
from ..options._frozen import FrozenDHCPOptions
from ..packet import structured as _structured
from ..packet._fields import _FILE_FIELD_SIZE, _SNAME_FIELD_SIZE, _check_bootp_field
from ..packet._mapping import _coerce_bootp_text, _text_value

__all__ = ["DHCPLease"]

#: The options of a lease built with none; read-only, so one is shared.
_NO_OPTIONS = FrozenDHCPOptions(DHCPOptions())

_Address = _ty.Union[str, int, bytes, _ipaddress.IPv4Address]


class DHCPLease:
    """One address held by one client: a value, built once and never changed.

    `ip` is the address: never `None`, and never `0.0.0.0` unless the lease is
    built with `strict=False`, for a reservation that has no address yet; whoever
    takes such a lease checks it with `validate()`. `expires` is the
    instant the lease ends, a timezone-aware `datetime` held in UTC, or `None`
    for a lease that never ends; a naive `datetime` raises `DHCPValueError` and
    any other type `TypeError`. `options` is the configuration the lease carries:
    it is copied in, so the bag the caller holds is not the lease's, and it is
    read-only; `lease.options.copy()` is an ordinary bag to change. Two leases
    with the same address, expiry, option payloads and state are equal and hash
    equal.

    `offered` is the state: True for an address held for a client that has been
    offered it and has not yet accepted (`expires` is then the end of the hold),
    False, the default, for a binding the client has accepted.

    `siaddr`, `sname` and `file` are the BOOTP header fields a reply to the
    client carries (the next server, its name and the boot file, RFC 2131 Table
    3); unset, the reply's are blank. They take part in equality and hash.
    """

    __slots__ = ("ip", "expires", "options", "offered", "siaddr", "sname", "file")

    ip: _ipaddress.IPv4Address
    expires: _ty.Optional[_dt.datetime]
    options: DHCPOptions
    offered: bool
    siaddr: _ipaddress.IPv4Address
    sname: str
    file: str

    def __init__(
        self,
        ip: _Address,
        expires: _ty.Optional[_dt.datetime] = None,
        options: _ty.Optional[DHCPOptions] = None,
        *,
        offered: bool = False,
        siaddr: _Address = _const.UNSPECIFIED_ADDRESS,
        sname: str = "",
        file: str = "",
        strict: bool = True,
    ) -> None:
        if ip is None:
            raise TypeError("a lease needs an address")
        address = _address("ip", ip)
        if strict and address.is_unspecified:
            raise DHCPValueError(
                "a lease needs an address, not 0.0.0.0 (strict=False builds one "
                "without, to be checked with validate())"
            )
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
        _set(self, "offered", bool(offered))
        _set(self, "siaddr", _address("siaddr", siaddr))
        _set(self, "sname", _bootp_text("sname", sname, _SNAME_FIELD_SIZE))
        _set(self, "file", _bootp_text("file", file, _FILE_FIELD_SIZE))

    def validate(self) -> "DHCPLease":
        """This lease, or `DHCPValueError` when it has no address to give.

        A lease built with `strict=False` may hold `0.0.0.0`; call this before
        using one as a binding. A strict lease always passes.
        """
        if self.ip.is_unspecified:
            raise DHCPValueError("the lease has no address (0.0.0.0)")
        return self

    def replace(
        self,
        *,
        ip: _ty.Union[str, int, bytes, _ipaddress.IPv4Address, _Missing] = _MISSING,
        expires: _ty.Union[_dt.datetime, None, _Missing] = _MISSING,
        options: _ty.Union[DHCPOptions, None, _Missing] = _MISSING,
        offered: _ty.Union[bool, _Missing] = _MISSING,
        siaddr: _ty.Union[_Address, _Missing] = _MISSING,
        sname: _ty.Union[str, _Missing] = _MISSING,
        file: _ty.Union[str, _Missing] = _MISSING,
        strict: bool = True,
    ) -> "DHCPLease":
        """A new lease with the given fields changed and the others carried over.

        An omitted field keeps this lease's value, `options` as the same
        read-only object; a given one is checked as `DHCPLease(...)` checks it,
        so `expires=None` is a lease that never ends. `strict` applies to a new
        `ip`: an address carried over was accepted already. This lease is not
        changed.
        """
        return DHCPLease(
            self.ip if isinstance(ip, _Missing) else ip,
            self.expires if isinstance(expires, _Missing) else expires,
            self.options if isinstance(options, _Missing) else options,
            offered=self.offered if isinstance(offered, _Missing) else offered,
            siaddr=self.siaddr if isinstance(siaddr, _Missing) else siaddr,
            sname=self.sname if isinstance(sname, _Missing) else sname,
            file=self.file if isinstance(file, _Missing) else file,
            strict=strict and not isinstance(ip, _Missing),
        )

    def to_mapping(self) -> _ty.Dict[str, _ty.Any]:
        """The lease as plain data: `ip`, `expires`, `offered`, the boot fields, `options`.

        `expires` is ISO 8601 text in UTC, and is left out for a lease that never
        ends (TOML has no null); `siaddr`, `sname` and `file` are written only
        when set, `sname` and `file` as text or, when not UTF-8, ``{"hex": ...}``;
        `options` is `DHCPOptions.to_mapping`'s form.
        """
        mapping: _ty.Dict[str, _ty.Any] = {"ip": str(self.ip)}
        if self.expires is not None:
            mapping["expires"] = self.expires.isoformat()
        mapping["offered"] = self.offered
        if not self.siaddr.is_unspecified:
            mapping["siaddr"] = str(self.siaddr)
        if self.sname:
            mapping["sname"] = _text_value(self.sname)
        if self.file:
            mapping["file"] = _text_value(self.file)
        mapping["options"] = self.options.to_mapping()
        return mapping

    @classmethod
    def from_mapping(
        cls,
        data: _ty.Mapping[str, _ty.Any],
        *,
        codemap: _ty.Optional[_ty.Type[OptionCode]] = None,
        strict: bool = True,
    ) -> "DHCPLease":
        """Build a lease from a mapping in the shape `to_mapping` produces.

        Only `ip` is required, and with `strict=False` not even that: it is then
        `0.0.0.0` when left out, for `validate()` to catch. `expires` left out or
        null is a lease that never ends, `offered` defaults to False, the boot
        fields to blank and `options` to none. `expires` is ISO 8601 text with an
        offset (`Z` included) or an aware `datetime`; `sname` and `file` are text,
        null or ``{"hex": ...}``; `options` is read by `DHCPOptions.from_mapping`
        with `codemap`. Each value is then checked as `DHCPLease(...)` checks it.
        Other keys are ignored.

        Raises:
            TypeError: a field has the wrong type.
            ValueError: `ip` is missing, or a field cannot be read.
        """
        if "ip" not in data and strict:
            raise ValueError("the lease has no 'ip' field")
        offered = data.get("offered", False)
        if not isinstance(offered, bool):
            raise TypeError(f"offered must be true or false, not {offered!r}")
        return cls(
            data.get("ip", _const.UNSPECIFIED_ADDRESS),
            _instant(data.get("expires")),
            DHCPOptions.from_mapping(data.get("options"), codemap=codemap),
            offered=offered,
            siaddr=data.get("siaddr", _const.UNSPECIFIED_ADDRESS),
            sname=_coerce_bootp_text(data.get("sname"), "sname"),
            file=_coerce_bootp_text(data.get("file"), "file"),
            strict=strict,
        )

    def to_text(self, format: str) -> str:
        """The lease as a document: ``"json"``, ``"yaml"``, ``"toml"`` or ``"ini"``.

        `to_mapping` written out by `pydhcp.packet.structured.dumps`.
        """
        return _structured.dumps(self.to_mapping(), format)

    @classmethod
    def from_text(
        cls,
        text: str,
        format: str,
        *,
        codemap: _ty.Optional[_ty.Type[OptionCode]] = None,
        strict: bool = True,
    ) -> "DHCPLease":
        """`pydhcp.packet.structured.loads` then `from_mapping`, with its errors."""
        return cls.from_mapping(
            _structured.loads(text, format), codemap=codemap, strict=strict
        )

    def __setattr__(self, name: str, value: _ty.Any) -> _ty.NoReturn:
        raise AttributeError("DHCPLease is read-only")

    def __delattr__(self, name: str) -> _ty.NoReturn:
        raise AttributeError("DHCPLease is read-only")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DHCPLease):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def _key(self) -> tuple[_ty.Any, ...]:
        return (
            self.ip,
            self.expires,
            self.options,
            self.offered,
            self.siaddr,
            self.sname,
            self.file,
        )

    def __repr__(self) -> str:
        extra = ", offered=True" if self.offered else ""
        if not self.siaddr.is_unspecified:
            extra += f", siaddr={self.siaddr!r}"
        if self.sname:
            extra += f", sname={self.sname!r}"
        if self.file:
            extra += f", file={self.file!r}"
        if self.ip.is_unspecified:
            extra += ", strict=False"
        return (
            f"DHCPLease(ip={self.ip!r}, expires={self.expires!r}, "
            f"options={self.options!r}{extra})"
        )

    def __reduce__(self) -> tuple[_ty.Any, ...]:
        return (_rebuild, self._key())

    def __copy__(self) -> "DHCPLease":
        return self

    def __deepcopy__(self, memo: _ty.Dict[int, _ty.Any]) -> "DHCPLease":
        return self


def _instant(value: _ty.Any) -> _ty.Optional[_dt.datetime]:
    """`expires` from a document: ISO 8601 text, a `datetime`, or nothing."""
    if not isinstance(value, str):
        return _ty.cast(_ty.Optional[_dt.datetime], value)
    text = value.strip()
    if text[-1:] in ("Z", "z"):
        # `fromisoformat` takes the `Z` designator only from Python 3.11.
        text = text[:-1] + "+00:00"
    try:
        return _dt.datetime.fromisoformat(text)
    except ValueError:
        raise DHCPValueError(f"expires is not an ISO 8601 instant: {value!r}") from None


def _address(field: str, value: _Address) -> _ipaddress.IPv4Address:
    if isinstance(value, _ipaddress.IPv4Address):
        return value
    try:
        return _ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise DHCPValueError(f"{field}: {exc}") from exc


def _bootp_text(field: str, value: str, width: int) -> str:
    """`sname` or `file`: text that fits its fixed-width BOOTP field."""
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text, not {type(value).__name__}")
    _check_bootp_field(field, _nvt.encode(value), width)
    return value


def _rebuild(
    ip: _ipaddress.IPv4Address,
    expires: _ty.Optional[_dt.datetime],
    options: DHCPOptions,
    offered: bool,
    siaddr: _ipaddress.IPv4Address = _const.UNSPECIFIED_ADDRESS,
    sname: str = "",
    file: str = "",
) -> DHCPLease:
    # strict=False: the address was accepted when the pickled lease was built.
    return DHCPLease(
        ip,
        expires,
        options,
        offered=offered,
        siaddr=siaddr,
        sname=sname,
        file=file,
        strict=False,
    )
