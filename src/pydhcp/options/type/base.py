from __future__ import annotations
from collections.abc import Iterable
import typing as _ty
from ... import _utils

if _ty.TYPE_CHECKING:
    from typing_extensions import Self
    from ..base import BaseDhcpOptionCode


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
        # `is not None`, not truthiness: a hint of 0 is a real constraint (a
        # zero-length presence option such as RFC 4039 Rapid Commit must reject
        # any payload), and `if hint:` silently skipped it.
        if hint is not None:
            if todecode != hint:
                raise ValueError("Wrong option size")
        decoded, read = cls._dhcp_read(option)
        if read != todecode:
            raise ValueError("Couldnt decode whole option")
        return decoded


_T = _ty.TypeVar("_T", bound=DhcpOptionType)
_C = _ty.TypeVar("_C", bound="BaseDhcpOptionCode")


def hashable_payload(value: _ty.Any) -> _ty.Any:
    """A hashable stand-in for a payload value, for use inside `__hash__`.

    Ten record codecs define `__eq__` and so were left unhashable by Python's
    `__hash__ = None` rule, while `Bytes`, `String`, `IPv4Address` and the
    integer codecs stayed hashable through their bases -- so
    `set(options.get(code))` worked or raised `TypeError` depending on which
    option the caller happened to touch. Several of those records hold a
    payload that may itself be a list codec (`List[IPv4Address]`, `UserClass`,
    a MoS label list), which is what stops a plain `hash((a, b))` from working.

    Every such codec is a flat sequence of hashable items, so the tuple of its
    items hashes consistently with the element-wise `__eq__` beside it.
    """
    if isinstance(value, list):
        return tuple(hashable_payload(item) for item in value)
    return value


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


class RecordList(List[_T]):
    """Typed list of two-field records, normalized from `(first, second)` pairs.

    Five containers repeated `List`'s whole shape around a record type that
    takes two constructor arguments -- the MoS options, the two RFC 3925 `Vi*`
    options, option 82's encapsulated TLVs and the CCC option. They differ from
    `List` in exactly one place: a record is *itself* a two-element sequence, so
    `List.__init__`'s rule that a tuple argument is a sequence of items would
    split one `(code, value)` record into two items. Here only a `list` spells
    "several records"; a tuple is one record.

    Subclass a subscripted form (`class X(RecordList[SomeRecord])`) rather than
    setting a `_RECORD_TYPE` attribute -- `_args_[0]` is the same information and
    `_dhcp_read`/`_normalize` already read it.
    """

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> _T:
        ty = cls._args_[0]
        if isinstance(item, _ty.cast(_ty.Any, ty)):
            return _ty.cast(_T, item)
        first, second = item
        return _ty.cast(_T, _ty.cast(_ty.Any, ty)(first, second))


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
