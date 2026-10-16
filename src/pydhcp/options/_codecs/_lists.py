"""The typed list containers: `List[T]`, `RecordList[T]` and `DHCPOptionCodes[C]`."""

from __future__ import annotations

import typing as _ty

from ...exceptions import DHCPValueError
from ..._generic import GenericMeta
from ._base import DHCPOptionType, _NormalizedList

if _ty.TYPE_CHECKING:
    from .._codes import BaseDHCPOptionCode

_T = _ty.TypeVar("_T", bound=DHCPOptionType)
_C = _ty.TypeVar("_C", bound="BaseDHCPOptionCode")


_ListT = _ty.TypeVar("_ListT", bound="List[_ty.Any]")


class List(_NormalizedList[_T], metaclass=GenericMeta):
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

    @classmethod
    def unpack_from(cls: type[_ListT], option: memoryview) -> tuple[_ListT, int]:
        _l = len(option)
        self = cls()
        ty = self._args_[0]
        while option:
            item, l = ty.unpack_from(option)
            list.append(self, item)
            option = option[l:]
        return self, _l

    def pack_into(self, data: bytearray) -> int:
        written = 0
        for item in self:
            written += item.pack_into(data)
        return written

    def to_json(self) -> list[_ty.Any]:
        return [item.to_json() for item in self]

    @classmethod
    def from_json(cls: type[_ListT], data: _ty.Any) -> _ListT:
        """Each item read back by its own codec's `from_json`, as `to_json` wrote it."""
        if not isinstance(data, list):
            return cls(data)
        read = getattr(cls._args_[0], "from_json", None)
        return cls([read(item) if read is not None else item for item in data])


class RecordList(List[_T]):
    """Typed list of two-field records, normalized from `(first, second)` pairs.

    Five containers repeated `List`'s whole shape around a record type that
    takes two constructor arguments -- the MoS options, the two RFC 3925 `VI*`
    options, option 82's encapsulated TLVs and the CCC option. They differ from
    `List` in exactly one place: a record is *itself* a two-element sequence, so
    `List.__init__`'s rule that a tuple argument is a sequence of items would
    split one `(code, value)` record into two items. Here only a `list` spells
    "several records"; a tuple is one record.

    Subclass a subscripted form (`class X(RecordList[SomeRecord])`) rather than
    setting a `_RECORD_TYPE` attribute -- `_args_[0]` is the same information and
    `unpack_from`/`_normalize` already read it.
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

    @classmethod
    def from_json(cls: type[_ListT], data: _ty.Any) -> _ListT:
        """The `[first, second]` pairs `to_json` wrote, each normalized as a record."""
        return cls(data)


_DHCPOptionCodesT = _ty.TypeVar("_DHCPOptionCodesT", bound="DHCPOptionCodes[_ty.Any]")


class DHCPOptionCodes(List[_C]):  # type: ignore[type-var]
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
            raise DHCPValueError(
                f"DHCP option code {item_int} does not fit in one octet (0-255)"
            )
        return item_int

    @classmethod
    def unpack_from(
        cls: type[_DHCPOptionCodesT], option: memoryview
    ) -> tuple[_DHCPOptionCodesT, int]:
        return cls(option.tolist()), len(option)

    def pack_into(self, data: bytearray) -> int:
        data.extend(_ty.cast(_ty.Iterable[int], self))
        return len(self)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({[int(code) for code in self]!r})"
