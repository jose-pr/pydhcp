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
        if hint:
            if todecode != hint:
                raise ValueError("Wrong option size")
        decoded, read = cls._dhcp_read(option)
        if read != todecode:
            raise ValueError("Couldnt decode whole option")
        return decoded


_T = _ty.TypeVar("_T", bound=DhcpOptionType)
_C = _ty.TypeVar("_C", bound="BaseDhcpOptionCode")


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
