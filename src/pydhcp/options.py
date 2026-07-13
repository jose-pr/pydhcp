from __future__ import annotations

import typing as _ty
from ._options import BaseDhcpOptionCode as BaseDhcpOptionCode, DhcpOption as DhcpOption
from .optiontype import DhcpOptionType as DhcpOptionType
from . import constants as _const
from .enum.optioncode import DhcpOptionCode as _ianacodes
from .log import LOGGER
from math import inf as _inf

T = _ty.TypeVar("T", bound=DhcpOptionType)
C = _ty.TypeVar("C", bound=BaseDhcpOptionCode)
_R = _ty.TypeVar("_R")


class DhcpOptions(_ty.MutableMapping[int, bytearray]):
    def __init__(self, codemap: _ty.Optional[type[BaseDhcpOptionCode]] = None) -> None:
        self._codemap = codemap or _ianacodes
        self._options: _ty.OrderedDict[int, bytearray] = _ty.OrderedDict()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({list(self._options.keys())})"

    def decode(self, options: memoryview, base_offset: int = 0) -> memoryview:
        offset = base_offset
        while options:
            code = options[0]
            if code == 0:
                options = options[1:]
                offset += 1
                continue

            if code == 255:
                break

            if len(options) < 2:
                LOGGER.warning(f"Option {code} at offset {offset} is truncated (cannot read length)")
                options = options[len(options):]
                break

            length = options[1]
            remaining = len(options) - 2
            if length > remaining:
                LOGGER.warning(
                    f"Option {code} at offset {offset} claims {length} bytes but only {remaining} available"
                )
                data = options[2:]
                self._options.setdefault(code, bytearray()).extend(data)
                options = options[len(options):]
                continue

            next_idx = 2 + length
            data = options[2:next_idx]
            options = options[next_idx:]
            offset += next_idx
            self._options.setdefault(code, bytearray()).extend(data)
        return options

    def partial_encode(self, maxsize: _ty.Optional[float], word_size: int = 1) -> tuple[bytearray, _ty.Optional["DhcpOptions"]]:
        if maxsize is None:
            maxsize = _inf

        if word_size <= 0:
            raise ValueError(f"Invalid Options Word Size")

        endbytes = b"\xff" + b"\x00" * (word_size - 1)

        if maxsize < max(word_size * 2, 4):
            raise ValueError(f"Invalid Options Max Size")

        tofill = maxsize - word_size
        options = bytearray()
        _extraoptions: _ty.OrderedDict[int, bytearray] = _ty.OrderedDict()

        for code, option in self._options.items():
            if not tofill or tofill < 3:
                _extraoptions[code] = option
                continue

            options.append(int(code))
            opt_view = memoryview(option)
            tofill -= 1

            while opt_view and tofill >= word_size:
                slice_data = opt_view[: int(min(255, tofill))]
                _len = len(slice_data)
                options.append(_len)
                options.extend(slice_data)
                options.extend(b"\x00" * (word_size - _len))
                opt_view = opt_view[_len:]
                tofill -= _len
            if opt_view:
                _extraoptions[code] = bytearray(opt_view)

        options.extend(endbytes)
        if _extraoptions:
            leftover = DhcpOptions(self._codemap)
            leftover._options = _extraoptions
        else:
            leftover = None
        return options, leftover

    def encode(self, word_size: int = 1) -> bytearray:
        encoded, _ = self.partial_encode(None, word_size)
        return encoded

    def __getitem__(self, _key: int) -> bytearray:
        return self._options[_key]

    @_ty.overload  # type: ignore[override]
    def get(self, __key: int, default: _ty.Any = None, *, decode: type[T]) -> T | None:
        ...

    @_ty.overload
    def get(
        self, __key: int, default: _ty.Any = None, *, decode: _ty.Callable[[bytearray], _R]
    ) -> _R | None:
        ...

    @_ty.overload
    def get(
        self, __key: int, default: _ty.Any = None, *, decode: _ty.Literal[True]
    ) -> DhcpOptionType | None:
        ...

    @_ty.overload
    def get(
        self, __key: int, default: _ty.Any = None, *, decode: _ty.Literal[False]
    ) -> bytearray | None:
        ...

    @_ty.overload
    def get(self, __key: int, default: _ty.Any = None) -> DhcpOptionType | None:
        ...

    def get(
        self,
        __key: int,
        default: _ty.Any = None,
        decode: _ty.Union[bool, type[DhcpOptionType], _ty.Callable[[bytearray], _ty.Any]] = True,
    ) -> _ty.Any:
        value = self._options.get(__key, _const.MISSING)
        if value is _const.MISSING:
            return default
        assert isinstance(value, bytearray)
        if decode:
            target_decoder: _ty.Union[type[DhcpOptionType], _ty.Callable[[bytearray], _ty.Any]]
            if decode is True:
                target_decoder = self._codemap.from_code(__key).get_type()
            else:
                target_decoder = decode
            
            if isinstance(target_decoder, type) and issubclass(target_decoder, DhcpOptionType):
                return target_decoder._dhcp_decode(value)
            return _ty.cast(_ty.Callable[[bytearray], _ty.Any], target_decoder)(value)
        else:
            return value

    def _ensuretype(self, option: _ty.Union[DhcpOption, tuple[int, _ty.Any]]) -> DhcpOption:
        if isinstance(option, DhcpOption):
            return option
        return self._codemap.normalize(*option)

    def append(self, option: _ty.Union[DhcpOption, tuple[int, _ty.Any]]) -> None:
        opt = self._ensuretype(option)
        opt.value._dhcp_write(self._options.setdefault(int(opt.code), bytearray()))

    def replace(self, option: _ty.Union[DhcpOption, tuple[int, _ty.Any]]) -> None:
        opt = self._ensuretype(option)
        self[int(opt.code)] = opt.value

    def __setitem__(self, __key: int, __value: _ty.Any) -> None:
        if not isinstance(__value, (bytes, memoryview, bytearray, DhcpOptionType)):
            __value = self._codemap.from_code(__key).get_type()(__value)  # type: ignore[call-arg]
        if isinstance(__value, DhcpOptionType):
            data = self._options.setdefault(__key, bytearray())
            data.clear()
            __value._dhcp_write(data)
        else:
            if not isinstance(__value, bytearray):
                __value = bytearray(__value)
            self._options[__key] = __value

    def __delitem__(self, __key: int) -> None:
        return self._options.__delitem__(__key)

    def __len__(self) -> int:
        return len(self._options)

    def __iter__(self) -> _ty.Iterator[int]:
        return self._options.__iter__()

    @_ty.overload  # type: ignore[override]
    def items(self) -> _ty.ItemsView[BaseDhcpOptionCode, DhcpOptionType]:
        ...

    @_ty.overload
    def items(self, decoded: _ty.Literal[False]) -> _ty.ItemsView[int, bytearray]:
        ...

    @_ty.overload
    def items(
        self, decoded: _ty.Literal[True]
    ) -> _ty.ItemsView[BaseDhcpOptionCode, DhcpOptionType]:
        ...

    @_ty.overload
    def items(self, decoded: type[C]) -> _ty.ItemsView[C, DhcpOptionType]:
        ...

    def items(self, decoded: _ty.Union[bool, type[BaseDhcpOptionCode]] = True) -> _ty.Any:
        items = self._options.items()
        if decoded is True:
            decoded = self._codemap
        if decoded:
            items = [decoded.decode(*option) for option in items]  # type: ignore
        return items

    def __contains__(self, __key: object) -> bool:
        return self._options.__contains__(__key)
