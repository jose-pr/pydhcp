import typing as _ty
from ._options import *
from .optiontype import *
from . import contants as _const
from .enum.optioncode import DhcpOptionCode as _ianacodes
from math import inf as _inf

T = _ty.TypeVar("T", bound=DhcpOptionType)
C = _ty.TypeVar("C", bound=BaseDhcpOptionCode)
_R = _ty.TypeVar("_R")


class DhcpOptions(_ty.MutableMapping[int, bytearray]):
    def __init__(self, codemap: type[BaseDhcpOptionCode] = None) -> None:
        self._codemap = codemap or _ianacodes
        self._options: _ty.OrderedDict[int, bytearray] = _ty.OrderedDict()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({list(self._options.keys())})"

    def decode(self, options: memoryview):
        while options:
            code = options[0]
            if code == 0:
                options = options[1:]
                continue

            if code == 255:
                break
            length = options[1]
            next = 2 + length
            data = options[2:next]
            options = options[next:]
            self._options.setdefault(code, bytearray()).extend(data)
        return options

    def partial_encode(self, maxsize: int, word_size: int = 1):
        if maxsize is None:
            maxsize = _inf

        if word_size <= 0:
            raise ValueError(f"Invalid Options Word Size")

        endbytes = b"\xff" + b"\x00" * (word_size - 1)

        if maxsize < max(word_size * 2, 4):
            raise ValueError(f"Invalid Options Max Size")

        tofill = maxsize - word_size
        options = bytearray()
        _extraoptions = _ty.OrderedDict()

        for code, option in self._options.items():
            if not tofill or tofill < 3:
                _extraoptions[code] = option
                continue

            options.append(int(code))
            option = memoryview(option)
            tofill -= 1

            while option and tofill >= word_size:
                slice = option[: min(255, tofill)]
                _len = len(slice)
                options.append(_len)
                options.extend(slice)
                options.extend(b"\x00" * (word_size - _len))
                option = option[_len:]
                tofill -= _len
            if option:
                _extraoptions[code] = bytearray(option)

        options.extend(endbytes)
        if _extraoptions:
            leftover = DhcpOptions(self._codemap)
            leftover._options = _extraoptions
        else:
            leftover = None
        return options, leftover

    def encode(self, word_size=1):
        encoded, _ = self.partial_encode(None, word_size)
        return encoded

    def __getitem__(self, _key: int):
        return self._options[_key]

    @_ty.overload
    def get(self, __key: int, /, decode: type[T] = ...) -> T | None:
        ...

    @_ty.overload
    def get(
        self, __key: int, /, decode: _ty.Callable[[bytearray], _R] = ...
    ) -> _R | None:
        ...

    @_ty.overload
    def get(
        self, __key: int, /, decode: _ty.Literal[True] = True
    ) -> DhcpOptionType | None:
        ...

    @_ty.overload
    def get(self, __key: int, /) -> DhcpOptionType | None:
        ...

    @_ty.overload
    def get(
        self, __key: int, /, decode: _ty.Literal[False] = False
    ) -> bytearray | None:
        ...

    def get(
        self,
        __key: int,
        /,
        default=None,
        decode: bool | type[T] | _ty.Callable[[bytearray], _R] = True,
    ):
        value = super().get(__key, default=_const.MISSING)
        if value is _const.MISSING:
            return default
        if decode:
            if decode is True:
                decode = self._codemap.get_type(__key)
            return (
                decode._dhcp_decode(value)
                if issubclass(decode, DhcpOptionType)
                else decode(value)
            )
        else:
            return value

    def _ensuretype(self, option: DhcpOption | tuple[int, str]):
        if isinstance(option, DhcpOption):
            return option
        return self._codemap.normalize(*option)

    def append(self, option: DhcpOption):
        option = self._ensuretype(option)
        option.value._dhcp_write(self._options.setdefault(option.code, bytearray()))

    def replace(self, option: DhcpOption):
        option = self._ensuretype(option)
        self[option.code] = option.value

    def __setitem__(self, __key: int, __value: bytearray | DhcpOptionType):
        if not isinstance(__value, (bytes, memoryview, bytearray, DhcpOptionType)):
            __value = self._codemap.from_code(__key).get_type()(__value)
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

    @_ty.overload
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

    def items(self, decoded: Boolean | type[BaseDhcpOptionCode] = True):
        items = self._options.items()
        if decoded is True:
            decoded = self._codemap
        if decoded:
            items = [decoded.decode(*option) for option in items]
        return items

    def __contains__(self, __key: object) -> bool:
        return self._options.__contains__(__key)
