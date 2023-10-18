import typing as _ty
from ._options import *
from .optiontype import *
from . import _utils
from .iana.options import DhcpOptionCode as _ianacodes
from math import inf as _inf

T = _ty.TypeVar("T", bound=DhcpOptionType)


class DhcpOptions(_ty.MutableMapping[int, bytearray]):
    def __init__(self, codemap: DhcpOptionCodeMap = None) -> None:
        self._codemap = codemap or _ianacodes
        self._options: _ty.OrderedDict[int, bytearray] = _ty.OrderedDict()

    def __repr__(self) -> str:
        return f"DhcpOptions({list(self._options.keys())})"

    def _key(self, code):
        try:
            return self._codemap.from_code(code)
        except:
            return int(code)

    def decode(self, options: memoryview):
        while options:
            code = options[0]
            if code == 0:
                options = options[1:]
                continue

            if code == 255:
                break
            code = self._key(code)
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
        return self._options[self._key(_key)]

    @_ty.overload
    def get(self, __key: int, /, decode: type[T] = ...) -> T | None:
        ...

    @_ty.overload
    def get(
        self, __key: int, /, decode: _ty.Literal[True] = True
    ) -> DhcpOptionType | None:
        ...

    @_ty.overload
    def get(self, __key: int, /) -> DhcpOptionType:
        ...

    @_ty.overload
    def get(
        self, __key: int, /, decode: _ty.Literal[False] = False
    ) -> bytearray | None:
        ...

    def get(self, __key, /, default=None, decode: bool | type[DhcpOptionType] = True):
        value = super().get(__key, default=_utils.MISSING)
        if value is _utils.MISSING:
            return default
        if decode:
            if decode is not True:
                ty = decode
            else:
                ty = self._codemap.get_type(__key)
            return ty._dhcp_decode(value)[0]
        else:
            return value

    def _getopt(self, option: DhcpOption | tuple[int, str]):
        if isinstance(option, DhcpOption):
            return option
        code, value = option
        code = self._codemap.from_code(code)
        return DhcpOption(code, code.get_type()(value))

    def append(self, option: DhcpOption):
        option = self._getopt(option)
        self._options.setdefault(self._key(option.code), bytearray()).extend(
            option.encode()
        )

    def replace(self, option: DhcpOption):
        option = self._getopt(option)
        data = option.encode()
        if not isinstance(data, bytearray):
            data = bytearray(data)
        self._options[option.code] = data

    def __setitem__(self, __key: int, __value: bytearray | DhcpOptionType):
        encode = getattr(__value, "_dhcp_encode", None)
        if encode:
            __value = __value._dhcp_encode()
        self._options[self._key(__key)] = __value

    def __delitem__(self, __key: int) -> None:
        return self._options.__delitem__(self._key(__key))

    def __len__(self) -> int:
        return len(self._options)

    def __iter__(self) -> _ty.Iterator[int]:
        return self._options.__iter__()

    def items(self) -> _ty.ItemsView[int, bytearray]:
        return self._options.items()

    def __contains__(self, __key: object) -> bool:
        return self._options.__contains__(self._key(__key))
