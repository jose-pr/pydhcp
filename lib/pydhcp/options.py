import typing as _ty
from ._options import *
from . import _utils
from .iana.options import DhcpOptionCode as _ianacodes

T = _ty.TypeVar("T", bound=DhcpOptionType)


class DhcpOptions(_ty.MutableMapping[int, bytearray]):
    def __init__(self, codemap: DhcpOptionCodeMap = None) -> None:
        self._codemap = codemap or _ianacodes
        self._options: dict[int, bytearray] = {}

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

    def encode(self, padding=False):
        if padding is True:
            padding = 2
        elif not padding or padding < 2:
            padding = 0
        options = bytearray()
        for code, option in self._options.items():
            options.append(int(code))
            option = memoryview(option)
            while option:
                slice = option[:255]
                options.append(len(slice))
                options.append(slice)
                if padding:
                    pad = padding - len(bytearray) % padding
                    options.extend(bytes(pad))
                option = option[255:]

        options.append(255)
        if padding:
            options.extend(bytes(padding - 1))
        return options

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
    def get(
        self, __key: int, /
    ) -> DhcpOptionType:
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
            return ty.decode(value)
        else:
            return value

    def append(self, option: DhcpOption):
        self._options.setdefault(self._key(option.code), bytearray()).extend(
            option.encode()
        )

    def replace(self, option: DhcpOption):
        data = option.encode()
        if not isinstance(data, bytearray):
            data = bytearray(data)
        self._options[option.code] = data

    def __setitem__(self, __key: int, __value: bytearray | DhcpOptionType):
        encode = getattr(__value, "encode", None)
        if encode:
            __value = __value.encode()
        self._options[self._key(__key)] = __value

    def __delitem__(self, __key: int) -> None:
        return self._options.__delitem__(self._key(__key))

    def __len__(self) -> int:
        return len(self._options)

    def __iter__(self) -> _ty.Iterator[int]:
        return self._options.__iter__()

    def items(self) -> _ty.ItemsView[int, bytearray]:
        return self._options.items()
