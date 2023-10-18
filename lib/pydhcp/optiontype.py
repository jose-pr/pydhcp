from collections.abc import Iterable
import typing as _ty
import types as _types
import struct as _struct
from . import _utils

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from .netutils import IPAddress as _IP


class DhcpOptionType:
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        raise NotImplementedError()

    def _dhcp_write(self, buffer: bytearray) -> int:
        raise NotImplementedError()

    def _dhcp_encode(self) -> bytes:
        encoded = bytearray()
        _wrote = self._dhcp_write(encoded)
        return bytes(encoded)

    @classmethod
    def _dhcp_len_hint(self) -> int | None:
        None

    @classmethod
    def _dhcp_decode(cls, option: memoryview | bytes | bytearray) -> "Self":
        hint = cls._dhcp_len_hint()
        todecode = len(option)
        option = memoryview(option) if not isinstance(option, memoryview) else option
        if hint:
            if todecode != hint:
                raise ValueError("Wrong option size")
            option = option[:hint]

        decoded, read = cls._dhcp_read(option)
        if read != todecode:
            raise ValueError("Couldnt decode whole option")
        return decoded


_T = _ty.TypeVar("_T", bound=DhcpOptionType)


class List(DhcpOptionType, list[_T], metaclass=_utils.GenericMeta):
    _args_: _ty.ClassVar[tuple[_T]]  # type:ignore

    def __init__(self, *items: _ty.Iterable[_T] | _T):
        for _items in items:
            self.extend(_items if isinstance(_items, (tuple, list)) else (_items,))

    def __setitem__(self, idx, item: _T) -> None:
        ty = self._args_[0]
        return list.__setitem__(
            self, idx, ty(item) if not isinstance(item, ty) else item
        )

    def append(self, item: _T) -> None:
        ty = self._args_[0]
        return list.append(self, ty(item) if not isinstance(item, ty) else item)

    def extend(self, __iterable: Iterable[_T]) -> None:
        ty = self._args_[0]
        list.extend(
            self,
            [(ty(item) if not isinstance(item, ty) else item) for item in __iterable],
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

    def _dhcp_write(self, data: bytearray):
        written = 0
        for item in self:
            written += item._dhcp_write(data)
        return written


class IPv4Address(DhcpOptionType, _IP):
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        return cls(option[:4].tobytes()), 4

    def _dhcp_write(self, data: bytearray):
        data.extend(self.packed)
        return 4

    @classmethod
    def _dhcp_len_hint(cls):
        return 4

    def __repr__(self) -> str:
        return str(self)


class Bytes(DhcpOptionType, bytearray):
    def __repr__(self) -> str:
        return str(bytes(self))

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        return cls(option), len(option)

    def _dhcp_write(self, data: bytearray):
        data.extend(self)
        return len(self)


class String(DhcpOptionType, str):
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        text, _, _ = option.tobytes().partition(b"\x00")
        return cls(text.decode()), len(option)

    def _dhcp_write(self, data: bytearray):
        text = self.encode()
        data.extend(text)
        return len(text)


class Boolean(DhcpOptionType, int):
    def __new__(cls, val):
        if val:
            val = 1
        else:
            val = 0
        return super().__new__(cls, val)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        return cls(option[0]), 1

    def _dhcp_write(self, data: bytearray):
        data.append(self)
        return 1

    @classmethod
    def _dhcp_len_hint(self) -> int:
        return 1


class U16(DhcpOptionType, int):
    def __new__(cls, val):
        if val > 1 << 16 or val < 0:
            raise ValueError()
        return super().__new__(cls, val)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        return cls(_struct.unpack("!H", option[:2])[0]), 2

    def _dhcp_write(self, data: bytearray):
        data.extend(_struct.pack("!H", self))
        return 2

    @classmethod
    def _dhcp_len_hint(self) -> int:
        return 2


class U32(DhcpOptionType, int):
    def __new__(cls, val):
        if val > 1 << 32 or val < 0:
            raise ValueError()
        return super().__new__(cls, val)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        return cls(_struct.unpack("!I", option)[0]), 4

    def _dhcp_write(self, data: bytearray):
        data.extend(_struct.pack("!I", self))
        return 4

    @classmethod
    def _dhcp_len_hint(self) -> int:
        return 4


class DomainList(DhcpOptionType, list[str]):
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        view = memoryview(option)
        self = cls()
        if not option:
            return self
        components: dict[str, str] = _ty.OrderedDict()
        domains: list[int] = [0]
        id = 0
        size = len(view)
        while id < size:
            first = view[id]
            id += 1
            if first == 0x00:
                components[id - 1] = None
                domains.append(id)
                continue
            is_ptr = first & 0xC0
            if is_ptr:
                if is_ptr != 0xC0:
                    raise ValueError()
                components[id - 1] = ((0x3F & first) << 8) | view[id]
                id += 1
            else:
                dc = view[id : first + id]
                if len(dc) != first:
                    raise ValueError()
                components[id - 1] = dc.tobytes().decode()
                id += first

        def get_dn(id: int):
            result = []
            for idx, dc in components.items():
                if idx >= id:
                    if dc is None:
                        break
                    elif isinstance(dc, int):
                        result.extend(get_dn(dc))
                        break
                    result.append(dc)
            return result

        for domain in domains:
            self.append(".".join(get_dn(domain)))
        return self, len(option)

    def _dhcp_write(self, _data: bytearray):
        components: list[tuple[list[str], int | None]] = []
        data = bytearray()
        for domain in self:
            domain = domain.split(".")
            unique = domain
            parent: tuple[int, int] = None
            for cn, cidx in components:
                pair = 1
                while pair < len(domain):
                    if domain[-pair:] != cn[-pair:]:
                        break
                    pair += 1
                pair -= 1
                if pair:
                    if parent:
                        _, _pair = parent
                        if pair <= _pair:
                            continue
                    for n in cn[:-pair]:
                        cidx += 1 + len(n)

                    parent = cidx, pair
                    unique = domain[:-pair]

            components.append((domain, len(data)))
            for cn in unique:
                data.append(len(cn))
                data.extend(cn.encode())
            if parent is None:
                data.append(0x00)
            else:
                cn
                data.extend((0xC000 | parent[0]).to_bytes(2, byteorder="big"))
        _data.extend(data)
        return len(data)

    def __repr__(self) -> str:
        return "\n".join(self)
