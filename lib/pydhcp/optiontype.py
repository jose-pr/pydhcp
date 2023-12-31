from collections.abc import Iterable
import typing as _ty
from . import _utils
import enum as _enum

if _ty.TYPE_CHECKING:
    from typing_extensions import Self
    from ._options import BaseDhcpOptionCode

from .netutils import IPv4 as _IP, IPv4Interface as _Interface, IPv4Network as _Network


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
        decoded, read = cls._dhcp_read(option)
        if read != todecode:
            raise ValueError("Couldnt decode whole option")
        return decoded


_T = _ty.TypeVar("_T", bound=DhcpOptionType)
_C = _ty.TypeVar("_C", bound="BaseDhcpOptionCode")


class List(DhcpOptionType, list[_T], metaclass=_utils.GenericMeta):
    _args_: _ty.ClassVar[tuple[_T]]  # type:ignore

    def __init__(self, *items: _ty.Iterable[_T] | _T):
        for _items in items:
            self.extend(_items if isinstance(_items, (tuple, list)) else (_items,))

    @classmethod
    def _normalize(cls, item: _T) -> _T:
        ty = cls._args_[0]
        return ty(item) if not isinstance(item, ty) else item

    def __setitem__(self, idx, item: _T) -> None:
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

    def _dhcp_write(self, data: bytearray):
        written = 0
        for item in self:
            written += item._dhcp_write(data)
        return written


class DhcpOptionCodes(List[_C]):
    @classmethod
    def _normalize(cls, item: _T) -> _T:
        ty = cls._args_[0]
        if isinstance(item, ty):
            return item
        try:
            return ty(item)
        except:
            ...
        item = int(item)
        if item > 255:
            raise ValueError()
        return item

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        return cls(option.tolist()), len(option)

    def _dhcp_write(self, data: bytearray):
        data.extend(self)
        return len(self)


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

    def _json_(self) -> str:
        return str(self)


class ClasslessRoute(DhcpOptionType):
    def __init__(self, gateway: _IP, network: _Network) -> None:
        self.gateway = _IP(gateway)
        self.network = _Network(network)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        cidr = option[0]
        last, rem = divmod(cidr, 4)
        last += rem + 1
        network = option[1:last].tobytes() + b"\x00\x00\x00\x00"
        network = _Network((network[:4], cidr))
        return cls(next, option[last : last + 4].tobytes()), last + 4

    def _dhcp_write(self, data: bytearray):
        cidr = self.network.prefixlen
        last, rem = divmod(cidr, 4)
        last += rem
        network = self.network.network_address.packed[:last]
        data.append(cidr)
        data.extend(network)
        data.extend(self.gateway.packed)
        return last + 5


class Bytes(DhcpOptionType, bytes):
    def __new__(cls, src=None) -> "Self":
        if isinstance(src, str):
            return cls.fromhex(src)
        return super().__new__(cls, src)

    def __repr__(self) -> str:
        return str(bytes(self))

    def __str__(self) -> str:
        return self.hex().upper()

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        return cls(option), len(option)

    def _dhcp_write(self, data: bytearray):
        data.extend(self)
        return len(self)

    def _json_(self) -> str:
        return self.hex(" ")


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

    def _json_(self):
        return self.__bool__()


class BaseFixedLengthInteger(DhcpOptionType):
    NUMBER_OF_BYTES: int
    SIGNED: bool = False

    @classmethod
    def _dhcp_read(cls: "type[int|Self]", option: memoryview) -> tuple["Self", int]:
        option = option[: cls.NUMBER_OF_BYTES]
        if len(option) != cls.NUMBER_OF_BYTES:
            raise ValueError()
        return cls.from_bytes(option, "big", signed=cls.SIGNED), cls.NUMBER_OF_BYTES

    def _dhcp_write(self: "int|Self", data: bytearray):
        data.extend(self.to_bytes(self.NUMBER_OF_BYTES, "big", signed=self.SIGNED))
        return self.NUMBER_OF_BYTES

    @classmethod
    def _dhcp_len_hint(self) -> int:
        return self.NUMBER_OF_BYTES

    def _validate(self: "type[int|Self]"):
        if self.bit_length() > self.NUMBER_OF_BYTES * 8:
            raise ValueError("Number is too  big")
        if not self.SIGNED and self < 0:
            raise ValueError("Value must not be signed")


class FixedLengthInteger(BaseFixedLengthInteger, int):
    def __new__(cls, val):
        val = super().__new__(cls, val)
        val._validate()
        return val


class U8(FixedLengthInteger):
    NUMBER_OF_BYTES = 1
    SIGNED = False


class U16(FixedLengthInteger):
    NUMBER_OF_BYTES = 2
    SIGNED = False


class U32(FixedLengthInteger):
    NUMBER_OF_BYTES = 4
    SIGNED = False


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
            ptr_or_len = view[id]
            id += 1
            if ptr_or_len == 0x00:
                components[id - 1] = None
                domains.append(id)
                continue
            is_ptr = ptr_or_len & 0xC0
            if is_ptr:
                if is_ptr != 0xC0:
                    raise ValueError()
                components[id - 1] = ((0x3F & ptr_or_len) << 8) | view[id]
                id += 1
            else:
                dc = view[id : ptr_or_len + id]
                if len(dc) != ptr_or_len:
                    raise ValueError()
                components[id - 1] = dc.tobytes().decode()
                id += ptr_or_len

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


class ClientIdentifier(Bytes):
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        if len(option) < 2:
            raise ValueError(option)
        return super()._dhcp_read(option)

    def __repr__(self) -> str:
        ty = self[0]
        addr = self[1:]
        try:
            from .enum import HardwareAddressType

            ty = HardwareAddressType(ty).name
        except:
            ...
        maybe = f"{ty}({addr.hex(':').upper()})"

        return f"{maybe}|{self}"

    def __str__(self) -> str:
        return self.hex(":").upper()


class OptionOverload(BaseFixedLengthInteger, _enum.Flag):
    @classmethod
    @property
    def NUMBER_OF_BYTES(self):
        return 1

    @classmethod
    @property
    def SIGNED(self):
        return False

    NONE = 0
    FILE = 1
    SNAME = 2
    BOTH = FILE | SNAME
