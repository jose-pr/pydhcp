from __future__ import annotations
from collections.abc import Iterable
import typing as _ty
from . import _utils
import enum as _enum
from .log import LOGGER

if _ty.TYPE_CHECKING:
    from typing_extensions import Self
    from ._options import BaseDhcpOptionCode

from .netutils import IPv4 as _IP, IPv4Interface as _Interface, IPv4Network as _Network


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


class IPv4Address(DhcpOptionType, _IP):
    """A single IPv4 address carried in network byte order."""
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        return cls(option[:4].tobytes()), 4

    def _dhcp_write(self, data: bytearray) -> int:
        data.extend(self.packed)
        return 4

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return 4

    def __repr__(self) -> str:
        return str(self)

    def __json__(self) -> str:
        return str(self)


class ClasslessRoute(DhcpOptionType):
    """RFC 3442 classless static route entry."""
    def __init__(self, gateway: _IP, network: _Network) -> None:
        self.gateway = _IP(gateway)
        self.network = _Network(network)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 1:
            raise ValueError("ClasslessRoute option is truncated: missing prefix length")
        cidr = option[0]
        if cidr > 32:
            raise ValueError(f"ClasslessRoute prefix length {cidr} exceeds 32")
        last = 1 + (cidr + 7) // 8
        if len(option) < last + 4:
            raise ValueError(
                f"ClasslessRoute option is truncated: needs {last + 4} bytes, got {len(option)}"
            )
        net_bytes = option[1:last].tobytes() + b"\x00\x00\x00\x00"
        network = _Network((net_bytes[:4], cidr))
        gateway = _IP(option[last : last + 4].tobytes())
        return cls(gateway, network), last + 4

    def _dhcp_write(self, data: bytearray) -> int:
        cidr = self.network.prefixlen
        last = (cidr + 7) // 8
        network = self.network.network_address.packed[:last]
        data.append(cidr)
        data.extend(network)
        data.extend(self.gateway.packed)
        return last + 5

    def __repr__(self) -> str:
        return f"ClasslessRoute(gateway={self.gateway}, network={self.network})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ClasslessRoute):
            return NotImplemented
        return (self.gateway, self.network) == (other.gateway, other.network)

    def __json__(self) -> list[_ty.Any]:
        return [str(self.gateway), str(self.network)]


class Bytes(DhcpOptionType, bytes):
    """Opaque byte payload."""
    def __new__(cls, src: _ty.Optional[_ty.Union[bytes, bytearray, memoryview, str]] = None) -> Self:
        if isinstance(src, str):
            return cls.fromhex(src)
        if src is None:
            return super().__new__(cls)
        return super().__new__(cls, src)

    def __repr__(self) -> str:
        return str(bytes(self))

    def __str__(self) -> str:
        return self.hex().upper()

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        return cls(option), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        data.extend(self)
        return len(self)

    def __json__(self) -> str:
        return self.hex()


class String(DhcpOptionType, str):
    """RFC 2132 NVT-ASCII string with null termination on the wire."""
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        text, _, _ = option.tobytes().partition(b"\x00")
        try:
            decoded_text = text.decode("utf-8")
        except UnicodeDecodeError:
            LOGGER.warning(f"Option contains invalid UTF-8: {text.hex()}")
            decoded_text = text.decode("utf-8", errors="replace")
        return cls(decoded_text), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        text = self.encode()
        data.extend(text)
        return len(text)


class Boolean(DhcpOptionType, int):
    """Boolean option encoded as a single octet."""
    def __new__(cls, val: _ty.Any) -> Self:
        if val:
            val = 1
        else:
            val = 0
        return super().__new__(cls, val)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        return cls(option[0]), 1

    def _dhcp_write(self, data: bytearray) -> int:
        data.append(self)
        return 1

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return 1

    def __repr__(self) -> str:
        return f"Boolean({bool(self)!r})"

    def __json__(self) -> bool:
        return self.__bool__()


class BaseFixedLengthInteger(DhcpOptionType, int):
    NUMBER_OF_BYTES: int
    SIGNED: bool = False

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        option_part = option[: cls.NUMBER_OF_BYTES]
        if len(option_part) != cls.NUMBER_OF_BYTES:
            raise ValueError()
        return cls(int.from_bytes(option_part, "big", signed=cls.SIGNED)), cls.NUMBER_OF_BYTES

    def _dhcp_write(self, data: bytearray) -> int:
        self._validate()
        data.extend(self.to_bytes(self.NUMBER_OF_BYTES, "big", signed=self.SIGNED))
        return self.NUMBER_OF_BYTES

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return cls.NUMBER_OF_BYTES

    def _validate(self) -> None:
        if self.bit_length() > self.NUMBER_OF_BYTES * 8:
            raise ValueError("Number is too big")
        if not self.SIGNED and self < 0:
            raise ValueError("Value must not be signed")

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)!r})"


class FixedLengthInteger(BaseFixedLengthInteger):
    def __new__(cls, val: _ty.Any) -> Self:
        val_obj = int.__new__(cls, val)
        val_obj._validate()
        return val_obj


class U8(FixedLengthInteger):
    """Unsigned 8-bit integer."""
    NUMBER_OF_BYTES = 1
    SIGNED = False


class U16(FixedLengthInteger):
    """Unsigned 16-bit integer."""
    NUMBER_OF_BYTES = 2
    SIGNED = False


class U32(FixedLengthInteger):
    """Unsigned 32-bit integer."""
    NUMBER_OF_BYTES = 4
    SIGNED = False


class I32(FixedLengthInteger):
    """Signed 32-bit integer."""
    NUMBER_OF_BYTES = 4
    SIGNED = True


class DomainList(DhcpOptionType, list[str]):
    """RFC 1035 domain-name list with compression support."""
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        view = memoryview(option)
        self = cls()
        if not option:
            return self, 0
        components: dict[int, str | int | None] = _ty.OrderedDict()
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

        def get_dn(id: int) -> list[str]:
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

    def _dhcp_write(self, _data: bytearray) -> int:
        components: list[tuple[list[str], int]] = []
        data = bytearray()
        for domain_str in self:
            domain = domain_str.split(".")
            unique = domain
            parent: _ty.Optional[tuple[int, int]] = None
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
            for comp in unique:
                data.append(len(comp))
                data.extend(comp.encode())
            if parent is None:
                data.append(0x00)
            else:
                data.extend((0xC000 | parent[0]).to_bytes(2, byteorder="big"))
        _data.extend(data)
        return len(data)


class ClientIdentifier(Bytes):
    """RFC 2132 client identifier."""
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 2:
            raise ValueError(option)
        return super()._dhcp_read(option)

    def __repr__(self) -> str:
        ty_val = self[0]
        addr = self[1:]
        ty_str = str(ty_val)
        try:
            from .enum import HardwareAddressType

            ty_str = HardwareAddressType(ty_val).name
        except ValueError:
            ...
        maybe = f"{ty_str}({addr.hex(':').upper()})"

        return f"{maybe}|{self}"

    def __str__(self) -> str:
        return self.hex(":").upper()


class OptionOverload(DhcpOptionType, _enum.IntFlag):
    """RFC 2132 option-overload selector."""
    NONE = 0
    FILE = 1
    SNAME = 2
    BOTH = FILE | SNAME

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        option_part = option[:1]
        if len(option_part) != 1:
            raise ValueError()
        return cls(option_part[0]), 1

    def _dhcp_write(self, data: bytearray) -> int:
        data.append(self.value)
        return 1

    @classmethod
    def _dhcp_len_hint(cls) -> int | None:
        return 1
