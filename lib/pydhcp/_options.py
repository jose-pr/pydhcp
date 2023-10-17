import typing as _ty
import struct as _struct

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from .netutils import IPAddress as _IP


class DhcpOptionCodeMap:
    def get_type(code) -> "type[DhcpOptionType]":
        return GenericDhcpOptionType

    def label(code) -> str:
        return "UNKNOWN"

    @classmethod
    def from_code(cls, code: int):
        return cls(code)

    def __repr__(self):
        return f"[{int(self):0>3}]{self.label()}"

    def __str__(self):
        return self.label()


class DhcpOptionType:
    def __init__(self, *args) -> None:
        pass

    @classmethod
    def decode(cls, option: bytearray) -> "Self":
        return NotImplementedError()

    def encode(self) -> bytearray:
        return NotImplementedError()


class GenericDhcpOptionType(DhcpOptionType):
    data: bytearray

    @classmethod
    def decode(cls, option: bytearray) -> "Self":
        self = cls()
        self.data = option
        return self

    def encode(self) -> bytearray:
        return self.data

    def __repr__(self) -> str:
        return str(bytes(self.data))


class StringDhcpOptionType(DhcpOptionType):
    data: str

    def __init__(self, text) -> None:
        self.data = text

    @classmethod
    def decode(cls, option: bytearray) -> "Self":
        text, _, _ = option.partition(b"\x00")
        text.decode()
        return cls(text.decode())

    def encode(self) -> bytearray:
        return self.data.encode()

    def __repr__(self) -> str:
        return self.data


class U16DhcpOptionType(DhcpOptionType):
    data: int

    def __int__(self):
        return self.data

    @classmethod
    def decode(cls, option: bytearray) -> "Self":
        if len(option) != 2:
            raise ValueError(option)
        self = cls()
        self.data = _struct.unpack("!H", option)[0]
        return self

    def encode(self) -> bytearray:
        return _struct.pack("!H", self.data)

    def __repr__(self) -> str:
        return str(self.data)


class U32DhcpOptionType(DhcpOptionType):
    data: int

    def __init__(self, u32=0) -> None:
        self.data = int(u32)

    @classmethod
    def decode(cls, option: bytearray) -> "Self":
        if len(option) != 4:
            raise ValueError(option)
        return cls(_struct.unpack("!I", option)[0])

    def encode(self) -> bytearray:
        return _struct.pack("!I", self.data)

    def __repr__(self) -> str:
        return str(self.data)


class IPv4DhcpOptionType(DhcpOptionType):
    ip: _IP

    def __init__(self, ip: _IP) -> None:
        self.ip = _IP(ip)

    @classmethod
    def decode(cls, option: bytearray) -> "Self":
        if len(option) != 4:
            raise ValueError(option)
        self = cls(bytes(option))
        return self

    def encode(self) -> bytearray:
        return self.ip.packed

    def __repr__(self) -> str:
        return str(self.ip)


class IPsv4DhcpOptionType(DhcpOptionType):
    ips: list[_IP]

    def __init__(self, *ips: _IP | list[_IP]) -> None:
        self.ips = []
        for _ips in ips:
            if not isinstance(_ips, (tuple, list)):
                _ips = (_ips,)
            for ip in _ips:
                self.ips.append(_IP(ip))

    @classmethod
    def decode(cls, option: bytearray) -> "Self":
        if len(option) % 4 != 0:
            raise ValueError(option)
        view = memoryview(option)
        self = cls()
        while view:
            self.ips.append(_IP(view[:4].tobytes()))
            view = view[4:]
        return self

    def encode(self) -> bytearray:
        data = bytearray()
        for ip in self.ips:
            data.extend(ip.packed)
        return data

    def __repr__(self) -> str:
        return "\n".join([str(ip) for ip in self.ips])

    def __str__(self) -> str:
        return "[" + ",".join([str(ip) for ip in self.ips]) + "]"


class DomainListDhcpOptionType(DhcpOptionType):
    domains: list[str]

    @classmethod
    def decode(cls, option: bytearray) -> "Self":
        view = memoryview(option)
        self = cls()
        self.domains = []
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
            self.domains.append(".".join(get_dn(domain)))
        return self

    def encode(self) -> bytearray:
        components: list[tuple[list[str], int | None]] = []
        data = bytearray()
        for domain in self.domains:
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
        return data

    def __repr__(self) -> str:
        return "\n".join(self.domains)

    def __str__(self) -> str:
        return str(self.domains)


class DhcpOption(_ty.NamedTuple):
    code: int
    value: "DhcpOptionType"

    def encode(self) -> bytearray:
        return self.value.encode()
