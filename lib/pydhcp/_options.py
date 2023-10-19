import typing as _ty
import struct as _struct

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from .netutils import IPv4 as _IP
from .optiontype import Bytes, DhcpOptionType


class DhcpOptionCode:
    def get_type(code) -> "type[DhcpOptionType]":
        return Bytes

    def label(code) -> str:
        return "UNKNOWN"

    @classmethod
    def from_code(cls, code: int):
        return cls(code)

    def __repr__(self):
        return f"[{int(self):0>3}]{self.label()}"

    def __str__(self):
        return self.label()
    
    @classmethod
    def normalize(cls, code:int, value: object):
        _code = cls.from_code(code)
        return DhcpOption(_code, _code.get_type()(value))
    
    @classmethod
    def decode(cls, code:int, value: bytearray):
        _code = cls.from_code(code)
        return DhcpOption(_code, _code.get_type()._dhcp_decode(value))

class DhcpOption(_ty.NamedTuple):
    code: int
    value: "DhcpOptionType"
