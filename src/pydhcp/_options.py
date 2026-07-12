from __future__ import annotations
import typing as _ty
import struct as _struct

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from .netutils import IPv4 as _IP
from .optiontype import Bytes, DhcpOptionType


class BaseDhcpOptionCode:
    def get_type(self) -> "type[DhcpOptionType]":
        return Bytes

    def label(self) -> str:
        return "UNKNOWN"

    @classmethod
    def from_code(cls, code: int) -> "BaseDhcpOptionCode":
        return cls(code)  # type: ignore[call-arg]

    def __int__(self) -> int:
        return 0

    def __repr__(self) -> str:
        code_val = int(self) if isinstance(self, int) else 0
        return f"[{code_val:0>3}]{self.label()}"

    def __str__(self) -> str:
        return self.label()
    
    @classmethod
    def normalize(cls, code: int, value: object) -> DhcpOption:
        _code = cls.from_code(code)
        return DhcpOption(_code, _code.get_type()(value))  # type: ignore[call-arg]
    
    @classmethod
    def decode(cls, code: int, value: bytearray) -> DhcpOption:
        _code = cls.from_code(code)
        return DhcpOption(_code, _code.get_type()._dhcp_decode(value))

class DhcpOption(_ty.NamedTuple):
    code: _ty.Union[int, "BaseDhcpOptionCode"]
    value: "DhcpOptionType"
