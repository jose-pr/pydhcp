import typing as _ty
import struct as _struct

if _ty.TYPE_CHECKING:
    from typing_extensions import Self

from .netutils import IPAddress as _IP
from .optiontype import Bytes, DhcpOptionType


class DhcpOptionCodeMap:
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

class DhcpOption(_ty.NamedTuple):
    code: int
    value: "DhcpOptionType"

    def encode(self) -> bytearray:
        return self.value._dhcp_encode()
