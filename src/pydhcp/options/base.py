from __future__ import annotations
import typing as _ty

from .type import Bytes, DhcpOptionType


class BaseDhcpOptionCode:
    def get_type(self) -> "type[DhcpOptionType]":
        return Bytes

    def label(self) -> str:
        return "UNKNOWN"

    @classmethod
    def from_code(cls, code: int) -> "BaseDhcpOptionCode":
        return cls(code)  # type: ignore[call-arg]

    def __int__(self) -> int:
        """The option code as a byte value.

        A subclass that carries neither a `value` (the enum case) nor an
        integer identity of its own has no option code, and this used to
        answer `0` for it. Zero is not a neutral answer: it is PAD, the wire
        padding marker, so such a code silently addressed option 0 -- it
        stored, encoded and emitted as a PAD TLV. Raising says what is true.
        """
        if hasattr(self, "value"):
            return int(self.value)
        if isinstance(self, int):
            return int.__index__(self)
        raise TypeError(
            f"{type(self).__name__} has no option-code value: give the class an "
            "int `value` (an IntEnum member does) or make it an `int` subclass"
        )

    def __json__(self) -> int:
        return int(self)

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
