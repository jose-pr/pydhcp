from __future__ import annotations
import typing as _ty

from .type import Bytes, DHCPOptionType


class BaseDHCPOptionCode:
    def get_type(self) -> "type[DHCPOptionType]":
        return Bytes

    def label(self) -> str:
        return "UNKNOWN"

    @classmethod
    def from_code(cls, code: int) -> "BaseDHCPOptionCode":
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
    def normalize(cls, code: int, value: object) -> DHCPOption:
        _code = cls.from_code(code)
        return DHCPOption(_code, _code.get_type()(value))  # type: ignore[call-arg]

    @classmethod
    def decode(cls, code: int, value: bytearray) -> DHCPOption:
        _code = cls.from_code(code)
        return DHCPOption(_code, _code.get_type()._dhcp_decode(value))


class DHCPOption(_ty.NamedTuple):
    code: _ty.Union[int, "BaseDHCPOptionCode"]
    value: "DHCPOptionType"
