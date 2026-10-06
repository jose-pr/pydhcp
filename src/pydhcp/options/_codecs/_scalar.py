from __future__ import annotations
import typing as _ty
import enum as _enum
import operator as _operator
from ...exceptions import DHCPDecodeError, DHCPValueError
from ... import _nvt as _nvt
from ..._network import HardwareAddressType as _HardwareAddressType


from ._base import DHCPOptionType, _NormalizedList, _TextForm, _text_argument

_BytesT = _ty.TypeVar("_BytesT", bound="Bytes")


class Bytes(DHCPOptionType, _TextForm, bytes):
    """Opaque byte payload: built from bytes, written as hex text."""

    def __new__(
        cls: type[_BytesT],
        value: _ty.Optional[_ty.Union[bytes, bytearray, memoryview]] = None,
    ) -> _BytesT:
        if isinstance(value, str):
            raise TypeError(
                f"{cls.__name__} is built from bytes, not text: "
                f"use {cls.__name__}.parse for hex text"
            )
        if value is None:
            return super().__new__(cls)
        return super().__new__(cls, value)

    @classmethod
    def parse(cls: type[_BytesT], text: str) -> _BytesT:
        """Build from hex text; spaces and colons between octets are ignored.

        Raises `DHCPValueError` for anything that is not whole hex octets.
        """
        digits = _text_argument(cls, text).replace(":", "")
        try:
            return cls(bytes.fromhex(digits))
        except ValueError as exc:
            raise DHCPValueError(f"not hex octets, {text!r}: {exc}") from exc

    def __repr__(self) -> str:
        return f"{type(self).__name__}({bytes.__repr__(self)})"

    def display_text(self) -> str:
        return bytes.__repr__(self)

    def __str__(self) -> str:
        return self.hex().upper()

    @classmethod
    def unpack_from(cls: type[_BytesT], option: memoryview) -> tuple[_BytesT, int]:
        return cls(option), len(option)

    def pack_into(self, data: bytearray) -> int:
        data.extend(self)
        return len(self)

    def to_json(self) -> str:
        return self.hex()


def _octets(value: _ty.Any) -> Bytes:
    """`value` as octets: bytes-like as is, hex text read as a document holds it.

    The record codecs take their payload from a structured document, where
    octets are written as hex text.
    """
    if isinstance(value, str):
        return Bytes.parse(value)
    return Bytes(value)


_URIListT = _ty.TypeVar("_URIListT", bound="URIList")


class URIList(_NormalizedList[str]):
    """List of UTF-8 URIs encoded as repeated U16-length-prefixed entries."""

    def __init__(self, *items: _ty.Any):
        if len(items) == 1 and isinstance(items[0], list):
            self.extend(items[0])
            return
        for item in items:
            self.append(item)

    @classmethod
    def _normalize(cls, item: _ty.Any) -> str:
        if isinstance(item, str):
            return item
        return str(item)

    @classmethod
    def unpack_from(cls: type[_URIListT], option: memoryview) -> tuple[_URIListT, int]:
        self = cls()
        idx = 0
        size = len(option)
        while idx < size:
            if idx + 2 > size:
                raise DHCPDecodeError(f"{cls.__name__} option is truncated")
            length = int.from_bytes(option[idx : idx + 2], "big")
            idx += 2
            if idx + length > size:
                raise DHCPDecodeError(f"{cls.__name__} option is truncated")
            payload = option[idx : idx + length].tobytes()
            try:
                decoded = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DHCPDecodeError(
                    f"{cls.__name__} option contains invalid UTF-8"
                ) from exc
            self.append(decoded)
            idx += length
        return self, size

    def pack_into(self, data: bytearray) -> int:
        written = 0
        for item in self:
            encoded = item.encode("utf-8")
            if len(encoded) > 0xFFFF:
                raise DHCPValueError(f"{type(self).__name__} entry exceeds 65535 bytes")
            data.extend(len(encoded).to_bytes(2, "big"))
            data.extend(encoded)
            written += len(encoded) + 2
        return written

    def to_json(self) -> list[str]:
        return list(self)


_StringT = _ty.TypeVar("_StringT", bound="String")


class String(DHCPOptionType, str):
    """RFC 2132 NVT-ASCII string with null termination on the wire.

    Octets that are not valid UTF-8 are preserved rather than replaced, so a
    hostname or boot filename in another encoding survives a decode/encode round
    trip intact; `to_json` renders the display form. See `pydhcp._nvt`.
    """

    def __new__(cls: type[_StringT], value: _ty.Any = "") -> _StringT:
        """Text, or octets read as text; anything else is a `TypeError`.

        `None` is not an empty string: an option with nothing to say is deleted
        from the bag, not stored.
        """
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = _nvt.decode(bytes(value), "Option string")
        elif not isinstance(value, str):
            raise TypeError(
                f"{cls.__name__} is built from text, not {type(value).__name__}"
            )
        return str.__new__(cls, value)

    @classmethod
    def unpack_from(cls: type[_StringT], option: memoryview) -> tuple[_StringT, int]:
        text, _, _ = option.tobytes().partition(b"\x00")
        return cls(_nvt.decode(text, "Option string")), len(option)

    def pack_into(self, data: bytearray) -> int:
        text = _nvt.encode(self)
        data.extend(text)
        return len(text)

    def to_json(self) -> str:
        return _nvt.display(self)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str.__repr__(self)})"

    def display_text(self) -> str:
        return str.__repr__(self)


_OctetStringT = _ty.TypeVar("_OctetStringT", bound="OctetString")


class OctetString(String):
    """Text that is the whole payload: no NUL terminator, no truncation.

    RFC 2132 s9.13 defines option 60 as "a string of n octets" -- not a
    NUL-terminated NVT string. `String` partitions at the first NUL, so a vendor
    class identifier that is binary, as embedded and CPE firmware sends, decoded
    to the empty string and lost everything a server might have matched on.
    Octets that are not valid UTF-8 are preserved, as in `String`.
    """

    @classmethod
    def unpack_from(
        cls: type[_OctetStringT], option: memoryview
    ) -> tuple[_OctetStringT, int]:
        return cls(_nvt.decode(option.tobytes(), "Option octet string")), len(option)


_BooleanT = _ty.TypeVar("_BooleanT", bound="Boolean")


class Boolean(DHCPOptionType, int):
    """Boolean option encoded as a single octet."""

    def __new__(cls: type[_BooleanT], val: _ty.Any) -> _BooleanT:
        if val:
            val = 1
        else:
            val = 0
        return super().__new__(cls, val)

    @classmethod
    def unpack_from(cls: type[_BooleanT], option: memoryview) -> tuple[_BooleanT, int]:
        return cls(option[0]), 1

    def pack_into(self, data: bytearray) -> int:
        data.append(self)
        return 1

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        return 1

    def __repr__(self) -> str:
        return f"{type(self).__name__}({bool(self)!r})"

    def display_text(self) -> str:
        return f"Boolean({bool(self)!r})"

    def to_json(self) -> bool:
        return self.__bool__()


_FlagT = _ty.TypeVar("_FlagT", bound="Flag")


class Flag(DHCPOptionType):
    """Zero-length presence option.

    Some options carry their whole meaning in being present at all -- RFC 4039's
    Rapid Commit is "Code 80, Len 0". Encoding such an option as a one-octet
    Boolean both rejects conformant packets on decode and emits a malformed
    option on encode.
    """

    __slots__ = ()

    def __init__(self, value: _ty.Any = True) -> None:
        # A zero-length option says everything by being there, so there is no
        # false to encode. Rejecting a falsy value keeps `opts[code] = False`
        # from reading as "off" while actually setting the flag.
        if not value:
            raise DHCPValueError(
                f"{type(self).__name__} is a presence-only option; delete the "
                "option to express absence instead of assigning a false value"
            )

    @classmethod
    def unpack_from(cls: type[_FlagT], option: memoryview) -> tuple[_FlagT, int]:
        return cls(), 0

    def pack_into(self, data: bytearray) -> int:
        return 0

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        return 0

    def __bool__(self) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Flag):
            return NotImplemented
        return True

    def __hash__(self) -> int:
        return hash(type(self))

    def to_json(self) -> bool:
        return True

    def __repr__(self) -> str:
        return "Flag()"


_BaseFixedLengthIntegerT = _ty.TypeVar(
    "_BaseFixedLengthIntegerT", bound="BaseFixedLengthInteger"
)


class BaseFixedLengthInteger(DHCPOptionType, int):
    NUMBER_OF_BYTES: int
    SIGNED: bool = False

    @classmethod
    def unpack_from(
        cls: type[_BaseFixedLengthIntegerT], option: memoryview
    ) -> tuple[_BaseFixedLengthIntegerT, int]:
        option_part = option[: cls.NUMBER_OF_BYTES]
        if len(option_part) != cls.NUMBER_OF_BYTES:
            raise DHCPDecodeError(
                f"{cls.__name__} needs {cls.NUMBER_OF_BYTES} octets, "
                f"got {len(option_part)}"
            )
        return (
            cls(int.from_bytes(option_part, "big", signed=cls.SIGNED)),
            cls.NUMBER_OF_BYTES,
        )

    def pack_into(self, data: bytearray) -> int:
        self._validate()
        data.extend(self.to_bytes(self.NUMBER_OF_BYTES, "big", signed=self.SIGNED))
        return self.NUMBER_OF_BYTES

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        return cls.NUMBER_OF_BYTES

    def _validate(self) -> None:
        bits = self.NUMBER_OF_BYTES * 8
        if self.SIGNED:
            low, high = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        else:
            low, high = 0, (1 << bits) - 1
        if low <= self <= high:
            return
        if self > high:
            what = "Number is too big"
        else:
            what = "Number is too small" if self.SIGNED else "Value must not be signed"
        raise DHCPValueError(
            f"{what}: {type(self).__name__} holds {low} to {high}, not {int(self)}"
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)!r})"

    def to_json(self) -> int:
        """A plain `int`, not this subclass.

        The base `to_json` returns `self`, and `self` is a `U16`/`U32`. JSON
        tolerates an int subclass; YAML refuses to represent it and TOML writes
        something it cannot read back, so a packet carrying any integer option
        -- which is most real packets, via option 57 or 51 -- could not survive
        a round trip through either.
        """
        return int(self)


_FixedLengthIntegerT = _ty.TypeVar("_FixedLengthIntegerT", bound="FixedLengthInteger")


class FixedLengthInteger(BaseFixedLengthInteger):
    def __new__(cls: type[_FixedLengthIntegerT], val: _ty.Any) -> _FixedLengthIntegerT:
        # Text is a number as a document writes it; anything else must be a
        # whole number already, so 1.9 is refused and not cut to 1.
        if not isinstance(val, str):
            try:
                val = _operator.index(val)
            except TypeError:
                raise TypeError(
                    f"{cls.__name__} is built from a whole number, "
                    f"not {type(val).__name__}"
                ) from None
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


_ClientIdentifierT = _ty.TypeVar("_ClientIdentifierT", bound="ClientIdentifier")


class ClientIdentifier(Bytes):
    """RFC 2132 client identifier."""

    @classmethod
    def unpack_from(
        cls: type[_ClientIdentifierT], option: memoryview
    ) -> tuple[_ClientIdentifierT, int]:
        if len(option) < 2:
            raise DHCPDecodeError(
                f"{cls.__name__} option is truncated: needs a type octet and an identifier"
            )
        return super().unpack_from(option)

    def pack_into(self, data: bytearray) -> int:
        if len(self) < 2:
            raise DHCPValueError(
                f"{type(self).__name__} needs at least 2 octets, a type and an "
                f"identifier (RFC 2132 section 9.14), got {len(self)}"
            )
        return super().pack_into(data)

    def display_text(self) -> str:
        if not self:
            return ""
        ty_val = self[0]
        addr = self[1:]
        ty_str = str(ty_val)
        try:
            ty_str = _HardwareAddressType(ty_val).label()
        except ValueError:
            ...
        maybe = f"{ty_str}({addr.hex(':').upper()})"

        return f"{maybe}|{self}"

    def __str__(self) -> str:
        return self.hex(":").upper()


_OptionOverloadT = _ty.TypeVar("_OptionOverloadT", bound="OptionOverload")


class OptionOverload(DHCPOptionType, _enum.IntFlag):
    """RFC 2132 option-overload selector."""

    NONE = 0
    FILE = 1
    SNAME = 2
    BOTH = FILE | SNAME

    def __repr__(self) -> str:
        if self.name is None:
            return f"{type(self).__name__}({int(self)})"
        return f"{type(self).__name__}.{self.name}"

    def display_text(self) -> str:
        return _enum.IntFlag.__repr__(self)

    @classmethod
    def unpack_from(
        cls: type[_OptionOverloadT], option: memoryview
    ) -> tuple[_OptionOverloadT, int]:
        option_part = option[:1]
        if len(option_part) != 1:
            raise DHCPDecodeError(
                "OPTION_OVERLOAD needs 1 octet, got 0 (RFC 2132 s9.3)"
            )
        return cls(option_part[0]), 1

    def pack_into(self, data: bytearray) -> int:
        data.append(self.value)
        return 1

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        return 1
