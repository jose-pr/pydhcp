"""A codec written from the options header's "Writing a codec" section alone.

The classes below use only what that section lists: the constructor,
`unpack_from`, `pack_into`, and the optional `fixed_size`, `to_json` and
`display_text`. Registering one is process-wide, so each test restores option
224 to the opaque default.
"""

from __future__ import annotations

import typing as _ty

import pytest

from pydhcp import DHCPDecodeError, DHCPMessage, DHCPOptionCode, DHCPOptions
from pydhcp import DHCPValueError
from pydhcp.options import Bytes, DHCPOptionType, OptionCodec
from conftest import build_request

CODE = 224
FORMATS = ("json", "yaml", "toml", "ini")


class Beacon(DHCPOptionType):
    """One octet of site number, then the label's UTF-8."""

    def __init__(self, value: _ty.Any) -> None:
        if isinstance(value, Beacon):
            value = value.to_json()
        site, label = value["site"], value["label"]
        if not 0 <= site <= 255:
            raise DHCPValueError(f"site {site} does not fit an octet")
        self.site = int(site)
        self.label = str(label)

    @classmethod
    def unpack_from(cls, option: memoryview) -> tuple[Beacon, int]:
        if len(option) < 1:
            raise DHCPDecodeError("a Beacon needs a site octet")
        value = cls({"site": option[0], "label": bytes(option[1:]).decode()})
        return value, len(option)

    def pack_into(self, buffer: bytearray) -> int:
        payload = bytes([self.site]) + self.label.encode()
        buffer.extend(payload)
        return len(payload)

    def to_json(self) -> dict[str, _ty.Any]:
        return {"site": self.site, "label": self.label}

    def display_text(self) -> str:
        return f"site {self.site}: {self.label}"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Beacon) and self.to_json() == other.to_json()

    def __hash__(self) -> int:
        return hash((self.site, self.label))


class Level(DHCPOptionType):
    """Two octets, big-endian; a value is its number."""

    def __init__(self, value: _ty.Any) -> None:
        self.number = int(value)
        if not 0 <= self.number <= 0xFFFF:
            raise DHCPValueError("a Level fits two octets")

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        return 2

    @classmethod
    def unpack_from(cls, option: memoryview) -> tuple[Level, int]:
        return cls(int.from_bytes(option[:2], "big")), 2

    def pack_into(self, buffer: bytearray) -> int:
        buffer.extend(self.number.to_bytes(2, "big"))
        return 2

    def to_json(self) -> int:
        return self.number

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Level) and other.number == self.number


class PlainCodec:
    """Not a `DHCPOptionType`: it has the methods of `OptionCodec` and nothing else."""

    def __init__(self, value: _ty.Any) -> None:
        self.text = str(value)

    @classmethod
    def unpack(cls, data: _ty.Any) -> PlainCodec:
        return cls(bytes(data).decode())

    @classmethod
    def unpack_from(cls, option: memoryview) -> tuple[PlainCodec, int]:
        return cls(bytes(option).decode()), len(option)

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        return None

    def pack(self) -> bytes:
        return self.text.encode()

    def pack_into(self, buffer: bytearray) -> int:
        buffer.extend(self.text.encode())
        return len(self.text)

    def to_json(self) -> str:
        return self.text

    def display_text(self) -> str:
        return f"plain {self.text}"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PlainCodec) and other.text == self.text


@pytest.fixture(autouse=True)
def _restore_option_224() -> _ty.Iterator[None]:
    yield
    DHCPOptionCode(CODE).register_type(Bytes)


def _message(value: _ty.Any) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = 1
    options[CODE] = value
    return build_request(options=options)


def test_a_codec_registers_decodes_and_encodes() -> None:
    DHCPOptionCode(CODE).register_type(Beacon)
    assert DHCPOptionCode(CODE).get_type() is Beacon

    options = DHCPOptions()
    options[CODE] = Beacon({"site": 7, "label": "north"})
    assert bytes(options[CODE]) == b"\x07north"
    assert options.get(CODE) == Beacon({"site": 7, "label": "north"})
    assert Beacon.unpack(b"\x07north").label == "north"
    assert Beacon({"site": 7, "label": "north"}).pack() == b"\x07north"


def test_a_value_the_constructor_accepts_is_built_on_assignment() -> None:
    DHCPOptionCode(CODE).register_type(Beacon)
    options = DHCPOptions()
    options[CODE] = {"site": 2, "label": "b"}
    assert options.get(CODE) == Beacon({"site": 2, "label": "b"})
    with pytest.raises(DHCPValueError):
        options[CODE] = {"site": 999, "label": "b"}


def test_a_message_round_trips_the_codec_and_displays_it() -> None:
    DHCPOptionCode(CODE).register_type(Beacon)
    message = _message(Beacon({"site": 1, "label": "gate"}))
    again = DHCPMessage.decode(message.encode())
    assert again.options.get(CODE) == Beacon({"site": 1, "label": "gate"})
    assert "site 1: gate" in again.summary()


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_message_round_trips_through_each_structured_format(fmt: str) -> None:
    DHCPOptionCode(CODE).register_type(Beacon)
    message = _message(Beacon({"site": 3, "label": "dock"}))
    text = message.to_text(fmt)
    again = DHCPMessage.from_text(text, fmt)
    assert again.options.get(CODE) == Beacon({"site": 3, "label": "dock"})
    assert bytes(again) == bytes(message)


def test_the_fixed_size_is_checked_and_trailing_octets_are_refused() -> None:
    DHCPOptionCode(CODE).register_type(Level)
    assert Level.unpack(b"\x01\x02").number == 0x0102
    for wrong in (b"\x01", b"\x01\x02\x03"):
        with pytest.raises(DHCPDecodeError):
            Level.unpack(wrong)
    options = DHCPOptions()
    options[CODE] = 258
    assert bytes(options[CODE]) == b"\x01\x02"


def test_a_constructor_error_while_unpacking_is_a_decode_error() -> None:
    class Strict(DHCPOptionType):
        def __init__(self, value: _ty.Any) -> None:
            if value == 0:
                raise DHCPValueError("zero is not allowed")
            self.value = value

        @classmethod
        def unpack_from(cls, option: memoryview) -> tuple[Strict, int]:
            return cls(option[0]), 1

        def pack_into(self, buffer: bytearray) -> int:
            buffer.append(self.value)
            return 1

    assert Strict.unpack(b"\x01").value == 1
    with pytest.raises(DHCPDecodeError):
        Strict.unpack(b"\x00")


def test_a_class_with_the_methods_of_the_protocol_registers_without_the_base() -> None:
    assert not issubclass(PlainCodec, DHCPOptionType)
    assert issubclass(PlainCodec, OptionCodec)
    assert isinstance(PlainCodec("x"), OptionCodec)
    DHCPOptionCode(CODE).register_type(PlainCodec)

    message = _message(PlainCodec("hello"))
    again = DHCPMessage.decode(message.encode())
    assert again.options.get(CODE) == PlainCodec("hello")
    assert "plain hello" in again.summary()
    assert DHCPMessage.from_text(message.to_text("json"), "json").options.get(
        CODE
    ) == PlainCodec("hello")


def test_what_has_not_the_methods_is_not_a_codec_and_is_not_registered() -> None:
    class Half:
        @classmethod
        def unpack(cls, data: _ty.Any) -> Half:
            return cls()

    assert not issubclass(Half, OptionCodec)
    assert not isinstance(b"bytes", OptionCodec)
    assert not isinstance("text", OptionCodec)
    assert not isinstance([1, 2], OptionCodec)
    with pytest.raises(TypeError):
        DHCPOptionCode(CODE).register_type(Half)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        DHCPOptionCode(CODE).register_type(int)  # type: ignore[arg-type]


def test_every_built_in_codec_satisfies_the_protocol() -> None:
    from pydhcp import options

    codecs = [
        getattr(options, name)
        for name in options.__all__
        if isinstance(getattr(options, name), type)
        and issubclass(getattr(options, name), DHCPOptionType)
    ]
    assert len(codecs) > 40
    for codec in codecs:
        assert issubclass(codec, OptionCodec), codec.__name__
