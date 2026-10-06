"""`to_mapping` and `from_mapping`: byte-exact for the names, no second reading of a value.

A document the code wrote before still loads (`tests/data/message_before_names.*`),
a value a codec refuses is an error that names the option and the type of the
value, and a decode accepts what the documents say it accepts.
"""

from __future__ import annotations

import enum
import pathlib

import pytest

from pydhcp import DHCPDecodeError, DHCPMessage, DHCPOptions, DHCPOpcode
from pydhcp import _nvt
from pydhcp.options import BaseDHCPOptionCode, Bytes, String

DATA = pathlib.Path(__file__).parent / "data"
FORMATS = ("json", "yaml", "toml", "ini")


def _message(sname: bytes = b"", file: bytes = b"") -> DHCPMessage:
    options = DHCPOptions()
    options[53] = b"\x02"
    options[1] = b"\xff\xff\xff\x00"
    return DHCPMessage(
        DHCPOpcode.BOOTREPLY,
        xid=7,
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        sname=_nvt.decode(sname),
        file=_nvt.decode(file),
        options=options,
    )


def _mapping(**options: object) -> dict[str, object]:
    base = _message().to_mapping()
    base["options"] = dict(options)
    return base


# --- sname and file are byte-exact ---------------------------------------------


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_file_written_before_the_names_were_exact_still_loads(fmt: str) -> None:
    text = (DATA / f"message_before_names.{fmt}").read_text(encoding="utf-8")
    loaded = DHCPMessage.from_text(text, fmt)
    assert bytes(loaded) == (DATA / "message_before_names.bin").read_bytes()
    assert loaded.sname == "srv-�" and loaded.file == "boot�.img"


@pytest.mark.parametrize("fmt", FORMATS)
def test_names_that_are_not_utf8_survive_every_format_octet_for_octet(
    fmt: str,
) -> None:
    message = _message(sname=b"srv-\xe9", file=b"boot\xe9\xff.img")
    again = DHCPMessage.from_text(message.to_text(fmt), fmt)
    assert bytes(again) == bytes(message)
    assert _nvt.encode(again.sname) == b"srv-\xe9"
    assert _nvt.encode(again.file) == b"boot\xe9\xff.img"


def test_a_name_that_is_text_stays_text_and_one_that_is_not_is_hex() -> None:
    mapping = _message(sname=b"srv-\xe9", file=b"pxe/boot.img").to_mapping()
    assert mapping["file"] == "pxe/boot.img"
    assert mapping["sname"] == {"hex": "7372762de9"}
    # A real U+FFFD is valid UTF-8 and is text.
    assert _message(sname="�".encode()).to_mapping()["sname"] == "�"


def test_a_name_given_as_hex_text_or_as_octets_is_read_as_octets() -> None:
    data = _message().to_mapping()
    data["sname"] = {"hex": "73 72:76"}
    data["file"] = b"boot.img"
    loaded = DHCPMessage.from_mapping(data)
    assert (loaded.sname, loaded.file) == ("srv", "boot.img")


def test_a_name_that_is_not_text_is_refused_by_name() -> None:
    data = _message().to_mapping()
    data["file"] = 5
    with pytest.raises(TypeError, match="file"):
        DHCPMessage.from_mapping(data)
    data["file"] = {"hex": "zz"}
    with pytest.raises(ValueError, match="file"):
        DHCPMessage.from_mapping(data)


# --- a value the codec refuses is an error, never a second reading -------------


@pytest.mark.parametrize(
    "name, value",
    [
        ("SUBNET_MASK", "dead"),
        ("IP_ADDRESS_LEASE_TIME", "abcd"),
        ("ROUTER", "beef"),
        ("SUBNET_MASK", "255.255.255.0/24"),
        ("SUBNET_MASK", [1, 2]),
    ],
)
def test_a_value_the_codec_refuses_names_the_option_and_the_type(
    name: str, value: object
) -> None:
    with pytest.raises((TypeError, ValueError)) as caught:
        DHCPMessage.from_mapping(_mapping(**{name: value}))
    assert f"({name})" in str(caught.value)
    assert type(value).__name__ in str(caught.value)
    assert "fromhex" not in str(caught.value)


def test_a_value_the_codec_refuses_is_never_stored() -> None:
    # "dead" is hex, and was stored as a two-octet subnet mask.
    with pytest.raises(ValueError):
        DHCPMessage.from_mapping(_mapping(SUBNET_MASK="dead"))


def test_raw_octets_are_read_as_such_in_their_explicit_form() -> None:
    loaded = DHCPMessage.from_mapping(_mapping(SUBNET_MASK={"hex": "dead"}))
    assert bytes(loaded.options[1]) == b"\xde\xad"


def test_hex_text_is_the_value_of_an_option_whose_codec_is_opaque() -> None:
    loaded = DHCPMessage.from_mapping(
        _mapping(VENDOR_SPECIFIC_INFORMATION="0102ff", **{"200": "deadbeef"})
    )
    assert bytes(loaded.options[43]) == b"\x01\x02\xff"
    assert bytes(loaded.options[200]) == b"\xde\xad\xbe\xef"


def test_hex_that_is_not_hex_names_the_option() -> None:
    with pytest.raises(ValueError, match=r"option 200.*str"):
        DHCPMessage.from_mapping(_mapping(**{"200": "zz"}))
    with pytest.raises(ValueError, match="option 200"):
        DHCPMessage.from_mapping(_mapping(**{"200": {"hex": "zz"}}))


def test_a_number_is_not_a_run_of_zero_octets() -> None:
    # bytes(5) is five zero octets.
    with pytest.raises(TypeError, match=r"option 200.*int"):
        DHCPMessage.from_mapping(_mapping(**{"200": 5}))
    with pytest.raises(TypeError):
        Bytes(5)  # type: ignore[arg-type]


def test_an_option_name_that_is_nobody_s_is_refused_by_name() -> None:
    with pytest.raises(ValueError, match="NOT_AN_OPTION"):
        DHCPMessage.from_mapping(_mapping(NOT_AN_OPTION="1"))


# --- a missing header key is a ValueError that names it -----------------------


@pytest.mark.parametrize("key", ["op", "hops", "xid", "sname", "file", "chaddr"])
def test_a_missing_header_field_is_a_value_error_naming_it(key: str) -> None:
    data = _message().to_mapping()
    del data[key]
    with pytest.raises(ValueError, match=f"'{key}'"):
        DHCPMessage.from_mapping(data)


# --- the codemap to_mapping named the options with ----------------------------


class _Site(BaseDHCPOptionCode, enum.IntEnum):
    SITE_NAME = 224

    def get_type(self) -> type:
        return String

    def label(self) -> str:
        return str(self.name)


def test_from_mapping_takes_the_codemap_to_mapping_used() -> None:
    options = DHCPOptions(_Site)
    options[53] = b"\x02"
    options[224] = "lab-1"
    message = DHCPMessage(DHCPOpcode.BOOTREPLY, options=options)
    mapping = message.to_mapping()
    assert mapping["options"]["SITE_NAME"] == "lab-1"
    again = DHCPMessage.from_mapping(mapping, codemap=_Site)
    assert bytes(again.options[224]) == b"lab-1"
    assert again.options._codemap is _Site
    with pytest.raises(ValueError, match="SITE_NAME"):
        DHCPMessage.from_mapping(mapping)
    assert DHCPMessage.from_text(message.to_text("json"), "json", codemap=_Site) == (
        again
    )


# --- decode accepts a missing END, as the documents say ------------------------


def _datagram(options: bytes, **fields: bytes) -> bytes:
    header = bytes([2, 1, 6, 0]) + bytes(4 + 2 + 2 + 16) + bytes(16)
    sname = fields.get("sname", b"").ljust(64, b"\x00")
    file = fields.get("file", b"").ljust(128, b"\x00")
    return header + sname + file + bytes([99, 130, 83, 99]) + options


@pytest.mark.parametrize(
    "options, kept",
    [
        (b"", {}),
        (b"\x35\x01\x02", {53: b"\x02"}),
        (b"\x35\x01\x02\x32\x04\x0a", {53: b"\x02", 50: b"\x0a"}),
        (b"\x35\x01\x02\x32", {53: b"\x02"}),
        (b"\x35\x01\x02\xff", {53: b"\x02"}),
    ],
)
def test_a_missing_end_is_accepted_and_what_arrived_is_kept(
    options: bytes, kept: dict[int, bytes]
) -> None:
    message = DHCPMessage.decode(_datagram(options))
    assert {int(c): bytes(v) for c, v in message.options.items(decoded=False)} == kept


def test_an_overloaded_field_without_an_end_is_accepted_too() -> None:
    wire = _datagram(b"\x35\x01\x02\x34\x01\x02\xff", sname=b"\x0c\x03abc")
    assert bytes(DHCPMessage.decode(wire).options[12]) == b"abc"


def test_what_is_written_always_ends_every_field_with_end() -> None:
    wire = _message().encode()
    assert wire[240:].rstrip(b"\x00").endswith(b"\xff")
    over = _message()
    over.options[12] = b"h" * 300
    wire = over.encode()
    assert wire[240:].rstrip(b"\x00")[-1] == 255
    assert 255 in wire[44:108]


def test_a_decode_error_still_names_a_short_datagram() -> None:
    with pytest.raises(DHCPDecodeError):
        DHCPMessage.decode(bytes(100))
