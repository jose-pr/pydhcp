"""One name per conversion: text, structured documents, the wire and the display.

Each pair has a round-trip property, every documented text spelling parses, and
a rejected input is checked for its error type.
"""

from __future__ import annotations

import pathlib
import pickle
import typing as _ty
from ipaddress import IPv4Address

import pytest

from pydhcp import (
    ClasslessRoute,
    DHCPMessage,
    DHCPOptions,
    DHCPValueError,
    SocketAddress,
)
from pydhcp.options import Bytes, ClientFQDN, DHCPOptionCode, StatusCode
from pydhcp.packet import (
    DHCPMessageType,
    HardwareAddressType,
    structured,
)
from conftest import build_request

DATA = pathlib.Path(__file__).parent / "data"
FORMATS = ("json", "yaml", "toml", "ini")


def _rich_message() -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPOFFER
    options[DHCPOptionCode.ROUTER] = ["192.0.2.1", "192.0.2.2"]
    options[DHCPOptionCode.DOMAIN_NAME] = "example.org"
    options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = 3600
    options[DHCPOptionCode.CLASSLESS_STATIC_ROUTE] = [("192.0.2.1", "10.0.0.0/8")]
    options[200] = b"\xde\xad\xbe\xef"
    return build_request(options=options, sname="srv", file="boot.img")


# -- the display ------------------------------------------------------------


def test_the_display_is_summary_and_nothing_is_called_dumps() -> None:
    message = _rich_message()
    text = message.summary()
    assert text.startswith("OP")
    assert "ROUTER" in text
    assert not hasattr(message, "dumps")
    assert not hasattr(HardwareAddressType, "dumps")


def test_a_hardware_address_is_formatted_by_format_address() -> None:
    assert (
        HardwareAddressType.ETHERNET.format_address(b"\x00\x11\x22\x33\x44\x55")
        == "00:11:22:33:44:55"
    )
    assert HardwareAddressType.INFINIBAND.format_address(b"\x01") == repr(b"\x01")


# -- the structured formats ---------------------------------------------------


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_message_round_trips_through_text(fmt: str) -> None:
    message = _rich_message()
    again = DHCPMessage.from_text(message.to_text(fmt), fmt)
    assert bytes(again) == bytes(message)


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_mapping_round_trips_through_loads_and_dumps(fmt: str) -> None:
    mapping = _rich_message().to_mapping()
    assert structured.loads(structured.dumps(mapping, fmt), fmt) == mapping


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_file_written_before_the_rename_still_loads(fmt: str) -> None:
    text = (DATA / f"message_before_rename.{fmt}").read_text(encoding="utf-8")
    loaded = DHCPMessage.from_text(text, fmt)
    assert bytes(loaded) == (DATA / "message_before_rename.bin").read_bytes()


def test_the_structured_module_has_loads_and_dumps_only() -> None:
    assert sorted(structured.__all__) == ["dumps", "loads"]
    for gone in ("load_message", "dump_message", "load_mapping", "dump_mapping"):
        assert not hasattr(structured, gone)


def test_an_unknown_format_is_refused() -> None:
    with pytest.raises(ValueError):
        structured.loads("{}", "xml")
    with pytest.raises(ValueError):
        _rich_message().to_text("xml")


# -- the wire ---------------------------------------------------------------


def test_encode_returns_bytes_and_bytes_of_a_message_is_its_encoding() -> None:
    message = _rich_message()
    wire = message.encode()
    assert type(wire) is bytes
    assert bytes(message) == wire
    assert DHCPMessage.decode(wire) == DHCPMessage.decode(bytes(message))


def test_options_decode_is_a_classmethod_that_returns_the_options() -> None:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPACK
    options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = 86400
    wire = options.encode()
    decoded = DHCPOptions.decode(wire)
    assert type(decoded) is DHCPOptions
    assert decoded.encode() == wire
    assert decoded.get(DHCPOptionCode.IP_ADDRESS_LEASE_TIME) == 86400
    # What it does not take: an instance to fill, an offset.
    with pytest.raises(TypeError):
        options.decode(wire, base_offset=0)  # type: ignore[call-arg]


# -- parse and try_parse ------------------------------------------------------

_TEXT_TYPES: list[tuple[_ty.Any, list[_ty.Any]]] = [
    (SocketAddress, [SocketAddress("192.0.2.1", 67), SocketAddress("0.0.0.0", 0)]),
    (
        ClasslessRoute,
        [
            ClasslessRoute("192.0.2.1", "10.0.0.0/8"),
            ClasslessRoute("0.0.0.0", "0.0.0.0/0"),
        ],
    ),
    (StatusCode, [StatusCode(0), StatusCode(1, "no space"), StatusCode(2, " pad")]),
    (
        ClientFQDN,
        [
            ClientFQDN("host.example.org"),
            ClientFQDN("host.example.org", flags=0x05, rcode1=1, rcode2=2),
            ClientFQDN("host", flags=0x04, partial=True),
            ClientFQDN(""),
        ],
    ),
    (Bytes, [Bytes(b""), Bytes(b"\x01\xab\xff")]),
]


@pytest.mark.parametrize(
    "cls,value",
    [(cls, value) for cls, values in _TEXT_TYPES for value in values],
    ids=lambda x: repr(x)[:40],
)
def test_parse_of_str_is_the_value(cls: _ty.Any, value: _ty.Any) -> None:
    assert cls.parse(str(value)) == value
    assert cls.try_parse(str(value)) == value
    assert pickle.loads(pickle.dumps(value)) == value


def test_every_documented_spelling_parses() -> None:
    assert SocketAddress.parse("192.0.2.1:67") == SocketAddress("192.0.2.1", 67)
    assert ClasslessRoute.parse("10.0.0.0/8 via 192.0.2.1") == ClasslessRoute(
        "192.0.2.1", "10.0.0.0/8"
    )
    assert StatusCode.parse("2 not enough") == StatusCode(2, "not enough")
    assert StatusCode.parse("2") == StatusCode(2)
    assert ClientFQDN.parse("a.example") == ClientFQDN("a.example")
    assert Bytes.parse("01 AB ff") == Bytes(b"\x01\xab\xff")
    assert Bytes.parse("01:ab:ff") == Bytes(b"\x01\xab\xff")
    assert Bytes.parse("") == Bytes(b"")


_REJECTED: list[tuple[_ty.Any, str]] = [
    (SocketAddress, "192.0.2.1"),
    (SocketAddress, "192.0.2.1:99999"),
    (SocketAddress, "not an address:67"),
    (SocketAddress, "192.0.2.1:http"),
    (ClasslessRoute, "10.0.0.0/8"),
    (ClasslessRoute, "10.0.0.0/8 via nowhere"),
    (ClasslessRoute, "10.0.0.1/8 via 192.0.2.1"),
    (StatusCode, "x"),
    (StatusCode, "256"),
    (StatusCode, ""),
    (ClientFQDN, "a.example [flags=0x10 rcode1=0 rcode2=0]"),
    (ClientFQDN, "a.example [flags=zz]"),
    (Bytes, "xyz"),
    (Bytes, "012"),
]


@pytest.mark.parametrize("cls,text", _REJECTED, ids=lambda x: repr(x)[:40])
def test_parse_raises_the_value_error_and_try_parse_says_none(
    cls: _ty.Any, text: str
) -> None:
    with pytest.raises(DHCPValueError) as caught:
        cls.parse(text)
    assert isinstance(caught.value, ValueError)
    assert cls.try_parse(text) is None
    assert cls.try_parse(text, default="d") == "d"


@pytest.mark.parametrize("cls", [c for c, _ in _TEXT_TYPES])
def test_a_non_text_argument_is_a_type_error_even_from_try_parse(cls: _ty.Any) -> None:
    with pytest.raises(TypeError):
        cls.parse(5)
    with pytest.raises(TypeError):
        cls.try_parse(5)


def test_a_bytes_option_is_built_from_bytes_not_text() -> None:
    assert Bytes(b"\x01\x02") == b"\x01\x02"
    assert Bytes(bytearray(b"\x01")) == b"\x01"
    assert Bytes() == b""
    with pytest.raises(TypeError):
        Bytes("0102")  # type: ignore[arg-type]
    assert Bytes(value=b"ab") == b"ab"
    with pytest.raises(TypeError):
        Bytes(src=b"ab")  # type: ignore[call-arg]


def test_a_hex_option_in_a_document_still_loads_as_its_octets() -> None:
    mapping = _rich_message().to_mapping()
    mapping["options"]["VENDOR_SPECIFIC_INFORMATION"] = "0102ff"
    loaded = DHCPMessage.from_mapping(mapping)
    assert bytes(loaded.options[DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION]) == (
        b"\x01\x02\xff"
    )


# -- the tuple form -----------------------------------------------------------


def test_a_socket_address_converts_to_a_plain_tuple() -> None:
    assert SocketAddress("127.0.0.1", 8080).to_tuple() == ("127.0.0.1", 8080)
    assert not hasattr(SocketAddress, "compat")
    assert SocketAddress("0.0.0.0", 1) == SocketAddress(IPv4Address("0.0.0.0"), 1)


# -- the names the policy hooks and the identity go by ------------------------


def test_the_client_identity_and_the_lease_length_are_read_with_get() -> None:
    message = build_request()
    assert message.get_client_id() == "01:00:11:22:33:44:55"
    assert message.get_client_id(lambda m: bytearray(b"\x09")) == "09"
    assert not hasattr(message, "client_id")
