from __future__ import annotations

import sys

import pytest

from pydhcp import DHCPMessage, DHCPOptions
from pydhcp.packet import DHCPMessageType
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import structured
from helpers import build_request


def _sample_packet() -> DHCPMessage:
    return build_request(DHCPMessageType.DHCPDISCOVER)


def _needs(format_name: str) -> None:
    """A format other than JSON is pktcap's, with the library of its own extra."""
    if format_name == "json":
        return
    pytest.importorskip("pktcap")
    if format_name == "yaml":
        pytest.importorskip("yaml")
    if format_name == "toml":
        pytest.importorskip("tomli_w")
        if sys.version_info < (3, 11):
            pytest.importorskip("tomli")


@pytest.mark.parametrize("format_name", ["json", "yaml", "toml", "ini"])
def test_packet_structured_round_trip_for_each_format(format_name: str) -> None:
    _needs(format_name)

    packet = _sample_packet()

    text = packet.to_text(format_name)
    restored = DHCPMessage.from_text(text, format_name)

    assert restored.to_mapping() == packet.to_mapping()
    assert restored.encode() == packet.encode()

    if format_name == "ini":
        assert "[record]" in text
        assert "[options]" in text
        assert "[message]" not in text


# --- the structured round trip must not change the packet ---


def _message_with_option(code, payload):

    from pydhcp.options import DHCPOptionCode, DHCPOptions
    from pydhcp.packet import DHCPMessageType
    from pydhcp.packet import DHCPMessage

    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    options[code] = bytearray(payload)
    return build_request(options=options, xid=0x1234)


def _require_format(fmt):
    _needs(fmt)


@pytest.mark.parametrize("fmt", ["json", "yaml", "toml", "ini"])
@pytest.mark.parametrize(
    "code,payload,why",
    [
        (12, bytes.fromhex("6162ff6364"), "text holding a non-UTF-8 octet"),
        (60, bytes.fromhex("00000de9fffe"), "a binary vendor class identifier"),
        (52, bytes([4]), "an OPTION_OVERLOAD value with no enum member"),
        (51, bytes.fromhex("1234"), "a lease time of the wrong length"),
        (57, bytes.fromhex("05dc"), "an ordinary U16 option"),
        (224, bytes.fromhex("0102"), "a site-specific code with no name"),
    ],
)
def test_structured_round_trip_preserves_option_octets(code, payload, why, fmt):
    """Whatever the text form, reloading must give back the same packet.

    Before: a non-UTF-8 hostname came back with U+FFFD in it, a 2-octet lease
    time was written as "1234" and reloaded as the decimal 1234 (four different
    octets), and an unnamed code was written under the key "UNKNOWN" -- which
    every other unnamed code shared, and which then failed on int("UNKNOWN").
    """
    from pydhcp.options import DHCPOptionCode

    _require_format(fmt)
    original = _message_with_option(code, payload)
    reloaded = DHCPMessage.from_text(original.to_text(fmt), fmt)

    got = bytes(reloaded.options.get(DHCPOptionCode(code), decode=False) or b"")
    assert got == payload, f"{why}: {got.hex()} != {payload.hex()}"


@pytest.mark.parametrize("fmt", ["json", "yaml", "toml", "ini"])
def test_integer_options_serialize_as_plain_integers(fmt):
    """`to_json` returned the U16/U32 subclass, not an int.

    JSON tolerates an int subclass; YAML refuses to represent it and TOML wrote
    something it could not read back -- so any packet carrying option 57 or 51,
    which is most real packets, could not round-trip through either.
    """
    from pydhcp.options import DHCPOptionCode

    _require_format(fmt)
    original = _message_with_option(57, bytes.fromhex("05dc"))
    mapping = original.to_mapping()
    assert type(mapping["options"]["MAXIMUM_DHCP_MESSAGE_SIZE"]) is int

    reloaded = DHCPMessage.from_text(original.to_text(fmt), fmt)
    assert bytes(
        reloaded.options.get(DHCPOptionCode(57), decode=False)
    ) == bytes.fromhex("05dc")


def test_unnamed_option_codes_do_not_collide_on_one_key():
    """Every code without a name used to serialize as "UNKNOWN"."""
    from pydhcp.options import DHCPOptionCode, DHCPOptions

    message = _message_with_option(224, bytes.fromhex("0102"))
    message.options[225] = bytearray(bytes.fromhex("0304"))

    keys = set(message.to_mapping()["options"])

    assert "224" in keys and "225" in keys
    assert "UNKNOWN" not in keys


@pytest.mark.parametrize("fmt", ["json", "yaml", "toml", "ini"])
def test_a_message_with_a_list_codec_option_round_trips_in_every_format(fmt):
    """Option 119 is a `DomainList`, a list subclass: a record format takes plain data only."""
    _needs(fmt)
    original = _message_with_option(119, bytes.fromhex("076578616d706c6503636f6d00"))
    mapping = original.to_mapping()
    assert mapping["options"]["DOMAIN_SEARCH"] == ["example.com"]
    assert type(mapping["options"]["DOMAIN_SEARCH"]) is not list

    reloaded = DHCPMessage.from_text(original.to_text(fmt), fmt)

    assert reloaded.encode() == original.encode()


@pytest.mark.parametrize("fmt", ["json", "yaml", "ini"])
def test_a_message_with_an_option_held_as_octets_before_a_plain_one_round_trips(fmt):
    """Option 121 that is no route list is held as `{"hex": ...}`, a table in TOML."""
    _needs(fmt)
    message = _message_with_option(121, bytes.fromhex("0a0a0000c0000201"))
    message.options[43] = bytearray(bytes.fromhex("00ff80fe"))
    assert message.to_mapping()["options"]["121"] == {"hex": "0a0a0000c0000201"}

    reloaded = DHCPMessage.from_text(message.to_text(fmt), fmt)

    assert reloaded.encode() == message.encode()


def test_toml_refuses_a_message_whose_options_it_would_write_in_another_order():
    """A table follows the plain values of its parent in TOML: the option held as octets
    would be read back after the plain one that follows it, so the message is refused
    with that reason and not approximated."""
    _needs("toml")
    message = _message_with_option(121, bytes.fromhex("0a0a0000c0000201"))
    message.options[43] = bytearray(bytes.fromhex("00ff80fe"))

    with pytest.raises(ValueError, match="another order"):
        message.to_text("toml")


def test_toml_holds_a_message_whose_table_options_come_last():
    _needs("toml")
    message = _message_with_option(43, bytes.fromhex("00ff80fe"))
    message.options[121] = bytearray(bytes.fromhex("0a0a0000c0000201"))

    assert DHCPMessage.from_text(message.to_text("toml"), "toml").encode() == (
        message.encode()
    )


def test_an_ini_document_written_with_a_message_section_is_still_read():
    """`[message]` and `[options]` are the sections a message was written with before."""
    _needs("ini")
    message = _sample_packet()
    text = message.to_text("ini").replace("[record]", "[message]", 1)

    assert "[message]" in text
    assert DHCPMessage.from_text(text, "ini").to_mapping() == message.to_mapping()


def test_json_is_written_and_read_by_the_standard_library_without_pktcap(monkeypatch):
    monkeypatch.setitem(sys.modules, "pktcap", None)
    message = _sample_packet()

    text = message.to_text("json")

    assert text.startswith("{" + chr(10))  # indented, as json.dumps(indent=2) writes it
    assert DHCPMessage.from_text(text, "json").to_mapping() == message.to_mapping()
