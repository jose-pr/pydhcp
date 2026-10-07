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


@pytest.mark.parametrize("format_name", ["json", "yaml", "toml", "ini"])
def test_packet_structured_round_trip_for_each_format(format_name: str) -> None:
    if format_name == "toml":
        pytest.importorskip("tomli_w")
        if sys.version_info < (3, 11):
            pytest.importorskip("tomli")

    packet = _sample_packet()

    text = packet.to_text(format_name)
    restored = DHCPMessage.from_text(text, format_name)

    assert restored.to_mapping() == packet.to_mapping()
    assert restored.encode() == packet.encode()

    if format_name == "ini":
        assert "[message]" in text
        assert "[options]" in text


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
    """`toml` and `ini` are written by the optional `toml` extra."""
    if fmt in ("toml", "ini"):
        pytest.importorskip("tomli_w")


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
