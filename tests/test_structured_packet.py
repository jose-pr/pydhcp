from __future__ import annotations

import pytest

from pydhcp import DhcpMessage, DhcpOptions
from pydhcp.packet import DhcpMessageType
from pydhcp.options import DhcpOptionCode
from pydhcp.packet.structured import dump_message, load_mapping, load_message
from pydhcp.packet import structured
from conftest import build_request


def _sample_packet() -> DhcpMessage:
    return build_request(DhcpMessageType.DHCPDISCOVER)


@pytest.mark.parametrize("format_name", ["json", "yaml", "toml", "ini"])
def test_packet_structured_round_trip_for_each_format(format_name: str) -> None:
    if format_name == "toml" and (
        structured._tomllib is None or structured._tomli_w is None
    ):
        pytest.skip("TOML packet round trip requires optional TOML dependencies")

    packet = _sample_packet()

    text = dump_message(packet, format_name)
    restored = load_message(text, format_name)

    assert restored.to_mapping() == packet.to_mapping()
    assert restored.encode() == packet.encode()

    if format_name == "ini":
        assert "[message]" in text
        assert "[options]" in text


def test_toml_decode_without_reader_reports_not_implemented(monkeypatch) -> None:
    monkeypatch.setattr(structured, "_tomllib", None)

    with pytest.raises(NotImplementedError, match="INI format as a stdlib fallback"):
        load_mapping("[message]\nop = 'BOOTREQUEST'\n", "toml")


def test_toml_encode_without_writer_reports_not_implemented(monkeypatch) -> None:
    packet = _sample_packet()
    monkeypatch.setattr(structured, "_tomli_w", None)

    with pytest.raises(NotImplementedError, match="INI format as a stdlib fallback"):
        dump_message(packet, "toml")


# --- the structured round trip must not change the packet ---


def _message_with_option(code, payload):

    from pydhcp.options import DhcpOptionCode, DhcpOptions
    from pydhcp.packet import DhcpMessageType
    from pydhcp.packet.message import DhcpMessage

    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
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
    from pydhcp.options import DhcpOptionCode
    from pydhcp.packet.structured import dump_message, load_message

    _require_format(fmt)
    original = _message_with_option(code, payload)
    reloaded = load_message(dump_message(original, fmt), fmt)

    got = bytes(reloaded.options.get(DhcpOptionCode(code), decode=False) or b"")
    assert got == payload, f"{why}: {got.hex()} != {payload.hex()}"


@pytest.mark.parametrize("fmt", ["json", "yaml", "toml", "ini"])
def test_integer_options_serialize_as_plain_integers(fmt):
    """`__json__` returned the U16/U32 subclass, not an int.

    JSON tolerates an int subclass; YAML refuses to represent it and TOML wrote
    something it could not read back -- so any packet carrying option 57 or 51,
    which is most real packets, could not round-trip through either.
    """
    from pydhcp.options import DhcpOptionCode
    from pydhcp.packet.structured import dump_message, load_message

    _require_format(fmt)
    original = _message_with_option(57, bytes.fromhex("05dc"))
    mapping = original.to_mapping()
    assert type(mapping["options"]["MAXIMUM_DHCP_MESSAGE_SIZE"]) is int

    reloaded = load_message(dump_message(original, fmt), fmt)
    assert bytes(
        reloaded.options.get(DhcpOptionCode(57), decode=False)
    ) == bytes.fromhex("05dc")


def test_unnamed_option_codes_do_not_collide_on_one_key():
    """Every code without a name used to serialize as "UNKNOWN"."""
    from pydhcp.options import DhcpOptionCode, DhcpOptions

    message = _message_with_option(224, bytes.fromhex("0102"))
    message.options[225] = bytearray(bytes.fromhex("0304"))

    keys = set(message.to_mapping()["options"])

    assert "224" in keys and "225" in keys
    assert "UNKNOWN" not in keys
