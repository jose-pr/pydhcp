"""Regression tests for the `DhcpMessage` decode/mapping nits fixed on this branch.

Each test pins a behaviour that was measured wrong before the fix; the measured
"before" value is named in the test so a future reader can tell a regression
from a deliberate change.
"""

from __future__ import annotations


import pytest
import yaml

from pydhcp.packet.message import DhcpMessage
from pydhcp.packet.structured import load_message


def _sample_message() -> DhcpMessage:
    header = (
        bytes([1, 1, 6, 0])
        + bytes.fromhex("12345678")
        + bytes(2)
        + bytes(2)
        + bytes(16)
        + bytes(16)
        + bytes(64)
        + bytes(128)
    )
    packet = header + bytes([99, 130, 83, 99]) + bytes([53, 1, 1, 255])
    return DhcpMessage.decode(packet)


class _SubMessage(DhcpMessage):
    """A subclass carrying no extra state, so only its identity is observable."""


def test_decode_returns_the_subclass_not_the_base() -> None:
    # `decode` is a classmethod but built `DhcpMessage(...)` by name, so every
    # subclass decoded to the base while `from_mapping` (already `cls(...)`)
    # returned the subclass. Measured before the fix: DhcpMessage / _SubMessage.
    raw = bytes(_sample_message().encode())
    assert type(_SubMessage.decode(raw)) is _SubMessage
    assert type(DhcpMessage.decode(raw)) is DhcpMessage


def test_decode_and_from_mapping_agree_on_type() -> None:
    message = _sample_message()
    raw = bytes(message.encode())
    assert type(_SubMessage.decode(raw)) is type(
        _SubMessage.from_mapping(message.to_mapping())
    )


def test_yaml_parses_an_unquoted_mac_as_a_sexagesimal_int() -> None:
    # The premise of the chaddr fix: PyYAML applies the YAML 1.1 sexagesimal
    # rule, so the MAC is destroyed before pydhcp is reached.
    assert yaml.safe_load("chaddr: 10:20:30:40:50:55\n")["chaddr"] == 8041827055


def test_int_chaddr_names_the_yaml_quoting_cause() -> None:
    data = dict(_sample_message().to_mapping())
    data["chaddr"] = yaml.safe_load("chaddr: 10:20:30:40:50:55\n")["chaddr"]
    with pytest.raises(TypeError, match="quote it"):
        DhcpMessage.from_mapping(data)


def test_non_text_chaddr_still_rejected() -> None:
    data = dict(_sample_message().to_mapping())
    data["chaddr"] = ["not", "text"]
    with pytest.raises(TypeError, match="text or bytes-like"):
        DhcpMessage.from_mapping(data)


@pytest.mark.parametrize("field", ["sname", "file"])
def test_null_bootp_text_is_empty_not_the_string_none(field: str) -> None:
    # Before the fix `str(None)` produced the four characters "None", so the
    # encoded packet carried a bogus server name / boot filename with no error.
    data = dict(_sample_message().to_mapping())
    data[field] = None
    message = DhcpMessage.from_mapping(data)
    assert getattr(message, field) == ""


def test_hand_authored_yaml_with_empty_sname_and_file_round_trips() -> None:
    """The end-to-end shape the fix exists for: a hand-written YAML packet."""
    message = _sample_message()
    mapping = dict(message.to_mapping())
    mapping["sname"] = None
    mapping["file"] = None
    mapping["chaddr"] = "10:20:30:40:50:55"
    text = yaml.safe_dump(mapping, sort_keys=False)

    loaded = load_message(text, "yaml")
    assert loaded.sname == ""
    assert loaded.file == ""
    assert loaded.chaddr == bytes.fromhex("102030405055")

    encoded = bytes(loaded.encode())
    # The 64-octet sname field and the 128-octet file field must be all NUL --
    # "None" would show up as 4e6f6e65 at the head of each.
    assert encoded[44:108] == bytes(64)
    assert encoded[108:236] == bytes(128)


@pytest.mark.parametrize("field", ["sname", "file"])
def test_non_text_bootp_field_is_rejected_rather_than_stringified(field: str) -> None:
    data = dict(_sample_message().to_mapping())
    data[field] = ["a", "b"]
    with pytest.raises(TypeError, match=f"{field} must be text or null"):
        DhcpMessage.from_mapping(data)
