"""Client FQDN option (81), RFC 4702 s2.1 and s2.3: every wire form it defines.

The Domain Name field is a fully qualified name (with the terminating
zero-length label), a partial name (without it) or empty, and receivers MUST
ignore the four reserved flag bits.
"""

from __future__ import annotations

import pytest

from pydhcp.options import DHCPOptions
from pydhcp.options.type import ClientFqdn

E = ClientFqdn.FLAG_E
S = ClientFqdn.FLAG_S

#: Encoded (E bit) names, as RFC 1035 s3.1 puts them on the wire.
HOST_EXAMPLE = b"\x04host\x07example"
QUALIFIED = HOST_EXAMPLE + b"\x00"


def _decode(wire: bytes) -> ClientFqdn:
    return ClientFqdn._dhcp_decode(bytearray(wire))


def _encode(value: ClientFqdn) -> bytes:
    return bytes(value._dhcp_encode())


def test_a_fully_qualified_name_carries_the_terminating_label() -> None:
    wire = bytes([E | S, 0, 0]) + QUALIFIED
    value = _decode(wire)
    assert (value.name, value.partial, value.flags) == ("host.example", False, E | S)
    assert _encode(value) == wire


def test_a_partial_name_has_no_terminating_label_and_is_not_given_one() -> None:
    """RFC 4702 s2.3: "without the terminating zero-length label"."""
    wire = bytes([E, 0, 0]) + HOST_EXAMPLE
    value = _decode(wire)
    assert (value.name, value.partial) == ("host.example", True)
    assert _encode(value) == wire


def test_an_empty_domain_name_field_is_allowed_and_stays_empty() -> None:
    """RFC 4702 s2.3: "A client MAY also leave the Domain Name field empty"."""
    wire = bytes([E, 0, 0])
    value = _decode(wire)
    assert (value.name, value.partial) == ("", True)
    assert _encode(value) == wire


def test_the_root_name_is_not_the_empty_field() -> None:
    wire = bytes([E, 0, 0]) + b"\x00"
    value = _decode(wire)
    assert (value.name, value.partial) == ("", False)
    assert _encode(value) == wire


def test_an_ascii_name_is_unchanged() -> None:
    wire = bytes([0, 0, 0]) + b"DESKTOP-K7N2A91"
    value = _decode(wire)
    assert (value.name, value.partial) == ("DESKTOP-K7N2A91", False)
    assert _encode(value) == wire


@pytest.mark.parametrize("flags", [0x45, 0x85, 0xF5, 0xF0 | E])
def test_reserved_flag_bits_are_ignored_on_receive(flags: int) -> None:
    """RFC 4702 s2.1: receivers MUST ignore the MBZ bits."""
    value = _decode(bytes([flags, 0, 0]) + QUALIFIED)
    assert value.name == "host.example"
    assert value.flags == flags & 0x0F


def test_a_sender_clears_the_reserved_bits_by_refusing_to_set_them() -> None:
    """RFC 4702 s2.1: senders MUST clear the MBZ bits."""
    with pytest.raises(ValueError, match="reserved"):
        ClientFqdn("host", flags=0x45)


def test_a_partial_name_is_spelled_by_the_partial_argument() -> None:
    value = ClientFqdn("host", flags=E, partial=True)
    assert _encode(value) == bytes([E, 0, 0]) + b"\x04host"
    assert _encode(ClientFqdn("host", flags=E)) == bytes([E, 0, 0]) + b"\x04host\x00"
    assert value != ClientFqdn("host", flags=E)
    assert ClientFqdn(value) == value


def test_the_ascii_form_has_no_partial_name() -> None:
    with pytest.raises(ValueError, match="E bit"):
        ClientFqdn("host", flags=0, partial=True)


def test_the_json_form_round_trips_a_partial_name() -> None:
    value = ClientFqdn("host", flags=E, partial=True)
    assert ClientFqdn(value.__json__()) == value


def test_a_message_option_with_a_partial_name_decodes() -> None:
    wire = bytes([81, 3 + len(HOST_EXAMPLE), E, 0, 0]) + HOST_EXAMPLE + b"\xff"
    options = DHCPOptions()
    options.decode(memoryview(bytearray(wire)))
    value = options.get(81)
    assert (value.name, value.partial) == ("host.example", True)


@pytest.mark.parametrize(
    "wire",
    [
        bytes([E, 0, 0]) + b"\x04hos",  # a label cut short, not a partial name
        bytes([E, 0, 0]) + QUALIFIED + b"\x00",  # data after the terminator
        bytes([E, 0, 0]) + b"\xc0\x00",  # a compression pointer
        bytes([E, 0]),  # shorter than the three fixed octets
    ],
)
def test_a_malformed_name_is_still_refused(wire: bytes) -> None:
    with pytest.raises(ValueError):
        _decode(wire)
