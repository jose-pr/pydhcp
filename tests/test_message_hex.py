"""`DHCPMessage.from_hex`: a message written as hexadecimal text, as `pydhcp packet --decode` reads it."""

from __future__ import annotations

import pytest

from capture_input import datagrams
from pydhcp import DHCPMessage
from pydhcp.exceptions import DHCPDecodeError


def _spelled(data: bytes, style: str) -> str:
    digits = data.hex()
    if style == "plain":
        return digits
    if style == "upper":
        return digits.upper()
    if style == "colons":
        return ":".join(digits[i : i + 2] for i in range(0, len(digits), 2))
    lines = [digits[i : i + 32] for i in range(0, len(digits), 32)]
    return (
        "\r\n".join(
            " ".join(line[i : i + 8] for i in range(0, 32, 8)) for line in lines
        )
        + "\n"
    )


@pytest.mark.parametrize("style", ["plain", "upper", "colons", "wrapped"])
def test_hex_text_reads_as_the_octets_it_spells(style: str) -> None:
    data = datagrams()[3]

    message = DHCPMessage.from_hex(_spelled(data, style))

    assert message.to_mapping() == DHCPMessage.decode(data).to_mapping()
    assert bytes(message.encode()) == bytes(DHCPMessage.decode(data).encode())


def test_text_that_is_not_hex_is_a_value_error() -> None:
    with pytest.raises(ValueError):
        DHCPMessage.from_hex("0101zz")
    with pytest.raises(ValueError):
        DHCPMessage.from_hex("010")  # an odd number of digits


def test_hex_that_is_not_a_message_is_a_decode_error() -> None:
    with pytest.raises(DHCPDecodeError):
        DHCPMessage.from_hex("0101")
    with pytest.raises(DHCPDecodeError):
        DHCPMessage.from_hex("")
