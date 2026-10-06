"""A value on the wire is never rewritten: unnamed message types and the flags field.

PROTOCOL.md, "Wire encoding": an unknown enum value becomes an unnamed member
carrying the number, so a relay forwards what it received. RFC 2131 s2 assigns
one of the sixteen bits of `flags`; the others are reserved and travel as sent.
"""

from __future__ import annotations

import json
import pickle

import pytest

from pydhcp import DHCPMessage
from pydhcp.exceptions import DHCPDecodeError
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPFlags, DHCPMessageType, DHCPOpcode

# --- option 53: an unassigned type is an unnamed member ------------------------


@pytest.mark.parametrize("number", [0, 19, 99, 128, 255])
def test_an_unassigned_message_type_is_carried(number: int) -> None:
    member = DHCPMessageType(number)
    assert int(member) == number
    assert member.name is None
    assert member.label() == f"TYPE_{number}"
    assert DHCPMessageType(number) is member
    assert pickle.loads(pickle.dumps(member)) is member
    assert DHCPMessageType.unpack(bytearray([number])) is member


def test_an_assigned_message_type_keeps_its_name() -> None:
    assert DHCPMessageType(5) is DHCPMessageType.DHCPACK
    assert DHCPMessageType(5).label() == "DHCPACK"


def test_a_number_that_is_no_octet_is_not_a_message_type() -> None:
    with pytest.raises(ValueError):
        DHCPMessageType(256)


def test_a_message_carries_an_unassigned_type_and_forwards_it() -> None:
    message = DHCPMessage(DHCPOpcode.BOOTREQUEST)
    message.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = bytearray([99])
    wire = bytes(message.encode())
    restored = DHCPMessage.decode(wire)
    assert restored.message_type is DHCPMessageType(99)
    assert bytes(restored.encode()) == wire
    mapping = restored.to_mapping()
    assert DHCPMessage.from_mapping(json.loads(json.dumps(mapping))).message_type is (
        DHCPMessageType(99)
    )


# --- the flags field: reserved bits are carried (RFC 2131 s2) ------------------


def _header_with_flags(flags: int) -> bytes:
    message = DHCPMessage(DHCPOpcode.BOOTREQUEST)
    wire = bytearray(message.encode())
    wire[10:12] = flags.to_bytes(2, "big")
    return bytes(wire)


@pytest.mark.parametrize("flags", [0x0000, 0x8000, 0x0001, 0x8001, 0x7FFF, 0xFFFF])
def test_the_flags_field_is_carried_octet_for_octet(flags: int) -> None:
    wire = _header_with_flags(flags)
    message = DHCPMessage.decode(wire)
    assert int(message.flags) == flags
    assert bytes(message.encode())[10:12] == flags.to_bytes(2, "big")
    assert message.broadcast is bool(flags & 0x8000)


def test_the_flags_field_survives_the_structured_form() -> None:
    message = DHCPMessage.decode(_header_with_flags(0x8001))
    mapping = json.loads(json.dumps(message.to_mapping()))
    assert DHCPMessage.from_mapping(mapping).flags == message.flags
    assert message.flags.label() == "BROADCAST|0x0001"
    assert DHCPFlags(0).label() == "UNICAST"
    assert DHCPFlags.BROADCAST.label() == "BROADCAST"


def test_an_op_other_than_request_or_reply_is_refused() -> None:
    wire = bytearray(_header_with_flags(0))
    wire[0] = 3
    with pytest.raises(DHCPDecodeError, match="DHCPOpcode"):
        DHCPMessage.decode(bytes(wire))
