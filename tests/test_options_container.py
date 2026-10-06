"""The option bag: equality on raw payloads, atomic writes, text and integer values."""

from __future__ import annotations

import typing as _ty

import pytest

from pydhcp import DHCPMessage, DHCPOptionCode, DHCPOptions, DHCPValueError
from pydhcp.options import (
    Bytes,
    DHCPOption,
    I32,
    String,
    U16,
    U32,
    U8,
)
from pydhcp.options._frozen import FrozenDHCPOptions

SUBNET = int(DHCPOptionCode.SUBNET_MASK)
HOSTNAME = int(DHCPOptionCode.HOSTNAME)
TIME_OFFSET = int(DHCPOptionCode.TIME_OFFSET)


def _bag(**payloads: bytes) -> DHCPOptions:
    bag = DHCPOptions()
    for code, payload in payloads.items():
        bag[int(code[1:])] = payload
    return bag


# --- equality: raw payloads, never decoded ------------------------------------


def test_bags_holding_the_same_malformed_payload_are_equal() -> None:
    # A one-octet subnet mask does not decode; comparing must not try.
    first, second = _bag(o1=b"\x01"), _bag(o1=b"\x01")
    assert first == second
    assert not first != second


def test_octets_that_decode_alike_are_not_equal() -> None:
    # Option 12 is NUL-terminated text: both payloads read as "abc".
    assert _bag(o12=b"abc\x00junk") != _bag(o12=b"abc")


def test_order_does_not_count_for_a_mapping() -> None:
    first = DHCPOptions()
    first[1] = b"\xff\xff\xff\x00"
    first[3] = b"\x0a\x00\x00\x01"
    second = DHCPOptions()
    second[3] = b"\x0a\x00\x00\x01"
    second[1] = b"\xff\xff\xff\x00"
    assert first == second


def test_a_bag_with_another_code_or_size_is_not_equal() -> None:
    assert _bag(o12=b"a") != _bag(o15=b"a")
    assert _bag(o12=b"a") != _bag(o12=b"a", o15=b"a")
    assert DHCPOptions() == DHCPOptions()


def test_a_bag_compares_with_another_type_by_declining() -> None:
    bag = _bag(o12=b"a")
    assert bag.__eq__(dict(bag)) is NotImplemented
    assert bag.__eq__(5) is NotImplemented
    assert bag != dict(bag)


def test_a_mutable_bag_and_its_snapshot_are_equal_and_the_snapshot_hashes() -> None:
    bag = _bag(o12=b"host", o1=b"\xff\xff\xff\x00")
    snapshot = FrozenDHCPOptions(bag)
    assert snapshot == bag and bag == snapshot
    assert hash(snapshot) == hash(FrozenDHCPOptions(bag.copy()))
    bag[12] = b"other"
    assert snapshot != bag


def test_two_decodes_of_one_truncated_datagram_are_equal() -> None:
    # Option 50 declares four octets and supplies one: kept as received.
    wire = bytearray(240)
    wire[0:4] = bytes([1, 1, 6, 0])
    wire[236:240] = bytes([99, 130, 83, 99])
    datagram = bytes(wire) + bytes([53, 1, 1, 50, 4, 7])
    assert DHCPMessage.decode(datagram) == DHCPMessage.decode(datagram)


def test_a_lease_snapshot_compares_without_decoding() -> None:
    bag = _bag(o1=b"\x01")
    assert FrozenDHCPOptions(bag) == FrozenDHCPOptions(bag)


# --- append: all or nothing ---------------------------------------------------


class _Broken(Bytes):
    """A codec that writes part of its payload and then fails."""

    def pack_into(self, data: bytearray) -> int:
        data.extend(b"\x01\x02")
        raise DHCPValueError("the second half does not fit")


def test_a_failed_append_to_a_new_code_leaves_the_bag_unchanged() -> None:
    bag = _bag(o12=b"host")
    with pytest.raises(DHCPValueError):
        bag.append(DHCPOption(DHCPOptionCode.TIME_OFFSET, _Broken(b"x")))
    assert dict(bag) == {12: bytearray(b"host")}
    assert TIME_OFFSET not in bag


def test_a_failed_append_to_an_existing_code_leaves_its_payload() -> None:
    bag = _bag(o12=b"host")
    with pytest.raises(DHCPValueError):
        bag.append(DHCPOption(DHCPOptionCode.HOSTNAME, _Broken(b"x")))
    assert bytes(bag[12]) == b"host"


def test_append_still_extends_a_payload() -> None:
    bag = DHCPOptions()
    bag.append((int(DHCPOptionCode.ROUTER), "10.0.0.1"))
    bag.append((int(DHCPOptionCode.ROUTER), "10.0.0.2"))
    assert bytes(bag[3]) == bytes([10, 0, 0, 1, 10, 0, 0, 2])


def test_an_append_that_cannot_be_built_leaves_the_bag_unchanged() -> None:
    bag = DHCPOptions()
    with pytest.raises(DHCPValueError):
        bag.append((TIME_OFFSET, 2**31))
    assert dict(bag) == {}


# --- integers: the real range, whole numbers ----------------------------------


@pytest.mark.parametrize(
    "cls, low, high",
    [
        (U8, 0, 2**8 - 1),
        (U16, 0, 2**16 - 1),
        (U32, 0, 2**32 - 1),
        (I32, -(2**31), 2**31 - 1),
    ],
)
def test_an_integer_codec_holds_exactly_its_range(
    cls: _ty.Any, low: int, high: int
) -> None:
    for edge in (low, high):
        buffer = bytearray()
        cls(edge).pack_into(buffer)
        assert cls.unpack(buffer) == edge
    for outside in (low - 1, high + 1):
        with pytest.raises(DHCPValueError):
            cls(outside)


def test_an_integer_codec_refuses_a_fraction() -> None:
    with pytest.raises(TypeError):
        U8(1.9)
    with pytest.raises(TypeError):
        I32(-0.5)
    assert U8("7") == 7  # a text document holds numbers as text


def test_a_signed_value_too_big_is_refused_at_the_bag_with_the_option_named() -> None:
    bag = DHCPOptions()
    with pytest.raises(DHCPValueError, match=r"option 2 \(TIME_OFFSET\)"):
        bag[TIME_OFFSET] = 2**31
    assert TIME_OFFSET not in bag


# --- text options: text, or an error -------------------------------------------


@pytest.mark.parametrize("value", [None, 5, ["a", "b"], 1.5, object()])
def test_a_text_option_refuses_a_value_that_is_not_text(value: object) -> None:
    bag = DHCPOptions()
    with pytest.raises(TypeError, match=r"option 12 \(HOSTNAME\)"):
        bag[HOSTNAME] = value
    assert HOSTNAME not in bag
    with pytest.raises(TypeError):
        String(value)  # type: ignore[arg-type]


def test_a_text_option_keeps_text_and_reads_octets_as_text() -> None:
    bag = DHCPOptions()
    bag[HOSTNAME] = "host"
    assert bytes(bag[HOSTNAME]) == b"host"
    assert String(b"host") == "host" and String(bytearray(b"h")) == "h"
    assert String("") == "" and String() == ""
    bag[HOSTNAME] = b"raw\xff"  # raw octets are stored as they are
    assert bytes(bag[HOSTNAME]) == b"raw\xff"


def test_a_value_the_codec_refuses_names_the_option_and_the_type() -> None:
    bag = DHCPOptions()
    with pytest.raises(TypeError, match=r"option 61 \(CLIENT_IDENTIFIER\).*str"):
        bag[61] = "zz"


def test_setdefault_answers_one_type_whether_or_not_the_code_was_there() -> None:
    bag = DHCPOptions()
    first = bag.setdefault(53, 5)  # type: ignore[arg-type]
    second = bag.setdefault(53, 6)  # type: ignore[arg-type]
    assert type(first) is type(second) is bytearray
    assert bytes(first) == bytes(second) == b"\x05"


# --- what a value shows and what it keeps --------------------------------------


def test_an_unnamed_hardware_type_is_named_by_its_number_in_the_summary() -> None:
    from pydhcp.packet import DHCPOpcode, HardwareAddressType

    message = DHCPMessage(
        DHCPOpcode.BOOTREQUEST, htype=HardwareAddressType(200), chaddr=b"\x01\x02"
    )
    assert "HTYPE_200(" in message.summary()
    assert "None(" not in message.summary()


def test_a_client_identifier_of_an_unnamed_type_is_shown_by_its_number() -> None:
    from pydhcp.options import ClientIdentifier

    text = ClientIdentifier(b"\xff\x00\x00\x00\x01").display_text()
    assert text.startswith("HTYPE_255(") and "None" not in text


def test_a_kerberos_realm_keeps_its_case_as_it_arrived() -> None:
    from pydhcp.options import CCCKerberosRealmName

    wire = b"\x07example\x03com\x00"
    realm = CCCKerberosRealmName.unpack(wire)
    assert str(realm) == "example.com"
    assert bytes(_packed(realm)) == wire
    assert str(CCCKerberosRealmName("example.com")) == "EXAMPLE.COM"


def _packed(value: _ty.Any) -> bytearray:
    out = bytearray()
    value.pack_into(out)
    return out


def test_a_domain_list_past_the_pointer_range_writes_the_name_in_full() -> None:
    from pydhcp.options import DomainList

    # The first entry sharing the last suffix sits beyond offset 0x3FFF, which a
    # 14-bit pointer cannot name.
    unique = [f"h{i:04d}.zone{i:04d}.example" for i in range(1300)]
    names = unique + [f"www.{unique[-1].split('.', 1)[1]}"]
    wire = _packed(DomainList(names))
    assert len(wire) > 0x3FFF
    assert list(DomainList.unpack(wire)) == names


def test_a_snapshot_refuses_every_write_a_bag_makes() -> None:
    snapshot = FrozenDHCPOptions(_bag(o12=b"host"))
    with pytest.raises(TypeError):
        snapshot.setdefault(15, "example")
    with pytest.raises(TypeError):
        snapshot.append((15, "example"))
    assert bytes(snapshot.setdefault(12, "other")) == b"host"
    assert 15 not in snapshot
