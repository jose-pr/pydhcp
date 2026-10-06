"""Where `encode()` puts the options, `sname` and `file`, checked on the octets.

The expectations are laid out from RFC 2131 section 4.1 and RFC 2132 options 52,
66 and 67 (and RFC 3396 for an option split between fields), with a small reader
of the three fields that shares nothing with the encoder.
"""

from __future__ import annotations

import pytest

from pydhcp import DHCPMessage, DHCPOptionCode, DHCPOptions, DHCPValueError
from pydhcp.packet import DHCPOpcode

COOKIE = bytes([99, 130, 83, 99])


def _tlv(code: int, payload: bytes) -> bytes:
    return bytes([code, len(payload)]) + payload


def _datagram(
    main: bytes, *, sname: bytes = b"", file: bytes = b"", op: int = 2
) -> bytes:
    header = bytes([op, 1, 6, 0]) + bytes(4 + 2 + 2 + 16)
    header += bytes.fromhex("020000000001").ljust(16, b"\x00")
    return header + sname.ljust(64, b"\x00") + file.ljust(128, b"\x00") + COOKIE + main


def _read(field: bytes) -> list[tuple[int, bytes]]:
    """The options of one field, up to its END; anything else is a failure."""
    found: list[tuple[int, bytes]] = []
    index = 0
    while True:
        code = field[index]
        if code == 255:
            return found
        assert code != 0, "PAD inside the options"
        length = field[index + 1]
        found.append((code, field[index + 2 : index + 2 + length]))
        index += 2 + length


def _fields(datagram: bytes) -> tuple[list, list, list]:
    """The options field, the `file` field and the `sname` field, read.

    The last two hold options only when option 52 in the first says so."""
    main = _read(datagram[240:])
    overload = dict(main).get(52, b"\x00")[0]
    file = _read(datagram[108:236]) if overload & 1 else []
    sname = _read(datagram[44:108]) if overload & 2 else []
    return main, file, sname


def _joined(datagram: bytes) -> dict[int, bytes]:
    """Every option by code, instances joined in the order RFC 3396 section 5
    gives: the options field, then `file`, then `sname`."""
    joined: dict[int, bytes] = {}
    main, file, sname = _fields(datagram)
    for code, payload in main + file + sname:
        joined[code] = joined.get(code, b"") + payload
    return joined


def _message(
    options: dict[int, bytes], *, sname: str = "", file: str = ""
) -> DHCPMessage:
    bag = DHCPOptions()
    for code, payload in options.items():
        bag[code] = payload
    return DHCPMessage(DHCPOpcode.BOOTREPLY, sname=sname, file=file, options=bag)


def _raw(message: DHCPMessage) -> dict[int, bytes]:
    return {int(c): bytes(v) for c, v in message.options.items(decoded=False)}


# --- a name too long for its field is carried as option 66 or 67 ---------------


def test_a_decoded_long_option_66_is_encoded_again() -> None:
    name = b"t" * 100
    wire = _datagram(
        _tlv(53, b"\x02") + _tlv(52, b"\x02") + _tlv(66, name) + b"\xff",
        sname=_tlv(12, b"example") + b"\xff",
    )
    decoded = DHCPMessage.decode(wire)
    assert decoded.sname == name.decode() and 66 not in decoded.options
    again = decoded.encode(1500)
    assert _joined(again)[66] == name and _joined(again)[52] == b"\x02"
    restored = DHCPMessage.decode(again)
    assert restored.sname == decoded.sname
    assert _raw(restored) == _raw(decoded)


def test_a_decoded_long_option_67_is_encoded_again() -> None:
    boot = b"b" * 200
    wire = _datagram(
        _tlv(53, b"\x02") + _tlv(52, b"\x01") + _tlv(67, boot) + b"\xff",
        file=_tlv(12, b"example") + b"\xff",
    )
    decoded = DHCPMessage.decode(wire)
    assert decoded.file == boot.decode()
    again = decoded.encode(1500)
    assert _joined(again)[67] == boot and _joined(again)[52] == b"\x01"
    restored = DHCPMessage.decode(again)
    assert restored.file == decoded.file and _raw(restored) == _raw(decoded)


def test_a_name_set_too_long_for_its_field_travels_as_an_option() -> None:
    message = _message({53: b"\x01"}, sname="s" * 100, file="f" * 200)
    wire = message.encode(1500)
    assert _joined(wire)[66] == b"s" * 100 and _joined(wire)[67] == b"f" * 200
    assert _joined(wire)[52] == b"\x03"
    restored = DHCPMessage.decode(wire)
    assert (restored.sname, restored.file) == ("s" * 100, "f" * 200)


def test_a_name_too_long_and_no_room_for_the_option_is_refused_by_name() -> None:
    # 300 octets of name need 306 of room; the three fields hold 221.
    message = _message({53: b"\x01"}, sname="s" * 300)
    with pytest.raises(OverflowError, match=r"option 66 \(TFTP_SERVER\)"):
        message.encode(300)


def test_a_file_is_never_dropped_for_an_option_67_it_would_replace() -> None:
    # The file is occupied, option 67 holds other octets, and the options need
    # the file field: the name has nowhere to go, and saying so beats losing it.
    message = _message(
        {53: b"\x05", 67: b"other", 119: bytes([1, 97, 0]) * 120},
        sname="s",
        file="boot.img",
    )
    with pytest.raises((OverflowError, DHCPValueError), match=r"file.*option 67"):
        message.encode()


def test_an_option_67_that_already_says_the_file_is_not_written_twice() -> None:
    message = _message(
        {53: b"\x05", 67: b"boot.img", 119: bytes([1, 97, 0]) * 118},
        sname="x",
    )
    message.file = "boot.img"
    wire = message.encode()
    assert _joined(wire)[67] == b"boot.img"
    assert DHCPMessage.decode(wire).file == "boot.img"


# --- the overload option and the order of what leads ---------------------------


def _example() -> DHCPMessage:
    """The 342 octets of options of a message whose `sname` and `file` are both
    occupied: 494 octets of demand with both moved, against 497 of room."""
    options = {
        53: b"\x01",
        1: bytes(4),
        51: bytes(4),
        3: bytes(24),
        12: b"h" * 59,
        119: (b"\x0e" + b"b" * 14 + b"\x00") * 10 + b"\x09" + b"c" * 9 + b"\x00",
        43: bytes(64),
    }
    return _message(options, sname="n" * 23, file="f" * 123)


def test_a_tight_packing_leads_with_53_and_52_and_ends_every_field() -> None:
    message = _example()
    wire = message.encode()
    assert len(wire) <= 548
    main, file, sname = _fields(wire)
    assert [code for code, _ in main[:2]] == [53, 52]
    # One occupied name moved is enough: the other field keeps its literal.
    assert main[1][1] in (b"\x01", b"\x02")
    # Every option comes back whole, from the three fields together.
    restored = DHCPMessage.decode(wire)
    assert (restored.sname, restored.file) == (message.sname, message.file)
    assert _raw(restored) == _raw(message)


def test_a_message_that_fits_is_written_in_the_order_it_was_set() -> None:
    message = _message({12: b"host", 53: b"\x05", 15: b"example"})
    main, file, sname = _fields(message.encode())
    assert [c for c, _ in main] == [53, 12, 15] and file == [] and sname == []


def test_option_1_comes_before_option_3() -> None:
    # RFC 2132 section 3.3: the subnet mask option MUST be first.
    message = _message({53: b"\x05", 3: bytes(4), 6: bytes(4), 1: bytes(4)})
    main, _, _ = _fields(message.encode())
    assert [c for c, _ in main] == [53, 1, 3, 6]


def test_option_1_before_option_3_holds_in_an_overloaded_message() -> None:
    message = _example()
    wire = message.encode()
    main, file, sname = _fields(wire)
    order = [c for c, _ in main + file + sname]
    # Within each field, 1 never follows 3.
    for field in (main, file, sname):
        codes = [c for c, _ in field]
        if 1 in codes and 3 in codes:
            assert codes.index(1) < codes.index(3)
    assert 1 in order and 3 in order


def test_options_are_split_between_fields_in_the_order_rfc_3396_gives() -> None:
    # 340 octets of host name do not fit the options field after 53 and 52:
    # 255 and 42 octets stay, and 43 go to the first overloaded field, laid out
    # by hand from RFC 3396 section 6 (instances in order, each with its own
    # length octet, the options field read first).
    name = bytes(range(32, 32 + 100)) * 3 + bytes(40)
    assert len(name) == 340
    message = _message({53: b"\x05", 12: name})
    expected_main = (
        _tlv(53, b"\x05")
        + _tlv(52, b"\x02")
        + _tlv(12, name[:255])
        + _tlv(12, name[255:297])
        + b"\xff"
    )
    expected_sname = _tlv(12, name[297:]) + b"\xff"
    wire = message.encode()
    assert wire[240 : 240 + len(expected_main)] == expected_main
    assert wire[44 : 44 + len(expected_sname)] == expected_sname
    assert _joined(wire)[12] == name


# --- the smallest sizes ---------------------------------------------------------


def test_nothing_encodes_below_269_and_an_empty_message_at_269() -> None:
    message = DHCPMessage(DHCPOpcode.BOOTREQUEST)
    with pytest.raises(ValueError, match="269"):
        message.encode(268)
    assert len(message.encode(269)) == 241


@pytest.mark.parametrize("size", [269, 270, 271])
def test_an_option_that_cannot_fit_names_it_and_the_shortfall(size: int) -> None:
    message = _message({53: b"\x01"})
    with pytest.raises(
        OverflowError, match=r"option 53 \(DHCP_MESSAGE_TYPE\)"
    ) as caught:
        message.encode(size)
    assert "short" in str(caught.value)


def test_the_smallest_message_with_an_option_is_272() -> None:
    wire = _message({53: b"\x01"}).encode(272)
    assert wire[240:244] == b"\x35\x01\x01\xff" and len(wire) == 244


@pytest.mark.parametrize("size", range(272, 332))
def test_a_message_never_passes_its_datagram_budget(size: int) -> None:
    message = _message({53: b"\x01", 12: b"h" * 40})
    try:
        wire = message.encode(size)
    except OverflowError:
        return
    assert len(wire) <= size - 28
    assert len(wire) == min(300, size - 28) or len(wire) > 300
    restored = DHCPMessage.decode(wire)
    assert _raw(restored) == _raw(message)


def test_the_overload_option_stays_in_the_options_field_at_the_smallest_sizes() -> None:
    message = _message({53: b"\x01", 12: b"h" * 40})
    with pytest.raises(OverflowError, match=r"option 53.*option 52|overload"):
        message.encode(274)
    wire = message.encode(275)
    main, _, sname = _fields(wire)
    assert [c for c, _ in main] == [53, 52] and sname == [(12, b"h" * 40)]
    assert DHCPMessage.decode(wire).options.get(12) == "h" * 40


def test_the_refusal_says_which_option_did_not_fit_and_by_how_much() -> None:
    message = _message({53: b"\x01", 119: bytes([1, 97, 0]) * 200})
    with pytest.raises(OverflowError) as caught:
        message.encode()
    text = str(caught.value)
    assert "option 119 (DOMAIN_SEARCH)" in text and "short" in text
    assert "576" in text


def test_a_header_whose_hlen_disagrees_with_chaddr_is_refused_by_name() -> None:
    message = DHCPMessage(DHCPOpcode.BOOTREQUEST, chaddr=b"\x01\x02\x03\x04\x05\x06")
    message.hlen = 4
    with pytest.raises(DHCPValueError, match="hlen=4"):
        message.encode()
