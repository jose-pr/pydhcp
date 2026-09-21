import json
import logging
import pytest
from datetime import timedelta
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.packet.message import DhcpMessage
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4
from pydhcp.options import DhcpOptions


def test_message_encode_decode():
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER.value]
    )
    options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray([1, 0, 17, 34, 51, 68, 85])
    options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = bytearray([1, 3, 6, 15])

    msg = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x3903F326,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        sname="",
        file="",
        options=options,
    )

    encoded = msg.encode()
    assert len(encoded) >= 240

    decoded = DhcpMessage.decode(encoded)
    assert decoded.op == OpCode.BOOTREQUEST
    assert decoded.xid == 0x3903F326
    # Exactly, not as a prefix: `chaddr` is a 16-octet field on the wire and
    # `decode` trims it back to `hlen`. `startswith` passed just as happily on
    # the untrimmed form, which is what the trim exists to prevent -- a client
    # identifier derived from it would carry ten trailing zeros.
    assert decoded.chaddr == b"\x00\x11\x22\x33\x44\x55"
    assert (
        decoded.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
        == DhcpMessageType.DHCPDISCOVER
    )


def test_message_edge_cases():
    # Message with sname and file populated
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPOFFER.value]
    )
    msg = DhcpMessage(
        op=OpCode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=1,
        xid=0x11112222,
        secs=timedelta(seconds=5),
        flags=Flags.BROADCAST,
        ciaddr=IPv4("192.168.1.5"),
        yiaddr=IPv4("192.168.1.10"),
        siaddr=IPv4("192.168.1.1"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        sname="my-server-name",
        file="boot-file-path",
        options=options,
    )
    encoded = msg.encode()
    decoded = DhcpMessage.decode(encoded)
    # Exactly, not as a prefix: `sname` and `file` are NUL-padded 64- and
    # 128-octet fields, and `startswith` accepted the padded form. A boot file
    # name carrying 114 trailing NULs is what a PXE client would then fetch.
    assert decoded.sname == "my-server-name"
    assert decoded.file == "boot-file-path"
    assert decoded.hops == 1
    assert decoded.secs == timedelta(seconds=5)
    assert decoded.flags == Flags.BROADCAST
    assert decoded.ciaddr == IPv4("192.168.1.5")
    assert decoded.yiaddr == IPv4("192.168.1.10")
    assert decoded.siaddr == IPv4("192.168.1.1")

    # String representations
    log_str = msg.log_str(IPv4("192.168.1.1"), IPv4("192.168.1.10"))
    assert "XID=11112222" in log_str


# --- Packet logging must never cost a packet its handler or its reply ---
#
# The listener calls msg.log() before handle(), and the server calls it before
# transport.send(), so anything that raises here is a silent packet drop.


def _discover_with(code, payload):
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER.value]
    )
    options[code] = bytearray(payload)
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x11223344,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=bytearray(b"\x00\x11\x22\x33\x44\x55"),
        sname="",
        file="",
        options=options,
    )


@pytest.mark.parametrize(
    "code,payload,label",
    [
        (224, b"\x01\x02\x03", "site-specific code with no enum member (RFC 3942)"),
        (DhcpOptionCode.ROUTER, b"\x01\x02", "truncated ROUTER payload"),
        (DhcpOptionCode.RAPID_COMMIT, b"", "zero-length RAPID_COMMIT (RFC 4039)"),
    ],
)
def test_dumps_tolerates_undecodable_options(code, payload, label):
    """dumps() must degrade per option to hex, the way to_mapping() already does.

    93 of 254 option codes are not enum members, including 28 in the private-use
    range, so raising here means a client sending any of them gets no service.
    """
    message = _discover_with(code, payload)

    dumped = message.dumps()

    assert "DHCPDISCOVER" in dumped
    assert str(int(code)) in dumped


def test_log_is_lazy_and_never_raises(caplog):
    """log() must do no formatting work when the level is disabled, and must not
    propagate a formatting failure to its caller."""
    message = _discover_with(224, b"\x01\x02\x03")

    calls = []
    original_dumps = type(message).dumps

    def counting_dumps(self, *args, **kwargs):
        calls.append(1)
        return original_dumps(self, *args, **kwargs)

    type(message).dumps = counting_dumps
    try:
        with caplog.at_level(logging.WARNING, logger="pydhcp"):
            message.log("src", "dst", logging.DEBUG)
        assert calls == [], "dumps() ran even though DEBUG was disabled"

        with caplog.at_level(logging.DEBUG, logger="pydhcp"):
            message.log("src", "dst", logging.DEBUG)
        assert calls == [1], "dumps() did not run when DEBUG was enabled"
    finally:
        type(message).dumps = original_dumps


def test_encode_clears_a_stale_option_overload():
    """A decoded overloaded packet carries its sender's option 52.

    Re-encoding it (a relay forwarding a PXE reply) must not keep the marker:
    decode moves the real sname/file out of the overloaded fields, so a stale 52
    tells the receiver to parse literal text as options.
    """
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPACK.value]
    )
    options[DhcpOptionCode.OPTION_OVERLOAD] = bytearray([3])
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    message.options = options
    message.sname = "10.0.0.5"
    message.file = "pxelinux.0"

    wire = bytes(message.encode())
    decoded = DhcpMessage.decode(bytearray(wire))

    assert DhcpOptionCode.OPTION_OVERLOAD not in decoded.options
    assert decoded.sname == "10.0.0.5"
    assert decoded.file == "pxelinux.0"


def test_encode_raises_rather_than_dropping_options_that_do_not_fit():
    """Encoding more options than the packet can hold must raise, not truncate.

    This reaches the up-front size check. The matching guard after the sname
    field is packed is defensive: no input was found that reaches it once the
    size accounting is correct, but leftover was previously discarded there
    without inspection.
    """
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPACK.value]
    )
    for index in range(12):
        options[200 + index] = bytearray(b"X" * 250)
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    message.options = options

    with pytest.raises(OverflowError):
        message.encode(576)


def test_decode_tolerates_non_utf8_sname_and_file():
    """RFC 2131 says NVT ASCII, but senders put other encodings there. Rejecting
    the field threw away the whole packet, message type and client id included."""
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER.value]
    )
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    wire = bytearray(message.encode())
    # Splice latin-1 bytes into the sname (offset 44) and file (offset 108) fields.
    wire[44:52] = b"caf\xe9-srv"
    wire[108:116] = b"b\xfcte.cfg"

    decoded = DhcpMessage.decode(wire)

    assert decoded.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == (
        DhcpMessageType.DHCPDISCOVER
    )
    assert decoded.sname and decoded.file


def test_non_utf8_sname_and_file_survive_a_re_encode():
    """Tolerating the field is not enough -- a relay must forward it unchanged.

    `file` is the PXE boot filename. Decoding with errors="replace" kept the
    packet but destroyed the bytes: each octet became the three of U+FFFD, so
    the forwarded name differed from the one the server sent, and near the fixed
    64/128-octet width it was truncated as well. The client then asks its TFTP
    server for a file that does not exist.
    """
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    wire = bytearray(message.encode())
    sname = b"caf\xe9-srv"
    file = b"b\xfcte.cfg"
    wire[44:108] = sname.ljust(64, b"\x00")
    wire[108:236] = file.ljust(128, b"\x00")

    decoded = DhcpMessage.decode(bytearray(wire))
    out = bytes(decoded.encode())

    assert out[44:108] == sname.ljust(64, b"\x00"), "sname octets were not preserved"
    assert out[108:236] == file.ljust(128, b"\x00"), "file octets were not preserved"

    # Rendering stays safe: no preserved octet reaches a terminal or serializer.
    decoded.dumps().encode("utf-8")
    mapping = decoded.to_mapping()
    assert "�" in mapping["sname"] and "�" in mapping["file"]
    json.dumps(mapping, ensure_ascii=False).encode("utf-8")


def test_valid_utf8_sname_is_unchanged_by_the_preserving_path():
    """The ordinary case must not move."""
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    wire = bytearray(message.encode())
    name = "münchen-srv".encode("utf-8")
    wire[44:108] = name.ljust(64, b"\x00")

    decoded = DhcpMessage.decode(bytearray(wire))

    assert decoded.sname == "münchen-srv"
    assert bytes(decoded.encode())[44:108] == name.ljust(64, b"\x00")
    assert decoded.to_mapping()["sname"] == "münchen-srv"


def test_unidentifiable_client_does_not_collide_with_every_other_one():
    """hlen=0 with no option 61 leaves nothing to key a lease on.

    hlen=0 is legal -- RFC 4390 requires exactly that for IPoIB, which supplies
    option 61 instead -- so it must not be rejected at decode. But the old
    fallback built the identifier from the hardware type alone, so every such
    client got "01": two of them would take over each other's lease, and a
    RELEASE from either would free both.
    """
    from pydhcp.packet.message import NoClientIdentity

    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    wire = bytearray(message.encode())
    wire[2] = 0  # hlen

    decoded = DhcpMessage.decode(bytearray(wire))
    assert decoded.chaddr == b""
    with pytest.raises(NoClientIdentity):
        decoded.client_id()

    # The legal IPoIB shape -- hlen 0, htype 32, option 61 present -- still works.
    ipoib = _discover_with(DhcpOptionCode.CLIENT_IDENTIFIER, b"\xff\x01\x02\x03")
    wire = bytearray(ipoib.encode())
    wire[1] = 32
    wire[2] = 0
    decoded = DhcpMessage.decode(bytearray(wire))
    assert decoded.htype == 32
    assert decoded.client_id() == "FF:01:02:03"


def test_unnamed_htype_survives_a_mapping_round_trip():
    """to_mapping() emits label(), because an unnamed member has no .name.

    Emitting None there put a null where a string belongs, and from_mapping()
    could not read its own output back.
    """
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    wire = bytearray(message.encode())
    wire[1] = 99

    decoded = DhcpMessage.decode(bytearray(wire))
    mapping = decoded.to_mapping()

    assert mapping["htype"] == "HTYPE_99"
    json.dumps(mapping)
    assert DhcpMessage.from_mapping(mapping).htype == 99


def test_encoded_messages_meet_the_bootp_minimum():
    """RFC 1542 s2.1 makes a short datagram discardable, not merely unusual.

    An agent performing the consistency checks "MUST silently discard" a BOOTP
    message whose UDP payload cannot hold 300 octets. Every message pydhcp emits
    with few options was under that -- all five client builders and the server's
    NAK, measured at 244-250 octets -- while ISC dhclient was measured padding to
    exactly 300 on the wire.
    """
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")

    wire = bytes(message.encode())
    assert len(wire) == 300

    # The padding is PAD octets after END, so it changes nothing semantically.
    end = wire.index(0xFF, 240)
    assert set(wire[end + 1 :]) == {0}, "padding must be PAD octets, after END"
    assert (
        DhcpMessage.decode(bytearray(wire)).options.get(
            DhcpOptionCode.DHCP_MESSAGE_TYPE
        )
        == DhcpMessageType.DHCPDISCOVER
    )

    # A message that is already long enough is not touched.
    big = _discover_with(200, b"X" * 200)
    assert len(bytes(big.encode())) > 300

    # And padding never exceeds an explicit limit below the minimum.
    assert len(bytes(message.encode(280))) == 280


def test_min_legal_size_is_the_rfc2131_capability_floor():
    """548 is not an arbitrary constant, and not a limit on any packet.

    RFC 2131 s2 states it twice over, and the two statements must agree:
    576 is the minimum IP datagram an IP host must accept, and a client "MUST
    be prepared to receive DHCP messages with an 'options' field of at least
    length 312 octets".
    """
    from pydhcp import constants as const

    fixed_header = 236  # op..file, RFC 2131 s2 figure 1
    ipv4_and_udp = 20 + 8

    assert const.UDP_MIN_PACKET_SIZE == ipv4_and_udp
    assert DhcpMessage.MIN_LEGAL_SIZE == const.DHCP_MIN_LEGAL_PACKET_SIZE - ipv4_and_udp
    assert DhcpMessage.MIN_LEGAL_SIZE == 548
    assert DhcpMessage.MIN_LEGAL_SIZE - fixed_header == 312


def test_decode_applies_no_minimum_size():
    """Liberal on receive, strict on send.

    RFC 1542 s2.1's "MUST silently discard" binds a relay agent performing the
    consistency checks, not a decoder; 6 of the 13 realistic corpus packets are
    under 300 octets, so enforcing a floor here would reject real traffic.
    """
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    wire = bytes(message.encode())
    end = wire.index(0xFF, 240)

    for size in (end + 1, 241):
        short = bytearray(wire[:size])
        if short[-1] != 0xFF:
            short[-1] = 0xFF
        decoded = DhcpMessage.decode(short)
        assert decoded.xid == message.xid, f"{size}-octet message was not decoded"

    assert len(bytes(message.encode())) == 300, "what we send is still padded"


def _first_option_code(wire):
    """The code octet of the first TLV after the magic cookie."""
    return bytes(wire)[240]


def _wire_overload_flag(wire):
    """The value of option 52 as it appears on the wire, or None.

    `decode` consumes option 52 and drops it -- it is framing, like PAD and
    END -- so a decoded message cannot answer "did this overload?". The wire
    can, and it is the stronger place to ask: it reads the octets the peer
    would, rather than trusting our own decoder's bookkeeping.
    """
    data = bytes(wire)
    index = 240
    while index < len(data):
        code = data[index]
        if code == 255:  # END
            return None
        if code == 0:  # PAD
            index += 1
            continue
        length = data[index + 1]
        if code == int(DhcpOptionCode.OPTION_OVERLOAD):
            return data[index + 2]
        index += 2 + length
    return None


def _overloading_message(count, payload_size):
    """A message whose options force `encode(576)` to overload sname/file."""
    options = DhcpOptions()
    options[DhcpOptionCode.SERVER_IDENTIFIER] = bytearray(b"\x0a\x00\x00\x01")
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPACK.value]
    )
    for index in range(count):
        options[200 + index] = bytearray(b"X" * payload_size)
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    message.options = options
    message.sname = "tftp.example.test"
    message.file = "pxelinux.0"
    return message


def test_message_type_leads_the_options_field_whether_or_not_we_overload():
    """RFC 2131 s3 walks the protocol by message type, and receivers read option
    53 before parsing the rest -- it is what says whether the packet is for them.

    The ordering step existed but reached neither path: the non-overload path
    kept the `options.encode()` taken for sizing, which predates the move, and
    the overload path then put OPTION_OVERLOAD in front of it. Measured on the
    bytes, not the mapping: the mapping never showed the defect, because the
    move *was* applied to it.
    """
    # Non-overload: option 53 is inserted last, so only the reordering can put
    # it first.
    options = DhcpOptions()
    options[DhcpOptionCode.SERVER_IDENTIFIER] = bytearray(b"\x0a\x00\x00\x01")
    options[DhcpOptionCode.ROUTER] = bytearray(b"\x0a\x00\x00\xfe")
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPACK.value]
    )
    plain = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    plain.options = options

    wire = bytes(plain.encode())
    assert _first_option_code(wire) == int(DhcpOptionCode.DHCP_MESSAGE_TYPE)
    assert wire[241:243] == b"\x01\x05", "53 must carry its own length and payload"

    # Overload, both flavours. OPTION_OVERLOAD is written after the reordering
    # and used to be pushed in front of the message type.
    for count, payload_size, expected in (
        (2, 180, 1),  # SNAME
        (2, 160, 2),  # FILE
        (2, 220, 3),  # BOTH
    ):
        message = _overloading_message(count, payload_size)
        wire = bytes(message.encode(576))
        decoded = DhcpMessage.decode(bytearray(wire))

        assert (
            _wire_overload_flag(wire) == expected
        ), f"{count}x{payload_size} did not overload as expected"
        assert (
            DhcpOptionCode.OPTION_OVERLOAD not in decoded.options
        ), "decode consumes option 52; leaving it makes the message lie"
        assert _first_option_code(wire) == int(DhcpOptionCode.DHCP_MESSAGE_TYPE)
        assert (
            decoded.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
            == DhcpMessageType.DHCPACK
        )


def test_encode_refuses_a_size_it_cannot_honour_instead_of_substituting_576():
    """`max_packetsize or DHCP_MIN_LEGAL_PACKET_SIZE` made an explicit 0 mean 576.

    Quietly encoding to a number other than the one the caller named is exactly
    the failure this module has spent the most effort removing: a caller asking
    for 0 has a wrong belief, and answering it with a 300-octet packet hides
    that. 269 is the real floor -- 268 of IPv4/UDP/header/cookie overhead plus
    the END octet -- and is NOT 576: RFC 2132 s9.10's 576 constrains what a
    client may advertise in option 57, not this API.
    """
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")

    for refused in (0, -1, 1, 100, 267, 268):
        with pytest.raises(ValueError) as excinfo:
            message.encode(refused)
        assert "269" in str(excinfo.value), "the error must name the real floor"
        assert str(refused) in str(excinfo.value), "and the value it was given"

    # No argument still means 576, and every size from the floor up that used to
    # work still does -- including the sub-576 ones.
    assert len(bytes(message.encode())) == 300
    for accepted in (272, 280, 299, 300, 312, 548, 575, 576, 1500):
        assert len(bytes(message.encode(accepted))) <= accepted


def test_over_long_sname_and_file_are_refused_rather_than_truncated():
    """Silent truncation is worse than the struct.error it sits next to.

    `file` is the PXE boot filename: a truncated one sends the client to a TFTP
    path that does not exist and nothing in the exchange says why. Measured
    2026-09-20: a 100-character sname and a 200-character file both encoded
    "successfully" at 300 octets, carrying only the first 64 and 128 octets.
    """
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")

    message.sname = "s" * 65
    with pytest.raises(ValueError, match="sname"):
        message.encode()

    message.sname = "s" * 64  # exact fit still encodes
    assert bytes(message.encode())[44:108] == b"s" * 64

    # Octets, not characters: a 33-character Latin-1 name is 66 octets.
    message.sname = "é" * 33
    with pytest.raises(ValueError, match="sname"):
        message.encode()

    message.sname = ""
    message.file = "f" * 129
    with pytest.raises(ValueError, match="file"):
        message.encode()

    message.file = "f" * 128
    assert bytes(message.encode())[108:236] == b"f" * 128

    # chaddr shares the pattern and the fix.
    message.file = ""
    message.chaddr = b"\xaa" * 20
    with pytest.raises(ValueError, match="chaddr"):
        message.encode()


def test_overloading_still_moves_a_long_sname_and_file_into_options():
    """The truncation guard must not fire on values the encoder legitimately
    moved out: when overloading, sname/file carry option fragments instead, and
    the real names travel in options 66 and 67."""
    message = _overloading_message(2, 220)

    wire = message.encode(576)
    decoded = DhcpMessage.decode(bytearray(wire))

    assert _wire_overload_flag(wire) == 3, "sname and file"
    assert bytes(wire)[44:108] != b"tftp.example.test".ljust(
        64, b"\x00"
    ), "the sname field should hold option fragments, not the literal name"
    assert decoded.sname == "tftp.example.test"
    assert decoded.file == "pxelinux.0"


def test_an_overloaded_message_round_trips():
    """decode(encode(m)) == m, even when the encoder had to overload.

    Found by the hypothesis round-trip property on Linux, where a wider router
    list tipped messages over the 576-octet budget that Windows never reached.
    `encode` deletes option 52 from the mapping it builds -- the flag describes
    the framing it is *about to* write, not a value the caller set -- but
    `decode` kept the flag it had just consumed. So a message that overloaded
    came back carrying an option its author never set, and comparing the two
    mappings failed on an option neither side asked for.
    """
    # Empty sname/file on purpose. When they hold values the encoder moves
    # them into options 66/67 to survive the trip, so the decoded mapping
    # legitimately gains two options -- a round-trip comparison would fail for
    # a reason that is not the defect. Overflowing with plain options isolates
    # it, and is what hypothesis generated.
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPACK.value]
    )
    options[200] = bytearray(b"X" * 220)
    options[201] = bytearray(b"X" * 220)
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    message.options = options
    message.sname = ""
    message.file = ""

    wire = message.encode(576)
    assert _wire_overload_flag(wire) == 3, "the fixture must actually overload"

    decoded = DhcpMessage.decode(bytearray(wire))
    assert decoded.to_mapping() == message.to_mapping()

    # And it survives a second pass: the re-encode overloads again off the
    # option payloads, not off a leftover flag.
    assert _wire_overload_flag(decoded.encode(576)) == 3


def test_out_of_range_header_fields_name_the_field():
    """`pack_into` names the struct format character, not the field.

    Measured 2026-09-20: hops=256, hlen=256 and xid=2**32 each produced
    `'B' format requires 0 <= number <= 255` (or `'I' ...`), from which a caller
    cannot tell which of the four B-format fields was wrong -- and `struct.error`
    is neither ValueError nor TypeError, so an `except ValueError` on a send
    path did not catch it at all.
    """
    for field, value in (
        ("hops", 256),
        ("hops", -1),
        ("hlen", 256),
        ("xid", 2**32),
        ("xid", -1),
    ):
        message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
        setattr(message, field, value)
        with pytest.raises(ValueError, match=field):
            message.encode()

    # hlen is bounded by 16, not 255: chaddr is a 16-octet field, so a larger
    # hlen has the receiver read past it into sname. decode() already rejected
    # it with the same bound, so hlen=17 encoded happily and would not decode.
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    message.hlen = 17
    with pytest.raises(ValueError, match="hlen"):
        message.encode()
    message.hlen = 16
    message.chaddr = b"\xaa" * 16
    assert DhcpMessage.decode(bytearray(message.encode())).hlen == 16

    # secs is clamped, not rejected: it is elapsed time the client reports, and
    # an overlong one is not a caller error.
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    message.secs = timedelta(seconds=100_000)
    assert DhcpMessage.decode(bytearray(message.encode())).secs == timedelta(
        seconds=0xFFFF
    )
