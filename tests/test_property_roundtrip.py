from __future__ import annotations

from datetime import timedelta

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, assume, event, given, settings, strategies as st

from ipaddress import IPv4Address as IPv4

from ipaddress import IPv4Network
from pydhcp.options import DHCPOptionCode, DHCPOptions
from pydhcp.packet import DHCPMessageType, DHCPFlags, HardwareAddressType, DHCPOpcode
from pydhcp.packet import DHCPMessage
from pydhcp.options import (
    U8,
    U16,
    U32,
    I32,
    Boolean,
    String,
    Bytes,
    List,
    IPv4AddressOption,
    DomainList,
    ClasslessRoute,
)

# No profile was registered at all, so these ran under hypothesis' defaults --
# including its 200 ms per-example deadline, which is a *timing* assertion on a
# shared CI runner and has nothing to say about a codec. One second is not a
# performance target either; it is the "this has become pathological" line, the
# only thing a deadline is useful for here. `too_slow` is suppressed for the
# same reason: the message-level strategy builds real packets, and a slow data
# generator is not a failure of the property.
settings.register_profile(
    "pydhcp",
    deadline=timedelta(seconds=1),
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("pydhcp")


def _round_trip(value):
    """Encode, decode, re-encode. Returns the decoded value for the caller.

    The re-encode comparison alone is weaker than it looks: a codec that
    decoded to a constant would still re-encode to the same octets. Callers
    must assert the decoded *value*, which for the integer types they did not.
    """
    encoded = value.pack()
    decoded = type(value).unpack(encoded)
    reencoded = decoded.pack()
    assert encoded == reencoded
    assert type(decoded) is type(value)
    return decoded


@given(st.integers(min_value=0, max_value=0xFF))
def test_u8_round_trip(n: int) -> None:
    assert _round_trip(U8(n)) == n


@given(st.integers(min_value=0, max_value=0xFFFF))
def test_u16_round_trip(n: int) -> None:
    assert _round_trip(U16(n)) == n


@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_u32_round_trip(n: int) -> None:
    assert _round_trip(U32(n)) == n


@given(st.integers(min_value=-(2**31), max_value=2**31 - 1))
def test_i32_round_trip(n: int) -> None:
    decoded = _round_trip(I32(n))
    assert decoded == n
    # The sign is the whole reason I32 exists apart from U32, and comparing a
    # decoded value only against itself would not have noticed an unsigned one.
    assert (decoded < 0) == (n < 0)


@given(st.booleans())
def test_boolean_round_trip(b: bool) -> None:
    decoded = _round_trip(Boolean(b))
    assert bool(decoded) == b


#: Anything encodable as UTF-8 except NUL. The alphabet was printable ASCII
#: only, which is the subset that could not possibly expose a codec that
#: assumed one octet per character -- a hostname or a boot filename is neither
#: ASCII-only nor a fixed width. NUL is excluded because it *terminates* an NVT
#: string on the wire: measured, `String("a\0b")` decodes back to `"a"`, so no
#: value containing one can round-trip and generating them would only assert
#: that truncation.
_CHARS = st.characters(codec="utf-8", exclude_characters="\x00")


def _sized(strategy, short_max: int, long_min: int, long_max: int):
    """Short values *and* long ones, because `max_size` alone yields neither.

    Measured on this hypothesis (6.165): `st.binary(max_size=1024)` produced
    nothing longer than 50 octets across 400 examples, and
    `st.lists(..., max_size=40)` never exceeded 21 entries. `max_size` is a
    ceiling the generator approaches essentially never, so raising it is the
    kind of widening that changes nothing at all -- the interesting sizes have
    to be asked for with `min_size`. 255 is the boundary that matters here: it
    is one option instance's maximum payload, above which RFC 3396 splitting
    and the length octet's own limit come into play.
    """
    return st.one_of(
        strategy(max_size=short_max),
        strategy(min_size=long_min, max_size=long_max),
    )


_TEXT = _sized(lambda **kw: st.text(alphabet=_CHARS, **kw), 80, 200, 400)


@given(_TEXT)
def test_string_round_trip(s: str) -> None:
    decoded = _round_trip(String(s))
    assert str(decoded) == s


@given(_sized(st.binary, 80, 300, 1024))
def test_bytes_round_trip(b: bytes) -> None:
    decoded = _round_trip(Bytes(b))
    assert bytes(decoded) == b
    assert len(decoded) == len(b)


_ADDRESS = st.ip_addresses(v=4).map(str)


@given(_sized(lambda **kw: st.lists(_ADDRESS, **kw), 16, 64, 90))
def test_list_ipv4address_round_trip(addrs: list[str]) -> None:
    decoded = _round_trip(List[IPv4AddressOption](addrs))
    # The whole list and its order, not just its first entry: a codec that
    # stopped after one address, or reversed them, produced an equal *first*
    # element. `max_size` was 8, i.e. 32 octets -- comfortably inside one
    # option instance, so the long branch above is what reaches past 255.
    assert list(decoded) == [IPv4AddressOption(a) for a in addrs]
    assert len(decoded) == len(addrs)


#: A DNS label as the wire allows it, not as a lowercase slug: 1-63 octets of
#: letters, digits and hyphen, in either case. The old alphabet was
#: `[a-z0-9-]{1,20}` -- three quarters of the legal length and no uppercase, so
#: a codec that lowercased a search-list entry (which a case-insensitive
#: *comparison* would forgive but a re-encode must not) went undetected.
_LABEL = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
    min_size=1,
    max_size=63,
)


@st.composite
def _domains(draw):
    """A domain name of up to six labels, bounded at 250 octets.

    RFC 3397 encodes one entry as length-prefixed labels plus a root octet, so
    an entry over 255 octets is rejected by the codec by design -- measured:
    `ValueError: search-list entry exceeds 255 octets`. Labels are dropped
    rather than filtered so hypothesis never has to discard a draw.
    """
    labels = draw(st.lists(_LABEL, min_size=1, max_size=6))
    while len(".".join(labels)) > 250 and len(labels) > 1:
        labels.pop()
    return ".".join(labels)


@given(
    st.one_of(
        st.lists(_domains(), min_size=1, max_size=4),
        st.lists(_domains(), min_size=8, max_size=14),
    )
)
def test_domain_list_round_trip(domains: list[str]) -> None:
    value = DomainList(domains)
    encoded = value.pack()
    decoded = DomainList.unpack(encoded)
    assert list(decoded) == domains
    # Repeated names are where RFC 1035 compression pointers get emitted, and a
    # pointer that terminates an entry used to drop every name after it. The
    # count is the assertion that catches a recurrence -- comparing only the
    # contents would pass while entries went missing.
    assert len(list(decoded)) == len(domains)
    assert DomainList.unpack(decoded.pack()) == decoded


@given(_ADDRESS, _ADDRESS, st.integers(0, 32))
def test_classless_route_round_trip(gateway: str, address: str, prefixlen: int) -> None:
    # The network was always `10.0.0.0/<n>`, so octets 2-4 were zero in every
    # single example -- and RFC 3442's encoding is "significant octets only",
    # which is exactly the part that zero octets cannot exercise. A route to
    # 10.20.30.0/24 costs three octets and one to 10.0.0.0/24 costs one, and
    # only the first tells a correct encoder from a truncating one.
    network = IPv4Network(f"{address}/{prefixlen}", strict=False)
    decoded = _round_trip(ClasslessRoute(IPv4(gateway), network))
    assert decoded.gateway == IPv4(gateway)
    assert decoded.network == network


# --- and the same values through the containers a packet actually uses -------
#
# Everything above goes straight to `pack`/`unpack`. That skips
# the option bag (code and length octets, RFC 3396 splitting, option order) and
# the message (the fixed header, the magic cookie, sname/file overloading) --
# i.e. everything between a codec and a packet on the wire.


def _fits(text: str, max_octets: int) -> str:
    """Trim `text` to `max_octets` of UTF-8, on a character boundary.

    `sname` and `file` are fixed 64- and 128-*octet* BOOTP fields and `encode`
    refuses an overlong value outright (measured: "sname is 256 octets and does
    not fit its 64-octet BOOTP field" for 64 emoji). Character counts are
    therefore the wrong bound as soon as the alphabet stops being ASCII, which
    is exactly the widening this file needed.
    """
    while len(text.encode("utf-8")) > max_octets:
        text = text[:-1]
    return text


def _nvt_field(max_octets: int):
    """A short value and a near-full one, both bounded by octets."""
    return st.one_of(
        st.text(alphabet=_CHARS, max_size=max_octets),
        st.text(alphabet=_CHARS, min_size=max_octets // 2, max_size=max_octets),
    ).map(lambda text: _fits(text, max_octets))


@st.composite
def _option_bags(draw) -> DHCPOptions:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = draw(st.sampled_from(DHCPMessageType))
    options[DHCPOptionCode.SUBNET_MASK] = IPv4(draw(_ADDRESS))
    options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = draw(st.integers(0, 0xFFFFFFFF))
    routers = draw(st.lists(_ADDRESS, max_size=16))
    if routers:
        options[DHCPOptionCode.ROUTER] = routers
    hostname = draw(_nvt_field(60))
    if hostname:
        options[DHCPOptionCode.HOSTNAME] = hostname
    search = draw(st.lists(_domains(), max_size=3))
    if search:
        options[DHCPOptionCode.DOMAIN_SEARCH] = search
    vendor = draw(
        st.one_of(st.binary(max_size=16), st.binary(min_size=40, max_size=64))
    )
    if vendor:
        options[DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION] = vendor
    return options


@given(_option_bags())
def test_option_bag_round_trip(options: DHCPOptions) -> None:
    """A bag of options survives its own wire form, payloads and order alike."""
    encoded = options.encode()
    assert encoded[-1] == 255

    decoded = DHCPOptions.decode(memoryview(encoded))

    assert list(decoded.items(decoded=False)) == list(options.items(decoded=False))
    assert bytes(decoded.encode()) == bytes(encoded)


@st.composite
def _messages(draw) -> DHCPMessage:
    chaddr = draw(st.binary(min_size=0, max_size=16))
    return DHCPMessage(
        op=draw(st.sampled_from([DHCPOpcode.BOOTREQUEST, DHCPOpcode.BOOTREPLY])),
        htype=HardwareAddressType.ETHERNET,
        hlen=len(chaddr),
        hops=draw(st.integers(0, 255)),
        xid=draw(st.integers(0, 0xFFFFFFFF)),
        # Capped at the two octets the field has: above 65535 `encode` saturates
        # rather than wrapping, so a larger value is a deliberate clamp and not
        # a round trip to assert.
        secs=timedelta(seconds=draw(st.integers(0, 0xFFFF))),
        flags=draw(st.sampled_from([DHCPFlags.UNICAST, DHCPFlags.BROADCAST])),
        ciaddr=IPv4(draw(_ADDRESS)),
        yiaddr=IPv4(draw(_ADDRESS)),
        siaddr=IPv4(draw(_ADDRESS)),
        giaddr=IPv4(draw(_ADDRESS)),
        chaddr=chaddr,
        # 64 and 128 octets are the fields' sizes on the wire.
        sname=draw(_nvt_field(64)),
        file=draw(_nvt_field(128)),
        options=draw(_option_bags()),
    )


#: Octets of option payload a default-size packet holds in its options field
#: (576 less 28 of IP and UDP less 240 of header and cookie), END included.
_OPTIONS_FIELD = 308


def _needs_a_field_moved(message: DHCPMessage) -> bool:
    """Whether the options only fit by moving an occupied `sname` or `file`.

    Counted from the wire form of the bag alone, never from `encode`: the
    options overflow the options field, so the only room is in `sname` and
    `file`, and an occupied one has to travel as option 66 or 67 first.
    """
    return len(message.options.encode()) > _OPTIONS_FIELD and bool(
        message.sname or message.file
    )


def _tlv(code: int, payload: bytes) -> bytes:
    return bytes([code, len(payload)]) + payload


#: A message whose options need 342 octets against a 308-octet field while
#: `sname` (23 octets) and `file` (123) are both occupied. Overloading both
#: fields fits it: 494 octets of options, the overload option and the two
#: relocated names, against 307 + 127 + 63 octets of room.
_SNAME = "n" * 23
_FILE = "f" * 123
_PACKED_OPTIONS = {
    53: b"\x01",
    1: bytes(4),
    51: bytes(4),
    3: bytes(24),
    12: b"h" * 59,
    119: (b"\x0e" + b"b" * 14 + b"\x00") * 10 + b"\x09" + b"c" * 9 + b"\x00",
    43: bytes(64),
}


def _packed_example() -> DHCPMessage:
    raw = b"".join(_tlv(code, value) for code, value in _PACKED_OPTIONS.items())
    return DHCPMessage(
        DHCPOpcode.BOOTREQUEST,
        sname=_SNAME,
        file=_FILE,
        options=DHCPOptions.decode(raw + b"\xff"),
    )


def test_the_overload_example_fits_in_a_default_size_datagram() -> None:
    """The ground truth for the example below: a legal datagram holds it.

    The fields are laid out by hand (RFC 2132 section 9.3: option 52 value 3,
    the file field read first, each field ended by END), so the message is
    known to fit whatever `encode` does with it.
    """
    message = _packed_example()
    assert len(message.options.encode()) == 342
    options = {c: _tlv(c, v) for c, v in _PACKED_OPTIONS.items()}
    main = (
        options[53]
        + _tlv(52, b"\x03")
        + options[119]
        + _tlv(67, _FILE.encode())
        + b"\xff"
    )
    file_field = options[43] + options[12] + b"\xff"
    sname_field = (
        options[3] + _tlv(66, _SNAME.encode()) + options[1] + options[51] + b"\xff"
    )
    assert (
        len(main) <= _OPTIONS_FIELD
        and len(file_field) <= 128
        and len(sname_field) <= 64
    )
    header = (
        bytes([1, 1, 0, 0])
        + bytes(4 + 2 + 2 + 16 + 16)
        + sname_field.ljust(64, b"\x00")
        + file_field.ljust(128, b"\x00")
        + b"c\x82Sc"
    )
    restored = DHCPMessage.decode(header + main)
    assert restored.sname == _SNAME
    assert restored.file == _FILE
    assert {
        int(c): bytes(v) for c, v in restored.options.items(decoded=False)
    } == _PACKED_OPTIONS


@pytest.mark.xfail(
    strict=True,
    raises=OverflowError,
    reason="encode lays the options out in order and does not search for a packing "
    "that places a relocated name in the field with room for it",
)
def test_an_example_that_needs_both_fields_packed_tightly_encodes() -> None:
    message = _packed_example()
    restored = DHCPMessage.decode(message.encode())
    assert restored.sname == _SNAME
    assert restored.file == _FILE


@given(_messages())
def test_dhcp_message_round_trip(message: DHCPMessage) -> None:
    """A whole packet survives `encode()` -> `decode()` -> `encode()`.

    Nothing in this module reached the message layer, so the fixed header, the
    magic cookie, the `hlen` trim of `chaddr` and the NUL padding of
    `sname`/`file` had no property coverage at all -- only the handful of
    hand-written examples in test_message.py.
    """
    # A message that overflows the options field and carries an occupied name
    # is laid out only by a packing search `encode` does not do; the example
    # above pins that case on its own, and the count shows how often it is drawn.
    moved = _needs_a_field_moved(message)
    event(f"needs an occupied field moved: {moved}")
    assume(not moved)
    encoded = message.encode()
    restored = DHCPMessage.decode(encoded)

    # The decoded view of every header field and every option.
    assert restored.to_mapping() == message.to_mapping()
    # The raw option payloads, which `to_mapping` may render as hex.
    assert list(restored.options.items(decoded=False)) == list(
        message.options.items(decoded=False)
    )
    # And byte-for-byte idempotence: a decode that lost a field the mapping
    # does not render would still show up here.
    assert bytes(restored.encode()) == bytes(encoded)
