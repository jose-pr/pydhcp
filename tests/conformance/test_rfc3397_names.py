"""Name compression on receive: RFC 1035 s4.1.4 and RFC 3397 s3.

One reader decodes the compressed domain lists of options 119 and 141 and, with
the compression it should not have, those of options 88 and 146. Its bounds are
the ones a valid message needs (a name of at most 255 octets, RFC 1035 s2.3.4),
and an input past them is refused with the codec's ordinary `ValueError`.
"""

from __future__ import annotations

import pytest

from pydhcp.options import DHCPOptions
from pydhcp.options.code import DHCPOptionCode
from pydhcp.options.type import DomainList, RdnssSelection, UncompressedDomainList
from pydhcp.options.type.domains import MAX_POINTER_HOPS

# (codec, octets that precede the name list inside the option's payload)
CODECS = [
    pytest.param(DomainList, b"", id="DomainList"),
    pytest.param(UncompressedDomainList, b"", id="UncompressedDomainList"),
    pytest.param(RdnssSelection, bytes(9), id="RdnssSelection"),
]

#: The option codes whose codec reads a name list: 119, 141, 88, 146.
CODES = [
    (DHCPOptionCode.DOMAIN_SEARCH, b""),
    (DHCPOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS, b""),
    (DHCPOptionCode.BCMCS_DOMAIN_NAME_LIST, b""),
    (DHCPOptionCode.RDNSS_SELECTION, bytes(9)),
]


def _label(text: str) -> bytes:
    return bytes([len(text)]) + text.encode()


def _names(decoded):
    return decoded.domains if isinstance(decoded, RdnssSelection) else decoded


def _chain(names: int, label_octets: int = 63) -> bytes:
    """`names` names, each one label then a pointer to the start of the last.

    Resolving name k yields k+1 labels, so the names grow with every
    resolution: the shape that costs a reader with no bound its time.
    """
    out = bytearray(_label("a" * label_octets) + b"\x00")
    previous = 0
    for _ in range(names - 1):
        start = len(out)
        out += _label("a" * label_octets) + (0xC000 | previous).to_bytes(2, "big")
        previous = start
    return bytes(out)


def _pointer_chain(names: int) -> bytes:
    """A root name, then `names` names that are one pointer to the one before."""
    out = bytearray(b"\x00")
    previous = 0
    for _ in range(names):
        start = len(out)
        out += (0xC000 | previous).to_bytes(2, "big")
        previous = start
    return bytes(out)


def _wire(code: int, payload: bytes) -> bytes:
    """The code's option instances as RFC 3396 splits them, then END."""
    out = bytearray()
    for index in range(0, len(payload), 255):
        piece = payload[index : index + 255]
        out += bytes([code, len(piece)]) + piece
    return bytes(out) + b"\xff"


# --- what a valid message needs ---------------------------------------------


def test_the_rfc_3397_example_is_decoded_from_its_three_instances() -> None:
    """RFC 3397 s3: "eng.apple.com." and "marketing.apple.com.", split in three.

    The second name ends in the pointer C0 04, which refers to offset 4 of the
    aggregated block, where "apple.com." begins.
    """
    wire = (
        b"\x77\x09\x03eng\x05appl"
        b"\x77\x09e\x03com\x00\x09ma"
        b"\x77\x09rketing\xc0\x04"
        b"\xff"
    )
    options = DHCPOptions()
    options.decode(memoryview(bytearray(wire)))
    assert list(options.get(119)) == ["eng.apple.com", "marketing.apple.com"]


@pytest.mark.parametrize("codec,prefix", CODECS)
def test_a_pointer_to_an_earlier_name_resolves(codec, prefix) -> None:
    payload = b"\x07example\x03com\x00\x03sub\xc0\x00"
    decoded = codec._dhcp_decode(bytearray(prefix + payload))
    assert list(_names(decoded)) == ["example.com", "sub.example.com"]


def test_a_long_valid_search_list_spans_several_option_instances() -> None:
    """RFC 3396: more than 255 octets of list arrive as several instances."""
    domains = [f"host{n}.dept{n % 7}.example.com" for n in range(40)]
    payload = bytes(DomainList(domains)._dhcp_encode())
    assert len(payload) > 255
    wire = _wire(119, payload)
    options = DHCPOptions()
    options.decode(memoryview(bytearray(wire)))
    assert list(options.get(119)) == domains


def test_the_longest_legal_name_is_accepted() -> None:
    """255 octets with the root label: three 63-octet labels and one of 61."""
    name = ".".join(["a" * 63] * 3 + ["b" * 61])
    payload = _label("a" * 63) * 3 + _label("b" * 61) + b"\x00"
    assert len(payload) == 255
    assert list(DomainList._dhcp_decode(bytearray(payload))) == [name]


# --- the bounds ---------------------------------------------------------------


@pytest.mark.parametrize("codec,prefix", CODECS)
def test_a_name_over_255_octets_is_refused(codec, prefix) -> None:
    # Five 63-octet labels reached through pointers: 5 * 64 + 1 = 321 octets.
    payload = _chain(5)
    with pytest.raises(ValueError, match="255 octets"):
        codec._dhcp_decode(bytearray(prefix + payload))


@pytest.mark.parametrize("code,prefix", CODES)
def test_every_option_that_reads_a_name_list_refuses_it(code, prefix) -> None:
    options = DHCPOptions()
    options.decode(memoryview(bytearray(_wire(int(code), prefix + _chain(6)))))
    with pytest.raises(ValueError, match="255 octets"):
        options.get(int(code))


def test_chained_names_are_refused_where_they_would_outgrow_the_limit() -> None:
    """A few hundred octets of chained pointers must be refused, not expanded.

    300 names that each extend the one before would decode into 300 names of up
    to 19,000 characters; the refusal comes at the fifth.
    """
    with pytest.raises(ValueError, match="255 octets"):
        DomainList._dhcp_decode(bytearray(_chain(300)))


def test_a_name_may_follow_as_many_pointers_as_the_limit_allows() -> None:
    names = _pointer_chain(MAX_POINTER_HOPS)
    decoded = DomainList._dhcp_decode(bytearray(names))
    assert list(decoded) == [""] * (MAX_POINTER_HOPS + 1)


def test_a_name_that_follows_more_pointers_than_a_name_can_need_is_refused() -> None:
    with pytest.raises(ValueError, match="more than 127 compression pointers"):
        DomainList._dhcp_decode(bytearray(_pointer_chain(MAX_POINTER_HOPS + 1)))


@pytest.mark.parametrize(
    "payload",
    [
        b"\x01a\xc0\x00",  # a pointer to the start of its own name
        b"\xc0\x02\xc0\x00",  # a pointer forward
        b"\x01a\x00\x01b\xc0\x03",  # a pointer to the start of its own name
        b"\x01a\x00\x01b\xc0\x50",  # a pointer past the end
        b"\x01a\x00\x01b\xc0\x04",  # a pointer into the middle of a label
        b"\x01a\xc0\x02\xc0\x02",  # a pointer to itself
    ],
)
@pytest.mark.parametrize("codec,prefix", CODECS)
def test_a_pointer_that_does_not_point_backwards_to_a_component_is_refused(
    codec, prefix, payload
) -> None:
    with pytest.raises(ValueError):
        codec._dhcp_decode(bytearray(prefix + payload))


# --- a name that runs off the end ----------------------------------------------


@pytest.mark.parametrize(
    "payload,kept",
    [
        (b"\x03foo", []),
        (b"\x03foo\x00\x03bar", ["foo"]),
        (b"\x03foo\x00\xc0", ["foo"]),
        (b"\xc0", []),
        (b"\x03foo\x00\x03bar\xc0", ["foo"]),
    ],
)
@pytest.mark.parametrize("codec", [DomainList, UncompressedDomainList])
def test_the_partial_last_name_is_discarded(codec, payload, kept) -> None:
    """RFC 3397 s3: a name unfinished at the end of the block MUST be discarded."""
    assert list(codec._dhcp_decode(bytearray(payload))) == kept


@pytest.mark.parametrize("codec", [DomainList, UncompressedDomainList])
def test_a_label_that_declares_more_than_remains_is_refused(codec) -> None:
    with pytest.raises(ValueError, match="truncated"):
        codec._dhcp_decode(bytearray(b"\x03foo\x00\x05ba"))
