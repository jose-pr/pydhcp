"""Domain-name lists: which options compress, and what a bare `str` means.

Two separate defects, both about `DomainList`:

* it is the *compressed* codec (RFC 3397), and it was registered for two
  options whose own RFCs forbid compression;
* being a bare `list[str]` subclass with no `__init__`, it read a `str`
  argument as an iterable of characters.
"""

from __future__ import annotations

import pytest

from pydhcp.options import DhcpOptions
from pydhcp.options.code import DhcpOptionCode
from pydhcp.options.type import DomainList, RdnssSelection, UncompressedDomainList

#: A list whose second name is a suffix-match for the first, so a compressing
#: encoder has something to point at and the difference is visible in bytes.
SHARED_SUFFIX = ["a.example.com", "b.example.com"]

#: What `SHARED_SUFFIX` encodes to with and without RFC 1035 compression. The
#: `c0 02` tail of the compressed form is the pointer at issue.
COMPRESSED = b"\x01a\x07example\x03com\x00\x01b\xc0\x02"
UNCOMPRESSED = b"\x01a\x07example\x03com\x00\x01b\x07example\x03com\x00"


def _has_pointer(payload: bytes) -> bool:
    """Is there a length octet with the RFC 1035 §4.1.4 pointer bits set?

    Walks the label structure rather than scanning for a byte value, so a
    `0xC0` octet *inside* a label is not mistaken for a pointer.
    """
    idx = 0
    while idx < len(payload):
        length = payload[idx]
        if length & 0xC0:
            return True
        idx += 1 + length
    return False


# --- which options may compress -------------------------------------------


def test_bcmcs_domain_names_are_written_uncompressed() -> None:
    """Option 88 forbids compression; pydhcp emitted a pointer anyway.

    RFC 4280 §4.6: "The domain names MUST be concatenated and encoded using
    the technique described in Section 3.3 of [RFC1035]. DNS name compression
    MUST NOT be used." Measured before the fix, option 88 encoded
    `SHARED_SUFFIX` as `COMPRESSED` -- the second name ending in a pointer a
    conforming receiver has no obligation to resolve.
    """
    options = DhcpOptions()
    options[DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST] = SHARED_SUFFIX

    payload = bytes(options.get(88, decode=False))
    assert not _has_pointer(payload), f"option 88 still compresses: {payload!r}"
    assert payload == UNCOMPRESSED
    assert list(options.get(88)) == SHARED_SUFFIX


def test_rdnss_selection_domains_are_written_uncompressed() -> None:
    """Option 146 forbids compression by reference; same pointer was emitted.

    RFC 6731 §4.3 encodes the field as RFC 3315 §8, which says a list of
    domain names in DHCP "MUST NOT be stored in compressed form, as described
    in section 4.1.4 of RFC 1035".
    """
    options = DhcpOptions()
    options[DhcpOptionCode.RDNSS_SELECTION] = RdnssSelection(
        0, "10.0.0.1", "10.0.0.2", SHARED_SUFFIX
    )

    payload = bytes(options.get(146, decode=False))
    assert payload[:9] == b"\x00" + b"\x0a\x00\x00\x01" + b"\x0a\x00\x00\x02"
    assert not _has_pointer(payload[9:]), f"option 146 still compresses: {payload!r}"
    assert payload[9:] == UNCOMPRESSED

    decoded = options.get(146)
    assert isinstance(decoded, RdnssSelection)
    assert list(decoded.domains) == SHARED_SUFFIX


def test_the_search_list_still_compresses() -> None:
    """RFC 3397 (option 119) and RFC 6011 (option 141) *require* compression.

    RFC 6011 §4.1: "To enable the searchlist to be encoded compactly,
    searchstrings in the searchlist MUST be concatenated and encoded using
    the technique described in Section 4.1.4 of [RFC1035]". So the split is
    per option, not a blanket ban, and this is the half that must not move.
    """
    for code in (
        DhcpOptionCode.DOMAIN_SEARCH,
        DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS,
    ):
        options = DhcpOptions()
        options[code] = SHARED_SUFFIX
        payload = bytes(options.get(int(code), decode=False))
        assert payload == COMPRESSED, f"option {int(code)} stopped compressing"


def test_a_compressed_payload_is_still_accepted_on_receive() -> None:
    """Strict on send, liberal on receive -- the package's stated stance.

    A peer that ignores its own RFC still sends a payload that resolves
    unambiguously inside the option, and refusing it would turn a readable
    packet into a decode failure.
    """
    options = DhcpOptions()
    options.decode(
        memoryview(bytearray(b"\x58" + bytes([len(COMPRESSED)]) + COMPRESSED))
    )
    assert list(options.get(88)) == SHARED_SUFFIX


def test_an_uncompressed_list_round_trips_the_root_name() -> None:
    """An empty entry is the root name: one zero octet, as for `DomainList`."""
    payload = bytes(UncompressedDomainList([""])._dhcp_encode())
    assert payload == b"\x00"
    decoded, _read = UncompressedDomainList._dhcp_read(memoryview(payload))
    assert list(decoded) == [""]


def test_an_uncompressed_list_obeys_the_shared_name_limits() -> None:
    """It routes through `type/domain.py`, so the 63/255 limits apply."""
    with pytest.raises(ValueError, match="63 octets"):
        UncompressedDomainList(["a" * 64 + ".example.com"])._dhcp_encode()
    with pytest.raises(ValueError, match="255 octets"):
        UncompressedDomainList([".".join(["label"] * 50)])._dhcp_encode()


# --- a bare string is one name --------------------------------------------


def test_a_bare_string_is_one_domain_not_one_per_character() -> None:
    """`DomainList("corp")` was `["c", "o", "r", "p"]`.

    With no `__init__` this inherited `list`'s, where a `str` is an iterable
    of characters. Measured: `options[119] = "corp"` stored four
    single-letter search domains and encoded all four, silently. Every other
    container in the package normalizes -- `List[IPv4Address]` has
    `_normalize` -- and this one is now the same shape: a list or tuple
    argument is several entries, anything else is one.
    """
    assert list(DomainList("corp")) == ["corp"]
    assert list(DomainList("example.com")) == ["example.com"]
    assert list(DomainList(SHARED_SUFFIX)) == SHARED_SUFFIX
    assert list(DomainList(tuple(SHARED_SUFFIX))) == SHARED_SUFFIX
    assert list(DomainList()) == []


def test_assigning_a_bare_string_to_the_search_list() -> None:
    """The container path, which is how a caller actually meets this.

    `options[119] = "example.com"` used to raise -- but about *empty labels*,
    because the per-character split produced a "." entry, so the message
    pointed at the name rather than at the argument. It now stores one
    domain.
    """
    options = DhcpOptions()
    options[DhcpOptionCode.DOMAIN_SEARCH] = "example.com"
    assert list(options.get(119)) == ["example.com"]
    assert bytes(options.get(119, decode=False)) == b"\x07example\x03com\x00"


def test_rdnss_selection_normalizes_a_bare_string_too() -> None:
    """`RdnssSelection(..., "a.com").domains` was `["a", ".", "c", "o", "m"]`.

    Which is not merely wrong, it is unencodable: "." is an empty label.
    """
    assert list(RdnssSelection(0, "10.0.0.1", "10.0.0.2", "a.com").domains) == ["a.com"]


def test_entries_must_be_strings() -> None:
    """Normalization is a type check, not a coercion: `str(3)` is not a name."""
    with pytest.raises(TypeError, match="domain-list entries must be str"):
        DomainList([1, 2])
    names = DomainList(SHARED_SUFFIX)
    with pytest.raises(TypeError, match="domain-list entries must be str"):
        names.append(3)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="domain-list entries must be str"):
        names[0] = None  # type: ignore[call-overload]
    with pytest.raises(TypeError, match="domain-list entries must be str"):
        names.extend([b"a.example.com"])  # type: ignore[list-item]
    assert list(names) == SHARED_SUFFIX
