"""Domain names are measured and delimited in octets (`options-codecs-8`, `-16`).

Found by auditing `options-codecs-8`, whose recorded text covers the *limits*
(63-octet labels, 255-octet names) that were already enforced. The desync
underneath them was not: `split_domain_name` validates in octets while the
encoder wrote character counts, so the two disagreed for every non-ASCII name.
"""

import pytest

from pydhcp.options.type.domain import decode_domain_name
from pydhcp.options.type.net import DomainList

# "bücher" is 6 characters and 7 octets -- the smallest case that separates
# len(str) from len(str.encode()).
UMLAUT = "bücher.example"


@pytest.mark.parametrize(
    "names",
    [
        [UMLAUT],
        ["éé.x.com", "y.x.com"],
        ["example.com"],
        # A shared suffix, so the compression path is exercised too: its
        # pointer offsets were computed in characters by the same bug.
        ["a.example.com", "b.example.com"],
        ["ü.é.com", "x.é.com"],
    ],
)
def test_domain_lists_round_trip_exactly(names) -> None:
    raw = bytes(DomainList(names)._dhcp_encode())
    decoded, _read = DomainList._dhcp_read(memoryview(raw))
    assert list(decoded) == names


def test_the_length_octet_counts_octets_not_characters() -> None:
    """RFC 1035 §3.1. The measured symptom: 6 declared for a 7-octet label.

    The corrupt bytes then either raised a bare `ValueError` on the way back in
    or -- worse -- decoded as different labels entirely: `['éé.x.com',
    'y.x.com']` came back as three names, one of them a replacement character.
    """
    raw = bytes(DomainList([UMLAUT])._dhcp_encode())
    first_label = UMLAUT.split(".")[0]
    assert raw[0] == len(first_label.encode("utf-8")) == 7
    assert raw[0] != len(first_label)


@pytest.mark.parametrize(
    "payload",
    [
        b"\x03a.b\x01c\x00",
        b"\x05x.y.z\x00",
    ],
)
def test_a_label_containing_a_dot_is_refused_not_silently_resplit(payload) -> None:
    """`options-codecs-16`, whose recommended fix was already disproved.

    The finding said the shared name helper (`options-codecs-18`) would fix
    this everywhere. The helper shipped and did not: a dot is legal inside a
    label on the wire, where the length octet is the only delimiter, but these
    names are joined with "." into a string -- so `b"\\x03a.b\\x01c\\x00"`
    decoded to "a.b.c" and re-encoded as three labels, a different name than
    arrived. Refusing says so; accepting silently rewrote it.
    """
    with pytest.raises(ValueError, match=r"label containing"):
        DomainList._dhcp_read(memoryview(payload))
    with pytest.raises(ValueError, match=r"label containing"):
        decode_domain_name(memoryview(payload))


def test_a_truncated_label_says_so() -> None:
    """The bare `raise ValueError()` this path used to carry printed nothing."""
    with pytest.raises(ValueError, match=r"truncated"):
        DomainList._dhcp_read(memoryview(b"\x09short"))
