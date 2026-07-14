from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, strategies as st

from pydhcp.network import IPv4, IPv4Network
from pydhcp.options.type import (
    U8,
    U16,
    U32,
    I32,
    Boolean,
    String,
    Bytes,
    List,
    IPv4Address,
    DomainList,
    ClasslessRoute,
)


def _round_trip(value):
    encoded = value._dhcp_encode()
    decoded = type(value)._dhcp_decode(encoded)
    reencoded = decoded._dhcp_encode()
    assert encoded == reencoded
    return decoded


@given(st.integers(min_value=0, max_value=0xFF))
def test_u8_round_trip(n: int) -> None:
    _round_trip(U8(n))


@given(st.integers(min_value=0, max_value=0xFFFF))
def test_u16_round_trip(n: int) -> None:
    _round_trip(U16(n))


@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_u32_round_trip(n: int) -> None:
    _round_trip(U32(n))


@given(st.integers(min_value=-(2**31), max_value=2**31 - 1))
def test_i32_round_trip(n: int) -> None:
    _round_trip(I32(n))


@given(st.booleans())
def test_boolean_round_trip(b: bool) -> None:
    decoded = _round_trip(Boolean(b))
    assert bool(decoded) == b


@given(st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=64))
def test_string_round_trip(s: str) -> None:
    decoded = _round_trip(String(s))
    assert str(decoded) == s


@given(st.binary(max_size=64))
def test_bytes_round_trip(b: bytes) -> None:
    decoded = _round_trip(Bytes(b))
    assert bytes(decoded) == b


@given(
    st.lists(
        st.ip_addresses(v=4).map(str),
        min_size=0,
        max_size=8,
    )
)
def test_list_ipv4address_round_trip(addrs: list[str]) -> None:
    value = List[IPv4Address](addrs)
    decoded = _round_trip(value)
    assert list(decoded) == [IPv4Address(a) for a in addrs]


_label = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=20)
_domain = st.lists(_label, min_size=1, max_size=4).map(".".join)


@given(st.lists(_domain, min_size=1, max_size=5))
def test_domain_list_round_trip(domains: list[str]) -> None:
    value = DomainList(domains)
    encoded = value._dhcp_encode()
    decoded = DomainList._dhcp_decode(encoded)
    assert list(decoded) == domains


@given(
    st.ip_addresses(v=4).map(str),
    st.integers(min_value=0, max_value=32),
)
def test_classless_route_round_trip(gateway: str, prefixlen: int) -> None:
    network = IPv4Network(f"10.0.0.0/{prefixlen}", strict=False)
    value = ClasslessRoute(IPv4(gateway), network)
    decoded = _round_trip(value)
    assert decoded.gateway == IPv4(gateway)
    assert decoded.network == network
