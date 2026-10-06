"""Arbitrary octets reach a decoder: it returns a value or raises `DHCPDecodeError`.

PROTOCOL.md, "Wire encoding": a decode failure raises the package's decode
error, never a bare `ValueError`, `IndexError`, `struct.error` or
`RecursionError`. The seeded walk in `test_decoders_fuzz.py` accepts any
`ValueError`; this property is the stricter statement and draws its octets from
Hypothesis, so a shrunk failure names the smallest input.
"""

from __future__ import annotations

import typing as _ty

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from pydhcp import DHCPMessage
from pydhcp.exceptions import DHCPDecodeError
from pydhcp.options import DHCPOptionCode, DHCPOptions

# a codec helper that no public module exports
from pydhcp.options import _codecs as t

#: The registered codecs, and the opt-in ones no code is bound to.
CODECS: list[_ty.Any] = []
for _code in range(1, 255):
    _codec = DHCPOptionCode(_code).get_type()
    if _codec not in CODECS:
        CODECS.append(_codec)
for _extra in (t.UserClass, t.EncapsulatedOptions, t.DomainName):
    if _extra not in CODECS:
        CODECS.append(_extra)

#: No deadline: a timing assertion on a shared runner says nothing about a codec.
PROPERTY = settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@pytest.mark.parametrize("codec", CODECS, ids=lambda codec: codec.__name__)
@PROPERTY
@given(st.binary(max_size=96))
def test_a_codec_returns_a_value_or_raises_the_decode_error(
    codec: _ty.Any, data: bytes
) -> None:
    try:
        value = codec.unpack(bytearray(data))
    except DHCPDecodeError:
        return
    assert type(value) is codec


@PROPERTY
@given(st.binary(max_size=300))
def test_an_options_field_returns_or_raises_the_decode_error(data: bytes) -> None:
    try:
        options = DHCPOptions.decode(data)
    except DHCPDecodeError:
        return
    for code in options:
        try:
            options.get(code)
        except DHCPDecodeError:
            pass


@PROPERTY
@given(st.binary(max_size=40), st.binary(max_size=200))
def test_a_message_returns_or_raises_the_decode_error(head: bytes, tail: bytes) -> None:
    # A header whose fixed fields are drawn, then a cookie and options: the
    # random prefix alone is refused as too short, which proves nothing.
    header = bytes([1, 1, 6, 0]) + bytes(4 + 4 + 16) + head.ljust(40, b"\x00")[:40]
    data = header + bytes(236 - len(header)) + b"\x63\x82\x53\x63" + tail
    try:
        DHCPMessage.decode(data)
    except DHCPDecodeError:
        pass
