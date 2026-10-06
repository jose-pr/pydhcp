"""No decoder raises anything but its documented error for arbitrary octets.

PROTOCOL.md, "Wire encoding": a decode failure is a `ValueError`, never an
`IndexError`, `struct.error` or a `RecursionError`. The inputs are seeded and
small, so a failure names its input and is reproducible.
"""

from __future__ import annotations

import random
import typing as _ty

import pytest

from pydhcp.options import DHCPOptionCode

# a codec helper that no public module exports
from pydhcp.options import _codecs as t

SEEDS = [
    b"",
    b"\x00",
    b"\xc0",
    b"\xff",
    b"\x03foo\x00",
    b"\x03foo\xc0\x00",
    bytes([4, 0, 0]) + b"\x03foo\x00",
    bytes([0]) + b"\x03foo\x00",
    bytes([1, 10, 0, 0, 1]),
    bytes([24, 10, 0, 0, 10, 0, 0, 1]),
    bytes([0, 0, 0x11, 0x8B, 5, 4, 1, 2, 3, 4]),
    bytes([1, 4, 10, 0, 0, 1, 3, 5, 1, 10, 0, 0, 2]),
    bytes([0, 5]) + b"http:",
]


def _codecs() -> "list[type]":
    found: "dict[type, None]" = {}
    for code in range(1, 255):
        found[DHCPOptionCode(code).get_type()] = None
    # Opt-in codecs the registry does not bind.
    for extra in (t.UserClass, t.EncapsulatedOptions, t.DomainName):
        found[extra] = None
    return list(found)


def _inputs() -> "list[bytes]":
    rng = random.Random(20261005)
    out = list(SEEDS)
    for _ in range(300):
        out.append(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 24))))
    for seed in SEEDS:
        for _ in range(30):
            data = bytearray(seed)
            if data:
                data[rng.randrange(len(data))] = rng.randrange(256)
            out.append(bytes(data[: rng.randrange(len(data) + 1)]))
            out.append(bytes(data) + bytes(rng.randrange(256) for _ in range(3)))
    return out


INPUTS = _inputs()


@pytest.mark.parametrize("codec", _codecs(), ids=lambda codec: codec.__name__)
def test_a_decoder_raises_only_value_error(codec: _ty.Any) -> None:
    for data in INPUTS:
        try:
            codec.unpack(data)
        except ValueError:
            pass
        except Exception as error:  # noqa: BLE001
            raise AssertionError(
                f"{codec.__name__} raised {type(error).__name__} for {data.hex()}"
            ) from error
