"""Every structured codec against the octets its RFC fixes, both ways.

The vectors are in `rfc_vectors.py`, written from the RFC texts and never from
what a codec emits: the printed octets decode to the stated value, and the
stated value encodes to the printed octets. A vector that a codec does not yet
meet carries a `pending` reason and is expected to fail until the codec is
fixed; the strict marker turns a fix into a failure that says to delete it.
"""

from __future__ import annotations

import typing as _ty

import pytest
from rfc_vectors import VECTORS, Vector

from pydhcp.options import DHCPOptionCode, DHCPOptions

# the label function that names a generated list class for a message
from value_samples import label


def _params(direction: str) -> list[_ty.Any]:
    found = []
    for vector in VECTORS:
        if direction == "encode" and vector.direction == "decode":
            continue
        marks = []
        if direction in vector.pending:
            marks.append(
                pytest.mark.xfail(strict=True, reason=vector.pending[direction])
            )
        found.append(pytest.param(vector, id=vector.name, marks=marks))
    return found


@pytest.mark.parametrize("vector", _params("decode"))
def test_the_printed_octets_decode_to_the_stated_value(vector: Vector) -> None:
    decoded = vector.codec.unpack(bytearray(vector.octets))
    assert decoded == vector.codec(*vector.args)
    assert type(decoded) is vector.codec


@pytest.mark.parametrize("vector", _params("encode"))
def test_the_stated_value_encodes_to_the_printed_octets(vector: Vector) -> None:
    assert bytes(vector.codec(*vector.args).pack()) == vector.octets


@pytest.mark.parametrize(
    "vector",
    [
        pytest.param(vector, id=vector.name)
        for vector in VECTORS
        if vector.code is not None
        and "decode" not in vector.pending
        and len(vector.octets) < 255
    ],
)
def test_the_registered_codec_of_the_option_reads_the_octets(vector: Vector) -> None:
    """The registry binds the option code to the codec the vector is for."""
    wire = bytes([vector.code, len(vector.octets)]) + vector.octets + b"\xff"
    options = DHCPOptions.decode(wire)
    assert label(type(options.get(vector.code))) == label(vector.codec)
    assert options.get(vector.code) == vector.codec(*vector.args)


def test_every_structured_codec_the_registry_binds_has_a_vector() -> None:
    """Opaque bytes are the one codec without a layout to put a vector to."""
    bound = {
        label(DHCPOptionCode(code).get_type())
        for code in range(1, 255)
        if DHCPOptionCode(code).get_type().__name__ != "Bytes"
    }
    covered = {label(vector.codec) for vector in VECTORS}
    assert bound - covered == set()
