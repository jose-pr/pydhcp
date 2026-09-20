"""Which option codes a bag will store, and what an option code is worth.

`DhcpOptions` keys on a raw `int`, and used to store any of them. Codes 0
(PAD) and 255 (END) are wire framing rather than options, and a code outside
0-255 has no wire form at all -- all three were accepted and only noticed, if
ever, by whatever read the resulting packet.
"""

from __future__ import annotations

import pytest

from pydhcp.options import DhcpOptions, MAX_OPTION_CODE, MIN_OPTION_CODE
from pydhcp.options.base import BaseDhcpOptionCode
from pydhcp.options.code import DhcpOptionCode


def test_pad_and_end_are_not_storable_options() -> None:
    """Storing under 0 or 255 emitted framing bytes as if they were options.

    Measured before the check: `options[0] = b"\\x01\\x02"` and
    `options[255] = b"\\x01\\x02"` encoded to `00 02 01 02 ff 02 01 02 ff`.
    A receiver reads the leading `00` as a single pad octet and then `02` as
    an option code, and stops dead at the `ff` -- so the first option's
    payload is reinterpreted as options and everything after the second one
    disappears. Neither is a wire form anyone wants by accident.
    """
    options = DhcpOptions()
    with pytest.raises(ValueError, match="PAD"):
        options[0] = b"\x01\x02"
    with pytest.raises(ValueError, match="END"):
        options[255] = b"\x01\x02"
    assert len(options) == 0
    assert bytes(options.encode()) == b"\xff"


def test_a_code_outside_a_byte_is_refused_where_it_is_set() -> None:
    """`options[300]` used to be stored and to fail only at `encode()`.

    And the failure named neither the option nor the code: `ValueError: byte
    must be in range(0, 256)`, raised from `bytearray.append` several frames
    away from the assignment that caused it, on a bag that may have been
    handed around since.
    """
    options = DhcpOptions()
    for bad in (300, 256, -1):
        with pytest.raises(ValueError, match="option code must be in range"):
            options[bad] = b"\x01\x02"
    assert len(options) == 0


def test_the_storable_range_is_the_one_the_constants_name() -> None:
    options = DhcpOptions()
    options[MIN_OPTION_CODE] = b"\xff\xff\xff\x00"
    options[MAX_OPTION_CODE] = b"\x01"
    assert sorted(options) == [MIN_OPTION_CODE, MAX_OPTION_CODE]
    assert (MIN_OPTION_CODE, MAX_OPTION_CODE) == (1, 254)


def test_a_non_int_code_is_refused_by_type() -> None:
    options = DhcpOptions()
    with pytest.raises(TypeError, match="option code must be an int"):
        options["53"] = b"\x05"  # type: ignore[index]
    # `True == 1` would have silently addressed SUBNET_MASK.
    with pytest.raises(TypeError, match="option code must be an int"):
        options[True] = b"\xff\xff\xff\x00"  # type: ignore[index]


def test_append_checks_the_code_too() -> None:
    """`append` writes through `setdefault`, not `__setitem__`.

    So it needs its own check, or the one path that concatenates onto an
    existing option is the one that can still create option 0.
    """
    options = DhcpOptions()
    with pytest.raises(ValueError, match="PAD"):
        options.append((0, b"\x01"))
    with pytest.raises(ValueError, match="END"):
        options.append((255, b"\x01"))
    assert len(options) == 0


def test_decode_still_accepts_what_arrives() -> None:
    """The check is on the store, not on the receive path.

    `decode()` handles 0 and 255 as framing and stays liberal about
    everything else -- a packet is not rejected for what a sender did.
    """
    options = DhcpOptions()
    options.decode(memoryview(bytearray(b"\x00\x00\x35\x01\x05\x00\xff")))
    assert bytes(options[53]) == b"\x05"
    assert 0 not in options and 255 not in options


def test_a_code_class_with_no_value_is_not_silently_pad() -> None:
    """`int()` on a value-less code used to answer 0, which is PAD.

    `BaseDhcpOptionCode` is the documented base for an application's own code
    enum. A subclass that forgot to be one -- no `value`, not an `int` --
    still answered `int(code) == 0`, so `normalize`/`replace`/`append` routed
    it to option 0 and it encoded as padding. Zero is a real code, so there
    was nothing to notice.
    """

    class Nameless(BaseDhcpOptionCode):
        pass

    with pytest.raises(TypeError, match="has no option-code value"):
        int(Nameless())

    # `repr` is diagnostics and must not raise while you debug this.
    assert repr(Nameless()) == "[000]UNKNOWN"


def test_a_code_class_that_is_an_int_still_converts() -> None:
    """Carrying the code as `int` identity is the other legal shape."""

    class IntCode(BaseDhcpOptionCode, int):
        pass

    assert int(IntCode(53)) == 53
    assert DhcpOptions()._codemap is DhcpOptionCode
