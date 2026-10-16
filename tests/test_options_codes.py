"""Which option codes a bag will store, and what an option code is worth.

`DHCPOptions` keys on a raw `int`, and used to store any of them. Codes 0
(PAD) and 255 (END) are wire framing rather than options, and a code outside
0-255 has no wire form at all -- all three were accepted and only noticed, if
ever, by whatever read the resulting packet.
"""

from __future__ import annotations

import pytest

from pydhcp.options import DHCPOptions, MAX_OPTION_CODE, MIN_OPTION_CODE
from pydhcp.options import BaseDHCPOptionCode
from pydhcp.options import Bytes, DHCPOptionCode


def test_pad_and_end_are_not_storable_options() -> None:
    """Storing under 0 or 255 emitted framing bytes as if they were options.

    Measured before the check: `options[0] = b"\\x01\\x02"` and
    `options[255] = b"\\x01\\x02"` encoded to `00 02 01 02 ff 02 01 02 ff`.
    A receiver reads the leading `00` as a single pad octet and then `02` as
    an option code, and stops dead at the `ff` -- so the first option's
    payload is reinterpreted as options and everything after the second one
    disappears. Neither is a wire form anyone wants by accident.
    """
    options = DHCPOptions()
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
    options = DHCPOptions()
    for bad in (300, 256, -1):
        with pytest.raises(ValueError, match="option code must be in range"):
            options[bad] = b"\x01\x02"
    assert len(options) == 0


def test_the_storable_range_is_the_one_the_constants_name() -> None:
    options = DHCPOptions()
    options[MIN_OPTION_CODE] = b"\xff\xff\xff\x00"
    options[MAX_OPTION_CODE] = b"\x01"
    assert sorted(options) == [MIN_OPTION_CODE, MAX_OPTION_CODE]
    assert (MIN_OPTION_CODE, MAX_OPTION_CODE) == (1, 254)


def test_a_non_int_code_is_refused_by_type() -> None:
    options = DHCPOptions()
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
    options = DHCPOptions()
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
    options = DHCPOptions.decode(memoryview(bytearray(b"\x00\x00\x35\x01\x05\x00\xff")))
    assert bytes(options[53]) == b"\x05"
    assert 0 not in options and 255 not in options


def test_a_code_class_with_no_value_is_not_silently_pad() -> None:
    """`int()` on a value-less code used to answer 0, which is PAD.

    `BaseDHCPOptionCode` is the documented base for an application's own code
    enum. A subclass that forgot to be one -- no `value`, not an `int` --
    still answered `int(code) == 0`, so `normalize`/`replace`/`append` routed
    it to option 0 and it encoded as padding. Zero is a real code, so there
    was nothing to notice.
    """

    class Nameless(BaseDHCPOptionCode):
        pass

    with pytest.raises(TypeError, match="has no option-code value"):
        int(Nameless())

    # `repr` is diagnostics and must not raise while you debug this.
    assert repr(Nameless()) == "[000]UNKNOWN"


def test_a_code_class_that_is_an_int_still_converts() -> None:
    """Carrying the code as `int` identity is the other legal shape."""

    class IntCode(BaseDHCPOptionCode, int):
        pass

    assert int(IntCode(53)) == 53
    # private: the code map as stored
    assert DHCPOptions()._codemap is DHCPOptionCode


# --- a code enum of one's own: its own unnamed members and codecs ----------------


def _site_codes() -> type:
    from pydhcp.options import OptionCodeEnum

    class SiteCodes(OptionCodeEnum):
        SITE_NAME = 224

    return SiteCodes


@pytest.mark.parametrize("first", ["pydhcp", "site"])
def test_an_unnamed_code_is_each_enums_own_whichever_was_made_first(first: str) -> None:
    site = _site_codes()
    makers = [lambda: DHCPOptionCode(249), lambda: site(249)]
    for make in makers if first == "pydhcp" else reversed(makers):
        make()
    assert type(DHCPOptionCode(249)) is DHCPOptionCode
    assert type(site(249)) is site
    assert site(249) is site(249) and site(249).label() == "UNKNOWN"
    assert site(249).name is None and int(site(249)) == 249


def test_a_registration_on_one_enum_leaves_the_other_alone() -> None:
    from pydhcp.options import String

    site = _site_codes()
    before = DHCPOptionCode(224).get_type()
    site.SITE_NAME.register_type(String)
    site(230).register_type(String)
    assert site.SITE_NAME.get_type() is String and site(230).get_type() is String
    assert DHCPOptionCode(224).get_type() is before
    assert DHCPOptionCode(230).get_type() is Bytes
    assert site(6).get_type() is Bytes  # nothing of DHCPOptionCode's comes along


def test_an_own_enum_works_as_a_codemap() -> None:
    from pydhcp.options import String

    site = _site_codes()
    site.SITE_NAME.register_type(String)
    options = DHCPOptions(codemap=site)
    options[224] = "lab"
    options[250] = b"\x01"
    assert options.get(224) == "lab"
    assert options.to_mapping() == {"SITE_NAME": "lab", "250": "01"}


def test_an_unnamed_member_pickles_to_the_same_member() -> None:
    import pickle

    assert pickle.loads(pickle.dumps(DHCPOptionCode(250))) is DHCPOptionCode(250)


# --- one reading of an option's name ------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "BOOTFILE_NAME",
        "bootfile_name",
        "bootfile-name",
        "Bootfile-Name",
        " bootfile_name ",
        "67",
        67,
        "option-67",
        "OPTION_67",
        "option67",
        "option 67",
    ],
)
def test_every_spelling_of_an_option_resolves_to_its_member(name: object) -> None:
    assert DHCPOptionCode.resolve(name) is DHCPOptionCode.BOOTFILE_NAME  # type: ignore[arg-type]


def test_an_alias_resolves_to_its_code_and_an_unnamed_number_to_a_member() -> None:
    assert DHCPOptionCode.resolve("grd") is DHCPOptionCode.SIXRD
    assert DHCPOptionCode.resolve("option-250") is DHCPOptionCode(250)


@pytest.mark.parametrize(
    "name, error",
    [("nope", ValueError), ("", ValueError), (True, TypeError), (1.5, TypeError)],
)
def test_a_name_that_names_nothing_is_refused(name: object, error: type) -> None:
    with pytest.raises(error):
        DHCPOptionCode.resolve(name)  # type: ignore[arg-type]


def test_update_from_mapping_and_the_capture_filter_read_names_alike() -> None:
    # private: the capture filter's key reader, called directly
    from pydhcp.capture._filter import option_selector

    options = DHCPOptions.from_mapping({"bootfile-name": "a.efi", "option-66": "tftp"})
    assert sorted(options) == [66, 67]
    options.update(Bootfile_Name="b.efi")
    assert options.get(67) == "b.efi"
    with pytest.raises(TypeError, match="unknown option"):
        options.update(no_such_option=1)
    assert (
        option_selector("option.bootfile-name", "x")[0] is DHCPOptionCode.BOOTFILE_NAME
    )
    with pytest.raises(ValueError, match="1 to 254"):
        option_selector("option.option-0", "x")
