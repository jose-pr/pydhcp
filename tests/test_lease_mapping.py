"""`DHCPLease` and `DHCPOptions` as plain data and documents, and back.

A lease written out loads back as an equal lease in every format, a field left
out takes its default, and what the constructor refuses is refused here too.
"""

from __future__ import annotations

import datetime as dt
import enum

import pytest

from pydhcp import DHCPLease, DHCPOptions, DHCPValueError
from pydhcp.options import BaseDHCPOptionCode, String

# private: the unit under test is not exported from a public module
from pydhcp.options._frozen import FrozenDHCPOptions

UTC = dt.timezone.utc
LATER = dt.datetime(2100, 1, 1, 12, 0, 30, 250, tzinfo=UTC)
FORMATS = ("json", "yaml", "toml", "ini")


def _options() -> DHCPOptions:
    options = DHCPOptions()
    options.update(router="10.0.0.1", hostname="pc1", dns=["9.9.9.9"])
    options[230] = b"\x00\xff"  # unnamed: kept by number, as octets
    options[12] = b"host\xff"  # text that is not UTF-8: kept as octets
    return options


def _lease(**changes: object) -> DHCPLease:
    lease = DHCPLease("10.0.0.5", LATER, _options())
    return lease.replace(**changes) if changes else lease  # type: ignore[arg-type]


# --- the options ---------------------------------------------------------------


def test_options_map_names_to_readable_values_and_load_back_byte_exact() -> None:
    options = _options()
    mapping = options.to_mapping()
    assert mapping["ROUTER"] == ["10.0.0.1"]
    assert mapping["230"] == "00ff"  # opaque: its readable form is hex text
    assert mapping["HOSTNAME"] == {"hex": "686f7374ff"}
    loaded = DHCPOptions.from_mapping(mapping)
    assert loaded == options and list(loaded) == list(options)


def test_options_from_none_or_nothing_is_an_empty_bag() -> None:
    assert len(DHCPOptions.from_mapping(None)) == 0
    assert len(DHCPOptions.from_mapping({})) == 0


def test_options_from_something_not_a_mapping_is_a_type_error() -> None:
    with pytest.raises(TypeError, match="mapping"):
        DHCPOptions.from_mapping(["ROUTER"])  # type: ignore[arg-type]


def test_a_read_only_bag_loads_read_only() -> None:
    frozen = FrozenDHCPOptions.from_mapping({"ROUTER": "10.0.0.1"})
    assert isinstance(frozen, FrozenDHCPOptions)
    assert bytes(frozen[3]) == bytes([10, 0, 0, 1])


class _Site(BaseDHCPOptionCode, enum.IntEnum):
    SITE_NAME = 224

    def get_type(self) -> type:
        return String

    def label(self) -> str:
        return str(self.name)


def test_options_are_named_and_read_with_their_codemap() -> None:
    options = DHCPOptions(codemap=_Site)
    options[224] = "lab"
    assert options.to_mapping() == {"SITE_NAME": "lab"}
    assert DHCPOptions.from_mapping({"SITE_NAME": "lab"}, codemap=_Site) == options


# --- the lease -------------------------------------------------------------------


def test_a_lease_maps_to_plain_data() -> None:
    mapping = _lease().to_mapping()
    assert mapping["ip"] == "10.0.0.5"
    assert mapping["expires"] == "2100-01-01T12:00:30.000250+00:00"
    assert mapping["offered"] is False
    assert mapping["options"] == _options().to_mapping()


@pytest.mark.parametrize(
    "lease",
    [
        _lease(),
        _lease(offered=True),
        _lease(expires=None),
        DHCPLease("10.0.0.5"),
    ],
    ids=["bound", "offered", "never-ends", "bare"],
)
def test_a_lease_round_trips_through_a_mapping(lease: DHCPLease) -> None:
    assert DHCPLease.from_mapping(lease.to_mapping()) == lease


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_lease_round_trips_through_every_format(fmt: str) -> None:
    if fmt != "json":
        pytest.importorskip("pktcap")
        if fmt in ("yaml", "toml"):
            pytest.importorskip("yaml" if fmt == "yaml" else "tomli_w")
    # TOML writes a table after the plain values, so the octets go last there.
    plain = DHCPOptions()
    plain.update(router="10.0.0.1", dns=["9.9.9.9"], hostname=b"host\xff")
    for lease in (
        _lease(options=plain),
        _lease(options=plain, expires=None, offered=True),
    ):
        assert DHCPLease.from_text(lease.to_text(fmt), fmt) == lease


def test_a_lease_that_never_ends_has_no_expires() -> None:
    assert "expires" not in _lease(expires=None).to_mapping()
    assert DHCPLease.from_mapping({"ip": "10.0.0.5", "expires": None}).expires is None


def test_only_the_address_is_required() -> None:
    assert DHCPLease.from_mapping({"ip": "10.0.0.5"}) == DHCPLease("10.0.0.5")
    with pytest.raises(ValueError, match="'ip'"):
        DHCPLease.from_mapping({"expires": "2100-01-01T00:00:00Z"})


def test_expires_reads_a_z_an_offset_and_a_datetime() -> None:
    instant = dt.datetime(2100, 1, 1, tzinfo=UTC)
    for value in (
        "2100-01-01T00:00:00Z",
        "2100-01-01T01:00:00+01:00",
        instant,
    ):
        lease = DHCPLease.from_mapping({"ip": "10.0.0.5", "expires": value})
        assert lease.expires == instant and lease.expires.tzinfo is UTC


@pytest.mark.parametrize(
    "field, value, error",
    [
        ("ip", "0.0.0.0", DHCPValueError),
        ("ip", "not an address", DHCPValueError),
        ("expires", "tomorrow", DHCPValueError),
        ("expires", "2100-01-01T00:00:00", DHCPValueError),  # naive
        ("expires", 86400, TypeError),
        ("offered", "false", TypeError),
        ("options", {"ROUTER": "not an address"}, ValueError),
    ],
)
def test_what_the_constructor_refuses_is_refused(
    field: str, value: object, error: type
) -> None:
    data = {"ip": "10.0.0.5", field: value}
    with pytest.raises(error):
        DHCPLease.from_mapping(data)


def test_other_keys_are_ignored() -> None:
    lease = DHCPLease.from_mapping({"ip": "10.0.0.5", "client": "01:aa"})
    assert lease == DHCPLease("10.0.0.5")


def test_a_document_written_before_an_option_had_a_codec_still_loads() -> None:
    """Options 175, 94 and 97 were opaque, so a document holds them as hex text."""
    options = DHCPOptions.from_mapping(
        {
            "ETHERBOOT": "130101eb03011501",
            "CLIENT_NDI": "010310",
            "97": "00" + "11" * 16,
        }
    )
    assert bytes(options[175]) == bytes.fromhex("130101eb03011501")
    assert options.get(94).display_text() == "UNDI 3.16"
    assert options.get(97).uuid is not None
    with pytest.raises(DHCPValueError, match="CLIENT_NDI"):
        DHCPOptions.from_mapping({"CLIENT_NDI": "not hex"})
