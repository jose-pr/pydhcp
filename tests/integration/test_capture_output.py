"""What `pydhcp capture` writes, octet for octet, against files written before the writer moved.

`tests/data/capture_output/expected/` holds the standard output, the growing files and
the one-file-per-record trees the command wrote for a fixed input (`build.py` beside
it says which). A record file is a user's data: the same message gives the same octets,
in the same file name, in each of the four formats.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import pathlib
import re
import typing as _ty

import pytest

from pydhcp import DHCPMessage

DATA = pathlib.Path(__file__).resolve().parents[1] / "data" / "capture_output"
EXPECTED = DATA / "expected"

_SPEC = importlib.util.spec_from_file_location(
    "capture_output_build", DATA / "build.py"
)
assert _SPEC is not None and _SPEC.loader is not None
build = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(build)

NAMES = sorted(
    path.relative_to(EXPECTED).as_posix()
    for path in EXPECTED.rglob("*")
    if path.is_file()
)


@pytest.fixture(scope="module")
def written(tmp_path_factory: pytest.TempPathFactory) -> "dict[str, bytes]":
    return _ty.cast(
        "dict[str, bytes]", build.build(tmp_path_factory.mktemp("capture_output"))
    )


def test_the_input_holds_only_lab_addresses_and_locally_administered_hardware() -> None:
    """Private addresses and locally administered hardware addresses only."""
    sent = build.datagrams()
    assert len(sent) == 53
    for data in sent:
        message = DHCPMessage.decode(data)
        assert message.chaddr[0] & 0x02, message.chaddr.hex()
        for found in re.findall(r"\d+\.\d+\.\d+\.\d+", message.to_text("json")):
            assert ipaddress.ip_address(found).is_private, found


def test_the_fixture_names_every_file_the_command_writes(
    written: "dict[str, bytes]",
) -> None:
    assert sorted(written) == NAMES


@pytest.mark.parametrize("name", NAMES)
def test_the_command_writes_the_octets_it_wrote_before(
    written: "dict[str, bytes]", name: str
) -> None:
    assert written[name] == (EXPECTED / name).read_bytes()
