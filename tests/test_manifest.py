"""What the manifest promises: which dependencies are required, which are extras,
and which floor applies where."""

from __future__ import annotations

import pathlib
import sys
import typing as _ty

import pytest
from packaging.requirements import Requirement

if sys.version_info >= (3, 11):
    import tomllib
else:
    tomllib = pytest.importorskip("tomli")

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "pyproject.toml"

pytestmark = pytest.mark.skipif(
    not MANIFEST.is_file(), reason="the manifest is not beside the tests"
)


def _project() -> "_ty.Dict[str, _ty.Any]":
    with MANIFEST.open("rb") as handle:
        return _ty.cast("_ty.Dict[str, _ty.Any]", tomllib.load(handle)["project"])


def _names(specs: "_ty.Iterable[str]") -> "_ty.Set[str]":
    return {Requirement(spec).name.lower() for spec in specs}


def test_the_library_requires_only_what_the_wire_needs() -> None:
    assert _names(_project()["dependencies"]) == {"netimps"}


def test_each_capability_is_one_extra() -> None:
    extras = _project()["optional-dependencies"]

    assert _names(extras["cli"]) == {"duho"}
    assert _names(extras["pktcap"]) == {"pktcap"}
    assert "yaml" not in extras
    assert _names(extras["toml"]) == {"tomli"}


def test_dev_refers_to_the_extras_by_name_and_repeats_no_range() -> None:
    extras = _project()["optional-dependencies"]
    capabilities = {"cli", "pktcap", "toml"}

    own = [Requirement(spec) for spec in extras["dev"] if spec.startswith("pydhcp")]

    assert len(own) == 1 and own[0].extras == capabilities
    assert not _names(extras["dev"]) & {"duho", "pyyaml", "tomli", "tomli-w"}


def test_dev_installs_the_record_formats_pktcap_writes() -> None:
    extras = _project()["optional-dependencies"]

    own = [Requirement(spec) for spec in extras["dev"] if spec.startswith("pktcap")]

    assert len(own) == 1 and own[0].extras == {"yaml", "toml"}


def test_every_runtime_dependency_has_a_ceiling_at_the_next_series() -> None:
    project = _project()
    specs = list(project["dependencies"])
    for extra in ("cli", "pktcap", "toml"):
        specs += project["optional-dependencies"][extra]

    unbounded = [
        spec
        for spec in specs
        if not any(s.operator == "<" for s in Requirement(spec).specifier)
    ]

    assert unbounded == []
