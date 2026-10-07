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


def test_the_library_requires_only_what_the_wire_and_the_capture_writer_need() -> None:
    assert _names(_project()["dependencies"]) == {"netimps", "pktcap"}


def test_each_capability_is_one_extra() -> None:
    extras = _project()["optional-dependencies"]

    assert _names(extras["cli"]) == {"duho"}
    assert _names(extras["yaml"]) == {"pyyaml"}
    assert _names(extras["toml"]) == {"tomli-w", "tomli"}


def test_dev_refers_to_the_extras_by_name_and_repeats_no_range() -> None:
    extras = _project()["optional-dependencies"]
    capabilities = {"cli", "yaml", "toml"}

    own = [Requirement(spec) for spec in extras["dev"] if spec.startswith("pydhcp")]

    assert len(own) == 1 and own[0].extras == capabilities
    assert not _names(extras["dev"]) & {"duho", "pyyaml", "tomli", "tomli-w"}


def _floor(extra: str, environment: "_ty.Dict[str, str]") -> "_ty.List[str]":
    floors = []
    for spec in _project()["optional-dependencies"][extra]:
        requirement = Requirement(spec)
        if requirement.marker is None or requirement.marker.evaluate(
            {"extra": "", **environment}
        ):
            floors.extend(
                s.version for s in requirement.specifier if s.operator == ">="
            )
    return floors


@pytest.mark.parametrize(
    "environment, floor",
    [
        # 6.0 has wheels for these.
        (
            {
                "python_version": "3.9",
                "sys_platform": "linux",
                "platform_machine": "x86_64",
            },
            "6.0",
        ),
        (
            {
                "python_version": "3.11",
                "sys_platform": "darwin",
                "platform_machine": "arm64",
            },
            "6.0",
        ),
        (
            {
                "python_version": "3.9",
                "sys_platform": "win32",
                "platform_machine": "AMD64",
            },
            "6.0",
        ),
        # No wheel of 6.0: Windows on ARM64, or Python 3.12 and later.
        (
            {
                "python_version": "3.9",
                "sys_platform": "win32",
                "platform_machine": "ARM64",
            },
            "6.0.1",
        ),
        (
            {
                "python_version": "3.14",
                "sys_platform": "win32",
                "platform_machine": "ARM64",
            },
            "6.0.1",
        ),
        (
            {
                "python_version": "3.12",
                "sys_platform": "linux",
                "platform_machine": "x86_64",
            },
            "6.0.1",
        ),
        (
            {
                "python_version": "3.14",
                "sys_platform": "linux",
                "platform_machine": "aarch64",
            },
            "6.0.1",
        ),
    ],
)
def test_exactly_one_pyyaml_floor_applies_to_a_host(
    environment: "_ty.Dict[str, str]", floor: str
) -> None:
    assert _floor("yaml", environment) == [floor]


def test_every_runtime_dependency_has_a_ceiling_at_the_next_series() -> None:
    project = _project()
    specs = list(project["dependencies"])
    for extra in ("cli", "yaml", "toml"):
        specs += project["optional-dependencies"][extra]

    unbounded = [
        spec
        for spec in specs
        if not any(s.operator == "<" for s in Requirement(spec).specifier)
    ]

    assert unbounded == []
