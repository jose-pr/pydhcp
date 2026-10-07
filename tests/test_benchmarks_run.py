"""The benchmark runner labels a result by the tree it measures."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "bench_run", ROOT / "benchmarks" / "run.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_the_label_is_the_manifests_version_not_the_installed_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An editable install keeps the metadata of the version it was installed at."""
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.0.1-installed")

    # private: a benchmark script's sampler or labeller, called directly
    assert _load_runner()._project_version() == _manifest_version()


def test_every_suite_the_runner_names_has_a_script_with_a_sampler() -> None:
    runner = _load_runner()

    assert set(runner.SUITES) == {"parse", "options", "listener", "server"}
    for suite in runner.SUITES:
        assert (ROOT / "benchmarks" / f"bench_{suite}.py").is_file()
