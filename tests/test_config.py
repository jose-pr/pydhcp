from __future__ import annotations

import json
import pytest

from pydhcp import config
from pydhcp.config import load_config


def test_load_config_json(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"server": {"listen": "*"}}), encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


def test_load_config_yaml(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("server:\n  listen: '*'\n", encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


def test_load_config_yml_extension(tmp_path) -> None:
    path = tmp_path / "config.yml"
    path.write_text("server:\n  listen: '*'\n", encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


def test_load_config_toml(tmp_path) -> None:
    if config._tomllib is None:
        pytest.skip("TOML config loading requires optional TOML dependencies")
    path = tmp_path / "config.toml"
    path.write_text('[server]\nlisten = "*"\n', encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


def test_load_config_toml_without_reader_reports_not_implemented(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(config, "_tomllib", None)
    path = tmp_path / "config.toml"
    path.write_text('[server]\nlisten = "*"\n', encoding="utf-8")
    with pytest.raises(NotImplementedError, match="INI or JSON as a stdlib fallback"):
        load_config(str(path))


def test_load_config_ini(tmp_path) -> None:
    path = tmp_path / "config.ini"
    path.write_text("[server]\nlisten = *\n", encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


def test_load_config_json_rejects_non_mapping(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="Configuration must be a mapping"):
        load_config(str(path))


def test_load_config_yaml_rejects_non_mapping(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("- 1\n- 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Configuration must be a mapping"):
        load_config(str(path))
