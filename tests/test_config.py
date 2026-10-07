from __future__ import annotations

import json
import sys

import pytest

from pydhcp import DHCPConfigError

# the loader behind the command line is not public
from pydhcp._config import load_config


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
    if sys.version_info < (3, 11):
        pytest.importorskip("tomli")
    path = tmp_path / "config.toml"
    path.write_text('[server]\nlisten = "*"\n', encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


def test_load_config_ini(tmp_path) -> None:
    path = tmp_path / "config.ini"
    path.write_text("[server]\nlisten = *\n", encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


def test_load_config_json_rejects_non_mapping(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(DHCPConfigError, match="top level must be a mapping"):
        load_config(str(path))


def test_load_config_yaml_rejects_non_mapping(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("- 1\n- 2\n", encoding="utf-8")
    with pytest.raises(DHCPConfigError, match="top level must be a mapping"):
        load_config(str(path))
