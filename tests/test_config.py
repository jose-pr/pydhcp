"""`load_config`: duho.config's four readers behind one mapping and one error.

What the readers do with a document is duho's to test; these pin what pydhcp adds:
the top level is a mapping, an error is a `DHCPConfigError` that carries the path and
the position and nothing of the document, and the formats are the four named.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import typing as _ty

import pytest

from pydhcp import DHCPConfigError

# the loader behind the command line is not public
from pydhcp._config import load_config

HAS_TOML = sys.version_info >= (3, 11) or importlib.util.find_spec("tomli") is not None
HAS_YAML = importlib.util.find_spec("yaml") is not None

SECRET = "hunter2-SECRET"


def test_load_config_json(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"server": {"listen": "*"}}), encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


@pytest.mark.skipif(not HAS_TOML, reason="no TOML reader")
def test_load_config_toml(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[server]\nlisten = "*"\n', encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


@pytest.mark.parametrize("name", ["config.ini", "config.cfg"])
def test_load_config_ini(tmp_path, name: str) -> None:
    path = tmp_path / name
    path.write_text("[server]\nlisten = *\n", encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


@pytest.mark.skipif(not HAS_YAML, reason="no PyYAML")
@pytest.mark.parametrize("name", ["config.yaml", "config.yml"])
def test_load_config_yaml(tmp_path, name: str) -> None:
    path = tmp_path / name
    path.write_text("server:\n  listen: '*'\n", encoding="utf-8")
    assert load_config(str(path)) == {"server": {"listen": "*"}}


def test_the_format_can_be_named(tmp_path) -> None:
    path = tmp_path / "config.conf"
    path.write_text('{"server": {}}', encoding="utf-8")
    assert load_config(str(path), "JSON") == {"server": {}}


def test_the_keys_under_default_in_ini_are_the_top_level(tmp_path) -> None:
    path = tmp_path / "config.ini"
    path.write_text("[DEFAULT]\nlisten = *\n[server]\nlease_file = x\n", "utf-8")
    assert load_config(str(path)) == {"listen": "*", "server": {"lease_file": "x"}}


def test_load_config_json_rejects_non_mapping(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(DHCPConfigError, match="top level must be a mapping"):
        load_config(str(path))


@pytest.mark.skipif(not HAS_YAML, reason="no PyYAML")
def test_an_empty_yaml_file_is_not_a_mapping(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(DHCPConfigError, match="not NoneType"):
        load_config(str(path))


@pytest.mark.parametrize("name", ["config.conf", "config"])
def test_a_name_no_format_claims_is_refused(tmp_path, name: str) -> None:
    path = tmp_path / name
    path.write_text("[server]\n", encoding="utf-8")
    with pytest.raises(DHCPConfigError, match="cannot tell the config format") as e:
        load_config(str(path))
    assert e.value.path == str(path)


def test_a_dash_is_a_file_name_and_not_standard_input() -> None:
    with pytest.raises(FileNotFoundError):
        load_config("-", "json")


def test_a_missing_file_is_the_oserror(tmp_path) -> None:
    for suffix in (".ini", ".json", ".toml", ".yaml"):
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / ("missing" + suffix)))


#: file name, the document with the marker as a value, and whether the format needs a library
MALFORMED: "list[_ty.Any]" = [
    pytest.param(
        "bad.json",
        '{"server": {"token": "' + SECRET + '", "listen": "127.0.0.1:1"',
        (1, None),
        id="json",
    ),
    pytest.param("bad.ini", "token = " + SECRET + "\n[server]\n", (1, None), id="ini"),
    pytest.param(
        "bad.toml",
        "[server\ntoken = '" + SECRET + "'\n",
        (1, 8),
        id="toml",
        marks=pytest.mark.skipif(not HAS_TOML, reason="no TOML reader"),
    ),
    pytest.param(
        "bad.yaml",
        "server: [" + SECRET + "\n",
        (2, 1),
        id="yaml",
        marks=pytest.mark.skipif(not HAS_YAML, reason="no PyYAML"),
    ),
]


@pytest.mark.parametrize("name, text, where", MALFORMED)
def test_a_malformed_document_is_an_error_with_its_position_and_none_of_its_text(
    tmp_path, name: str, text: str, where: "_ty.Tuple[int, _ty.Optional[int]]"
) -> None:
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))

    with pytest.raises(DHCPConfigError) as error:
        load_config(path)

    caught = error.value
    assert caught.path == str(path)
    assert caught.lineno == where[0]
    if where[1] is not None:
        assert caught.colno == where[1]
    assert str(caught).startswith(f"{path}:{where[0]}")
    assert "\n" not in str(caught)
    assert SECRET not in str(caught) and SECRET not in repr(vars(caught))
    assert caught.__cause__ is None and caught.__suppress_context__
