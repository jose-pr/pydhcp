from __future__ import annotations

import configparser as _configparser
import json as _json
from io import StringIO as _StringIO
import typing as _ty

from ..exceptions import DHCPDecodeError

from .._extras import toml_reader, toml_writer, yaml_module

__all__ = ["dumps", "loads"]


def _normalize_format(format: str) -> str:
    normalized = format.lower().strip()
    if normalized not in {"json", "yaml", "toml", "ini"}:
        raise ValueError(f"Unsupported structured format: {format}")
    return normalized


def _ensure_mapping(data: _ty.Any) -> dict[str, _ty.Any]:
    if not isinstance(data, dict):
        raise DHCPDecodeError("Structured packet data must be a mapping")
    return data


def _json_or_text(value: str) -> _ty.Any:
    try:
        return _json.loads(value)
    except _json.JSONDecodeError:
        return value


def loads(text: str, format: str) -> dict[str, _ty.Any]:
    normalized = _normalize_format(format)
    if normalized == "json":
        return _ensure_mapping(_json.loads(text))
    if normalized == "yaml":
        return _ensure_mapping(yaml_module().safe_load(text))
    if normalized == "toml":
        return _ensure_mapping(toml_reader().loads(text))

    parser = _configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # type: ignore[method-assign,assignment]
    parser.read_string(text)
    if not parser.has_section("message"):
        raise DHCPDecodeError("INI packet data must include a [message] section")
    data: dict[str, _ty.Any] = {
        key: _json_or_text(value) for key, value in parser.items("message")
    }
    data["options"] = (
        {key: _json_or_text(value) for key, value in parser.items("options")}
        if parser.has_section("options")
        else {}
    )
    return data


def dumps(data: dict[str, _ty.Any], format: str) -> str:
    normalized = _normalize_format(format)
    if normalized == "json":
        return _json.dumps(data, indent=2) + "\n"
    if normalized == "yaml":
        return _ty.cast(str, yaml_module().safe_dump(data, sort_keys=False))
    if normalized == "toml":
        # The module arrives through a runtime import, so it is `Any` here.
        return _ty.cast(str, toml_writer().dumps(data))

    parser = _configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # type: ignore[method-assign,assignment]
    message = {
        key: _json.dumps(value) for key, value in data.items() if key != "options"
    }
    options = {
        key: _json.dumps(value)
        for key, value in _ty.cast(dict[str, _ty.Any], data.get("options", {})).items()
    }
    parser["message"] = message
    parser["options"] = options
    buffer = _StringIO()
    parser.write(buffer)
    return buffer.getvalue()
