from __future__ import annotations

import configparser as _configparser
import json as _json
from io import StringIO as _StringIO
import typing as _ty

from .message import DhcpMessage

try:
    import tomllib as _tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    try:
        import tomli as _tomllib  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover - optional dependency absent
        _tomllib = None  # type: ignore[assignment]

try:
    import tomli_w as _tomli_w
except ImportError:  # pragma: no cover - optional dependency absent
    _tomli_w = None  # type: ignore[assignment]
import yaml as _yaml


_StructuredFormat = _ty.Literal["json", "yaml", "toml", "ini"]


def _normalize_format(format: str) -> str:
    normalized = format.lower().strip()
    if normalized not in {"json", "yaml", "toml", "ini"}:
        raise ValueError(f"Unsupported structured format: {format}")
    return normalized


def _ensure_mapping(data: _ty.Any) -> dict[str, _ty.Any]:
    if not isinstance(data, dict):
        raise ValueError("Structured packet data must be a mapping")
    return data


def _json_or_text(value: str) -> _ty.Any:
    try:
        return _json.loads(value)
    except _json.JSONDecodeError:
        return value


def load_mapping(text: str, format: str) -> dict[str, _ty.Any]:
    normalized = _normalize_format(format)
    if normalized == "json":
        return _ensure_mapping(_json.loads(text))
    if normalized == "yaml":
        return _ensure_mapping(_yaml.safe_load(text))
    if normalized == "toml":
        if _tomllib is None:
            raise NotImplementedError(
                "TOML packet decoding requires Python 3.11+ or the 'tomli' package; use INI format as a stdlib fallback"
            )
        return _ensure_mapping(_tomllib.loads(text))

    parser = _configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(text)
    if not parser.has_section("message"):
        raise ValueError("INI packet data must include a [message] section")
    data: dict[str, _ty.Any] = {
        key: _json_or_text(value) for key, value in parser.items("message")
    }
    data["options"] = {
        key: _json_or_text(value) for key, value in parser.items("options")
    } if parser.has_section("options") else {}
    return data


def dump_mapping(data: dict[str, _ty.Any], format: str) -> str:
    normalized = _normalize_format(format)
    if normalized == "json":
        return _json.dumps(data, indent=2) + "\n"
    if normalized == "yaml":
        return _yaml.safe_dump(data, sort_keys=False)
    if normalized == "toml":
        if _tomli_w is None:
            raise NotImplementedError(
                "TOML packet encoding requires the 'tomli-w' package; use INI format as a stdlib fallback"
            )
        return _tomli_w.dumps(data)

    parser = _configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    message = {key: _json.dumps(value) for key, value in data.items() if key != "options"}
    options = {
        key: _json.dumps(value) for key, value in _ty.cast(dict[str, _ty.Any], data.get("options", {})).items()
    }
    parser["message"] = message
    parser["options"] = options
    buffer = _StringIO()
    parser.write(buffer)
    return buffer.getvalue()


def dump_message(message: DhcpMessage, format: str) -> str:
    return dump_mapping(message.to_mapping(), format)


def load_message(text: str, format: str) -> DhcpMessage:
    return DhcpMessage.from_mapping(load_mapping(text, format))
