import json as _json
import configparser as _configparser
import typing as _ty
import yaml as _yaml  # type: ignore[import-untyped]

try:
    import tomllib as _tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - Python < 3.11
    try:
        import tomli as _tomllib
    except ImportError:  # pragma: no cover - optional dependency absent
        _tomllib = None


def _ensure_mapping(data: _ty.Any) -> _ty.Dict[str, _ty.Any]:
    if not isinstance(data, dict):
        raise ValueError("Configuration must be a mapping")
    return _ty.cast(_ty.Dict[str, _ty.Any], data)


def load_config(filepath: str) -> _ty.Dict[str, _ty.Any]:
    lowered = filepath.lower()
    if lowered.endswith(".ini"):
        parser = _configparser.ConfigParser()
        parser.read(filepath, encoding="utf-8")
        return {section: dict(parser.items(section)) for section in parser.sections()}

    if lowered.endswith(".yaml") or lowered.endswith(".yml"):
        with open(filepath, "r", encoding="utf-8") as f:
            return _ensure_mapping(_yaml.safe_load(f))

    if lowered.endswith(".toml"):
        if _tomllib is None:
            raise NotImplementedError(
                "TOML config loading requires Python 3.11+ or the 'tomli' package; use INI or JSON as a stdlib fallback"
            )
        with open(filepath, "rb") as f:
            return _ensure_mapping(_tomllib.load(f))

    with open(filepath, "r", encoding="utf-8") as f:
        return _ensure_mapping(_json.load(f))
