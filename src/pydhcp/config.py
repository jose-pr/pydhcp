import json as _json
import configparser as _configparser
import typing as _ty
import yaml as _yaml  # type: ignore[import-untyped]


def _import_toml_reader() -> _ty.Any:
    """The stdlib/optional TOML *reader*, or None when neither is installed.

    `tomllib` is stdlib from 3.11; `tomli` is the backport this package lists
    as the optional `toml` extra. Shared with `pydhcp.packet.structured`,
    which needs exactly this guard -- the ladder was written out twice and the
    two copies had already grown three differently worded errors for one
    condition. Each caller keeps its own module-level binding so a test can
    monkeypatch absence per module.
    """
    try:
        import tomllib  # type: ignore[import-not-found]

        return tomllib
    except ImportError:  # pragma: no cover - Python < 3.11
        try:
            import tomli

            return tomli
        except ImportError:  # pragma: no cover - optional dependency absent
            return None


def _import_toml_writer() -> _ty.Any:
    """The optional TOML *writer* (`tomli-w`), or None when not installed.

    There is no stdlib TOML writer at any version, which is why this is a
    separate probe from `_import_toml_reader`.
    """
    try:
        import tomli_w

        return tomli_w
    except ImportError:  # pragma: no cover - optional dependency absent
        return None


def _toml_reader_unavailable(operation: str, fallback: str) -> NotImplementedError:
    """The single phrasing for "this TOML read cannot run here"."""
    return NotImplementedError(
        f"{operation} requires Python 3.11+ or the 'tomli' package; "
        f"use {fallback} as a stdlib fallback"
    )


def _toml_writer_unavailable(operation: str, fallback: str) -> NotImplementedError:
    """The single phrasing for "this TOML write cannot run here"."""
    return NotImplementedError(
        f"{operation} requires the 'tomli-w' package; "
        f"use {fallback} as a stdlib fallback"
    )


_tomllib = _import_toml_reader()


def _ensure_mapping(data: _ty.Any) -> _ty.Dict[str, _ty.Any]:
    if not isinstance(data, dict):
        raise ValueError("Configuration must be a mapping")
    return _ty.cast(_ty.Dict[str, _ty.Any], data)


def load_config(filepath: str) -> _ty.Dict[str, _ty.Any]:
    lowered = filepath.lower()
    if lowered.endswith(".ini"):
        parser = _configparser.ConfigParser()
        # ConfigParser.read() ignores a path that does not exist and returns the
        # list it did read, so a typo in --config silently produced an empty
        # config and a server on its defaults -- while the same typo in a .yaml
        # or .json path raised. Make every format fail the same way.
        if not parser.read(filepath, encoding="utf-8"):
            raise FileNotFoundError(filepath)
        return {section: dict(parser.items(section)) for section in parser.sections()}

    if lowered.endswith(".yaml") or lowered.endswith(".yml"):
        with open(filepath, "r", encoding="utf-8") as f:
            return _ensure_mapping(_yaml.safe_load(f))

    if lowered.endswith(".toml"):
        if _tomllib is None:
            raise _toml_reader_unavailable("TOML config loading", "INI or JSON")
        with open(filepath, "rb") as f:
            return _ensure_mapping(_tomllib.load(f))

    with open(filepath, "r", encoding="utf-8") as f:
        return _ensure_mapping(_json.load(f))
