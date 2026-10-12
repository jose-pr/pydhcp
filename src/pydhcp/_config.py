from __future__ import annotations

import os as _os
import typing as _ty

from . import _extras
from .exceptions import DHCPConfigError

#: The configuration formats `load_config` reads, by `duho.config` backend name; the
#: file name's ending says which one a file is.
BACKENDS = ("json", "toml", "yaml", "ini")

#: A bound on a reader's own problem text, in characters (it can echo a name).
_PROBLEM_LIMIT = 400


def _bounded(text: str, limit: int) -> str:
    """`text` as one line of at most `limit` characters."""
    line = " ".join(text.split())
    return line if len(line) <= limit else line[: limit - 3] + "..."


def _problem(message: str, path: str) -> str:
    """The problem in a `duho.config` error message: what follows `in config file PATH: `."""
    _, found, rest = message.partition(f"{path}: ")
    return _bounded(rest if found else message.removeprefix("duho: "), _PROBLEM_LIMIT)


def load_config(
    source: "_ty.Union[str, _os.PathLike[str]]", format: _ty.Optional[str] = None
) -> _ty.Dict[str, _ty.Any]:
    """Read one configuration file into a mapping of sections.

    The format is `format` (`json`, `toml`, `yaml` or `ini`, any case) or else the
    file name's ending (`.json`, `.toml`, `.yaml`, `.yml`, `.ini`, `.cfg`); any
    other ending is refused. The reader is `duho.config`: its INI puts the keys of
    `[DEFAULT]` at the top level, and a TOML file before Python 3.11 and a YAML
    file need its `config` and `yaml` extras.

    A file that cannot be read raises the `OSError`. A document that does not
    parse, whose top level is not a mapping, whose format cannot be told, or
    whose reader is not installed raises `DHCPConfigError` with the path and the
    position when `duho.config` gave them. Without the `cli` extra, which
    installs `duho`, the `ImportError` names it.
    """
    config = _extras.duho_config()
    path = _os.fspath(source)
    try:
        parsed = config.load(path, format, backends=BACKENDS)
    except config.ConfigError as error:
        raise DHCPConfigError(
            _problem(str(error), path), path, error.lineno, error.colno
        ) from None
    if not isinstance(parsed, dict):
        raise DHCPConfigError(
            f"the top level must be a mapping, not {type(parsed).__name__}", path
        )
    return _ty.cast(_ty.Dict[str, _ty.Any], parsed)
