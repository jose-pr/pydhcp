"""The optional dependencies, imported where they are used.

Each function returns the module, or raises `ImportError` whose message names
the extra that installs it, in the form a user can paste. Nothing here imports
an optional module until a function is called, so `import pydhcp` loads none.
"""

from __future__ import annotations

import typing as _ty


def missing(what: str, extra: str) -> str:
    """The message for a capability whose extra is not installed."""
    return f'{what} needs the {extra!r} extra: pip install "pydhcp[{extra}]"'


def yaml_module() -> _ty.Any:
    """PyYAML, from the `yaml` extra."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as error:
        raise ImportError(missing("YAML", "yaml")) from error
    return yaml


def toml_reader() -> _ty.Any:
    """`tomllib` (Python 3.11 and later), else `tomli` from the `toml` extra."""
    try:
        import tomllib  # type: ignore[import-not-found]
    except ImportError:
        pass  # before Python 3.11 the reader is the extra's
    else:
        return tomllib
    try:
        import tomli
    except ImportError as error:
        raise ImportError(missing("Reading TOML", "toml")) from error
    return tomli


def toml_writer() -> _ty.Any:
    """`tomli_w` from the `toml` extra; the standard library has no TOML writer."""
    try:
        import tomli_w
    except ImportError as error:
        raise ImportError(missing("Writing TOML", "toml")) from error
    return tomli_w
