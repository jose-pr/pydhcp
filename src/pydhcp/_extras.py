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


#: What every capture function and command says when pktcap is not installed.
PKTCAP_NEEDED = "captures need the 'pktcap' extra: pip install \"pydhcp[pktcap]\""


def pktcap_module() -> _ty.Any:
    """`pktcap`, from the `pktcap` extra; `ImportError` with `PKTCAP_NEEDED` when it is absent.

    Only the module itself being absent is "not installed": a failure inside pktcap,
    or in one of its own dependencies, is raised as it is.
    """
    try:
        import pktcap
    except ModuleNotFoundError as error:
        if error.name != "pktcap":
            raise
        raise ImportError(PKTCAP_NEEDED) from error
    return pktcap


class _LazyPktcap:
    """Stands for the `pktcap` module where a module of this package names it.

    A name imported only for the type checker cannot be resolved by
    `typing.get_type_hints`; this object can, because it imports pktcap when an
    attribute is first read, and raises the `ImportError` of `pktcap_module`
    when the extra is not installed.
    """

    __slots__ = ()

    def __getattr__(self, name: str) -> _ty.Any:
        return getattr(pktcap_module(), name)


#: `pktcap` for a module that cannot import it at the top.
lazy_pktcap: _ty.Any = _LazyPktcap()


def has_pktcap() -> bool:
    """Whether the `pktcap` extra is installed."""
    try:
        pktcap_module()
    except ImportError:
        return False
    return True


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
