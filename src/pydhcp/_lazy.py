"""Binding a public name on first use (internal).

A package that exports a class only some callers use, and whose module is
costly to import, names it in ``__all__`` and binds it here: the first access
imports the module that defines it and stores the object in the package, so
every later access is an ordinary attribute.
"""

from __future__ import annotations

import importlib as _importlib
import typing as _ty

__all__ = ["bind"]


def bind(
    package: str,
    namespace: "dict[str, _ty.Any]",
    sources: "_ty.Mapping[str, str]",
    name: str,
) -> _ty.Any:
    """The object `name` of `package`, imported from the module `sources`
    gives for it (relative to `package`) and stored in `namespace`.

    `AttributeError`, worded as a module's own, for a name `sources` lacks.
    """
    source = sources.get(name)
    if source is None:
        raise AttributeError(f"module {package!r} has no attribute {name!r}")
    value = getattr(_importlib.import_module(source, package), name)
    namespace[name] = value
    return value
