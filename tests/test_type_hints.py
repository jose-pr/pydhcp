"""Every public annotation resolves with `typing.get_type_hints`.

Documentation generators, runtime validators and dependency injectors evaluate
annotations; on the oldest supported Python an `X | Y` or a name imported only
under `TYPE_CHECKING` fails there with a `TypeError` or `NameError` while a
type checker is content. The walk covers every class and function a public
module exports, each class's methods, properties and class-level fields.

`DHCPOptions` also shadows the builtin `type` through its star import of the
`type` subpackage, so its annotations are checked by name as well.
"""

from __future__ import annotations

import importlib
import inspect
import typing

import pytest

from pydhcp.options import DHCPOptions

#: Modules that declare `__all__`: the walk covers what it lists.
_WITH_ALL = [
    "pydhcp",
    "pydhcp.cli",
    "pydhcp.exceptions",
    "pydhcp.listener",
    "pydhcp.options.type",
    "pydhcp.packet",
    "pydhcp.packet.enums",
    "pydhcp.packet.message",
    "pydhcp.server",
]

#: Public modules without `__all__`: the walk covers every public name they define.
_WITHOUT_ALL = [
    "pydhcp.capture",
    "pydhcp.client",
    "pydhcp.config",
    "pydhcp.constants",
    "pydhcp.lease",
    "pydhcp.log",
    "pydhcp.metrics",
    "pydhcp.network",
    "pydhcp.nvt",
    "pydhcp.options",
    "pydhcp.options.base",
    "pydhcp.options.code",
    "pydhcp.options.registry",
    "pydhcp.packet.structured",
    "pydhcp.relay",
]


def _public_objects() -> typing.Iterator[typing.Tuple[str, object]]:
    seen: typing.Set[int] = set()
    for modname in _WITH_ALL + _WITHOUT_ALL:
        module = importlib.import_module(modname)
        names = getattr(module, "__all__", None)
        if names is None:
            names = [
                n
                for n, v in vars(module).items()
                if not n.startswith("_")
                and getattr(v, "__module__", None) == modname
                and (inspect.isclass(v) or inspect.isfunction(v))
            ]
        for name in names:
            obj = getattr(module, name)
            if not (inspect.isclass(obj) or inspect.isfunction(obj)):
                continue
            if not getattr(obj, "__module__", "").startswith("pydhcp"):
                continue
            if id(obj) in seen:
                continue
            seen.add(id(obj))
            yield f"{modname}.{name}", obj


def _members(cls: type) -> typing.Iterator[typing.Tuple[str, object]]:
    for mname in sorted(vars(cls)):
        if mname.startswith("_") and mname not in ("__init__", "__new__"):
            continue
        if mname == "__new__" and hasattr(cls, "_fields"):
            # The `__new__` that `collections` generates for a named tuple has
            # no module globals, so its string annotations never resolve on
            # some versions; the fields are checked on the class itself.
            continue
        raw = vars(cls)[mname]
        if isinstance(raw, (staticmethod, classmethod)):
            raw = raw.__func__
        elif isinstance(raw, property):
            raw = raw.fget
        if inspect.isfunction(raw):
            yield mname, raw


def _failures() -> typing.Dict[str, str]:
    failures: typing.Dict[str, str] = {}
    for qualified, obj in _public_objects():
        targets: typing.List[typing.Tuple[str, object]] = []
        if inspect.isclass(obj):
            targets.append((qualified, obj))
            targets.extend((f"{qualified}.{m}", f) for m, f in _members(obj))
        else:
            targets.append((qualified, obj))
        for label, target in targets:
            try:
                typing.get_type_hints(target)
            except Exception as exc:  # noqa: BLE001 - the message is the report
                failures[label] = f"{type(exc).__name__}: {exc}"
    return failures


def test_every_public_annotation_resolves() -> None:
    assert _failures() == {}


@pytest.mark.parametrize("member", ["__init__", "get", "items"])
def test_the_option_bag_annotations_can_be_evaluated(member: str) -> None:
    hints = typing.get_type_hints(getattr(DHCPOptions, member))
    assert hints, f"{member} resolved to no hints at all"


def test_the_option_submodule_really_does_shadow_the_builtin() -> None:
    """The premise of the qualification in `pydhcp.options`, pinned."""
    import pydhcp.options as options_module

    assert options_module.type is not type
    assert options_module.type.__name__ == "pydhcp.options.type"
