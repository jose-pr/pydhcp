"""The package layout: which modules are public, how big a module may be, and
how modules import each other.

A module without a leading underscore promises its import path will not move,
so the list below is the whole promise. A split of a large module adds
underscored modules; it never adds, moves or removes a public path by accident.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

import pydhcp

_SRC = Path(pydhcp.__file__).resolve().parent
_ROOT = _SRC.parent

#: Every public module path.
PUBLIC_MODULES = [
    "pydhcp",
    "pydhcp.capture",
    "pydhcp.cli",
    "pydhcp.client",
    "pydhcp.exceptions",
    "pydhcp.lease",
    "pydhcp.listener",
    "pydhcp.options",
    "pydhcp.packet",
    "pydhcp.packet.structured",
    "pydhcp.relay",
    "pydhcp.server",
]

#: The most lines a module may have. A module is a unit someone reviews in one
#: sitting; past this it is split along a seam, or named below with the reason.
MAX_MODULE_LINES = 500

#: Modules over the limit, each with why.
_LONG_MODULES = {
    "options/_codes.py": (
        "the standard option-code registry: one enum member per IANA code, each "
        "carrying the RFC text that defines it in its docstring"
    ),
}


def _modules() -> List[Path]:
    return sorted(p for p in _SRC.rglob("*.py") if "__pycache__" not in p.parts)


def _dotted(path: Path) -> str:
    parts = list(path.relative_to(_ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _is_public(dotted: str) -> bool:
    return not any(part.startswith("_") for part in dotted.split("."))


def test_the_public_modules_are_the_listed_ones() -> None:
    public = sorted(
        _dotted(p)
        for p in _modules()
        if p.name != "__main__.py" and _is_public(_dotted(p))
    )
    assert public == sorted(PUBLIC_MODULES)


def test_every_public_module_declares_all() -> None:
    missing = []
    for p in _modules():
        if p.name == "__main__.py" or not _is_public(_dotted(p)):
            continue
        tree = ast.parse(p.read_text(encoding="utf-8"))
        names = {
            target.id
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
            if isinstance(target, ast.Name)
        }
        if "__all__" not in names:
            missing.append(_dotted(p))
    assert missing == []


def test_no_module_is_over_the_size_limit_without_a_reason() -> None:
    long = {
        p.relative_to(_SRC).as_posix(): n
        for p in _modules()
        for n in [len(p.read_text(encoding="utf-8").splitlines())]
        if n > MAX_MODULE_LINES
    }
    unexplained = {name: n for name, n in long.items() if name not in _LONG_MODULES}
    assert unexplained == {}, "split it, or name it in _LONG_MODULES with a reason"
    stale = [name for name in _LONG_MODULES if name not in long]
    assert stale == [], "no longer over the limit: remove from _LONG_MODULES"
    assert all(reason.strip() for reason in _LONG_MODULES.values())


def _top_level_definitions(path: Path) -> Set[str]:
    """Names a module defines itself (a class, a function or an assignment)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: Set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names.update(t.id for t in targets if isinstance(t, ast.Name))
    return names


def _imports_from_packages(
    path: Path, modules: Dict[str, Path]
) -> Iterator[Tuple[int, str, str]]:
    """``(line, package, name)`` for each name imported out of a package `__init__`."""
    dotted = _dotted(path)
    package = (
        dotted.split(".") if path.name == "__init__.py" else dotted.split(".")[:-1]
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            base = package[: len(package) - (node.level - 1)]
            target: Optional[str] = ".".join(
                base + (node.module.split(".") if node.module else [])
            )
        else:
            target = node.module
        if target not in modules or modules[target].name != "__init__.py":
            continue
        for alias in node.names:
            if f"{target}.{alias.name}" in modules:
                continue  # a submodule, not a name the package re-exports
            yield node.lineno, target, alias.name


def test_no_internal_import_goes_through_a_re_exporting_init() -> None:
    """A name is imported from the module that defines it.

    A package `__init__` assembling its own children is the one exception, and
    so is the root assembling the public surface: both are where a re-export is
    written. Every other module that imports from a package `__init__` imports
    a name that `__init__` defines itself.
    """
    modules = {_dotted(p): p for p in _modules()}
    offenders = []
    for path in _modules():
        dotted = _dotted(path)
        if dotted == "pydhcp":
            continue
        is_init = path.name == "__init__.py"
        for line, target, name in _imports_from_packages(path, modules):
            if is_init and (target == dotted or target.startswith(dotted + ".")):
                continue
            if name == "*" or name not in _top_level_definitions(modules[target]):
                offenders.append(
                    f"{path.relative_to(_SRC).as_posix()}:{line} {target}.{name}"
                )
    assert offenders == []
