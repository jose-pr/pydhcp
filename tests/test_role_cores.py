"""The protocol cores read no clock and import no driver; the twins are siblings.

The drivers own sockets, threads, tasks and the clock; a core is handed a
decoded message and a context stamped with the time it arrived.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

import pydhcp
from pydhcp import (
    AsyncDHCPCapture,
    AsyncDHCPClient,
    AsyncDHCPRelay,
    AsyncDHCPServer,
    DHCPCapture,
    DHCPClient,
    DHCPRelay,
    DHCPServer,
)

SRC = pathlib.Path(pydhcp.__file__).resolve().parent

#: Every module of a core: the rules of a role, and the listener's shared base.
CORE_MODULES = [
    "listener/_core.py",
    "server/_core.py",
    "server/_state.py",
    "server/_policy.py",
    "server/_reply.py",
    "server/_handlers.py",
    "relay/_core.py",
    "capture/_core.py",
    "capture/_events.py",
    "client/_core.py",
]

#: Calls that read a clock or wait on one.
CLOCK_CALLS = {
    "now",
    "utcnow",
    "today",
    "monotonic",
    "monotonic_ns",
    "time",
    "time_ns",
    "perf_counter",
    "sleep",
}

DRIVER_MODULES = {"_sync", "_asyncio"}


def _tree(relative: str) -> ast.Module:
    return ast.parse((SRC / relative).read_text(encoding="utf-8"))


@pytest.mark.parametrize("relative", CORE_MODULES)
def test_a_core_reads_no_clock(relative: str) -> None:
    tree = _tree(relative)
    called = sorted(
        {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in CLOCK_CALLS
        }
    )
    imported = sorted(
        {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name in {"time", "sched", "asyncio", "threading"}
        }
        | {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module in {"time", "sched", "asyncio", "threading"}
        }
    )
    assert not called, f"{relative} calls a clock: {called}"
    assert not imported, f"{relative} imports {imported}"


@pytest.mark.parametrize(
    "relative", [m for m in CORE_MODULES if not m.startswith("listener/")]
)
def test_a_role_core_imports_no_driver(relative: str) -> None:
    offenders = []
    for node in ast.walk(_tree(relative)):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            parts = node.module.split(".")
            if parts[-1] in DRIVER_MODULES or "cli" in parts:
                offenders.append(node.module)
    assert not offenders, f"{relative} imports {offenders}"


@pytest.mark.parametrize(
    "sync, asyncy",
    [
        (DHCPServer, AsyncDHCPServer),
        (DHCPRelay, AsyncDHCPRelay),
        (DHCPCapture, AsyncDHCPCapture),
        (DHCPClient, AsyncDHCPClient),
    ],
)
def test_no_asyncio_role_is_a_subclass_of_a_synchronous_one(
    sync: type, asyncy: type
) -> None:
    assert not issubclass(asyncy, sync)
    assert not issubclass(sync, asyncy)
    shared = [
        base for base in sync.__mro__ if base in asyncy.__mro__ and base is not object
    ]
    assert shared, "the twins share nothing"
    assert all(base.__name__.startswith("_") for base in shared), shared


def test_no_role_class_carries_a_type_ignore_for_its_bases() -> None:
    offenders = []
    roles = [
        path
        for package in ("capture", "client", "listener", "relay", "server")
        for path in (SRC / package).rglob("*.py")
    ]
    for path in roles:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("class ") and "type: ignore" in line:
                offenders.append(f"{path.relative_to(SRC).as_posix()}:{number}")
    assert not offenders, offenders
