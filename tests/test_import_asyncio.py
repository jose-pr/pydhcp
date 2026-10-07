"""Importing the package, and using its blocking half, does not import asyncio.

Each check runs in a fresh interpreter, because this process has long since
imported it.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

TWINS = {
    "AsyncDHCPListener": "listener",
    "AsyncDHCPServer": "server",
    "AsyncDHCPClient": "client",
    "AsyncDHCPRelay": "relay",
    "AsyncDHCPCapture": "capture",
}


def run(code: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-800:]
    return proc.stdout.strip()


def loaded_after(statement: str) -> str:
    return run("import sys\n%s\nprint('asyncio' in sys.modules)" % statement)


@pytest.mark.parametrize(
    "statement",
    [
        "import pydhcp",
        "import pydhcp.listener",
        "import pydhcp.server",
        "import pydhcp.client",
        "import pydhcp.relay",
        "import pydhcp.capture",
        "import pydhcp.packet, pydhcp.options, pydhcp.exceptions",
        "import pydhcp.cli",
        "from pydhcp import DHCPServer, DHCPClient, DHCPRelay, DHCPCapture",
    ],
)
def test_a_blocking_import_leaves_asyncio_alone(statement: str) -> None:
    assert loaded_after(statement) == "False"


def test_a_blocking_server_and_client_leave_asyncio_alone() -> None:
    """A server receiving on a thread and a client that sends it a DISCOVER
    over loopback: the blocking path, from bind to a handled datagram."""
    out = run("""
        import sys, time
        from pydhcp import DHCPClient, DHCPServer

        with DHCPServer(listen=("127.0.0.1", 0)) as server:
            server.start()
            port = server.bound_addresses[0].port
            with DHCPClient(listen=("127.0.0.1", 0)) as client:
                client.start()
                discover = client.build_discover(bytes.fromhex("020000000001"))
                client.send(discover, dst="127.0.0.1", port=port)
                end = time.monotonic() + 10
                while server.metrics.packets_received < 1 and time.monotonic() < end:
                    time.sleep(0.01)
            received = server.metrics.packets_received
        print(received >= 1, 'asyncio' in sys.modules)
        """)
    assert out == "True False"


@pytest.mark.parametrize("name", sorted(TWINS))
def test_touching_an_asyncio_twin_imports_asyncio(name: str) -> None:
    package = TWINS[name]
    assert loaded_after("import pydhcp; pydhcp.%s" % name) == "True"
    assert loaded_after("from pydhcp import %s" % name) == "True"
    assert loaded_after("from pydhcp.%s import %s" % (package, name)) == "True"


def test_a_twin_is_the_one_object_everywhere_and_is_bound_once() -> None:
    out = run("""
        import importlib, pydhcp

        twins = %r
        for name, package in twins.items():
            module = importlib.import_module("pydhcp." + package)
            assert name in pydhcp.__all__ and name in module.__all__, name
            assert name in dir(pydhcp) and name in dir(module), name
            assert name not in vars(pydhcp) and name not in vars(module), name
        for name, package in twins.items():
            module = importlib.import_module("pydhcp." + package)
            defined = getattr(importlib.import_module("pydhcp.%%s._asyncio" %% package), name)
            assert getattr(pydhcp, name) is defined is getattr(module, name), name
            assert name in vars(pydhcp) and name in vars(module), name
        print("ok")
        """ % (TWINS,))
    assert out == "ok"


@pytest.mark.parametrize("module", ["pydhcp", "pydhcp.server", "pydhcp.client"])
def test_an_unknown_name_is_still_an_attribute_error(module: str) -> None:
    out = run(
        "import %s as m\ntry:\n    m.NoSuchThing\nexcept AttributeError as exc:\n    print(exc)"
        % module
    )
    assert "NoSuchThing" in out and module in out
