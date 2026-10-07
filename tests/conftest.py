"""Fixtures shared by the suite; the helpers they share with it are in helpers.py.

The network guard is here too: it is autouse, so no test opts in.
"""

from __future__ import annotations

import ipaddress
import socket
import typing as _ty

import pytest

# -- the network guard ------------------------------------------------------

#: Names the hosts file answers, so resolving them asks no name server.
_LOCAL_NAMES = frozenset(
    {"localhost", "localhost.localdomain", "", "0.0.0.0", "::", "::1"}
)

#: The lookups that reach the C resolver.
_LOOKUPS = ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr")


class NetworkEscape(AssertionError):
    """A test sent to, connected to or asked a name server about something off this host."""


def _is_address_literal(host: object) -> bool:
    try:
        ipaddress.ip_address(str(host).split("%")[0])
    except ValueError:
        return False
    return True


def _lookup_is_local(host: object) -> bool:
    """Whether resolving `host` asks nobody: the hosts file's names and address literals."""
    return host is None or str(host) in _LOCAL_NAMES or _is_address_literal(host)


def _stays_on_host(host: object) -> bool:
    """Whether a datagram to `host` cannot leave this machine: loopback or unspecified."""
    if host is None or str(host) in _LOCAL_NAMES:
        return True
    try:
        address = ipaddress.ip_address(str(host).split("%")[0])
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


@pytest.fixture
def allow_off_host_destination() -> bool:
    """Let one test address a destination that is not this host.

    Requesting it is the documentation: the test says in its docstring why it
    must (a route probe that sends nothing, a broadcast the platform is asked
    about). Lookups stay guarded.
    """
    return True


@pytest.fixture(autouse=True)
def _network_guard(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    """Fail a test that sends, connects or resolves a name beyond this host.

    Address literals are not lookups and loopback never leaves the machine, so
    both pass. The escapes are recorded and fail the test again at teardown, so
    code that swallows the exception cannot hide one.
    """
    import netimps

    escapes: "list[str]" = []
    allowed = "allow_off_host_destination" in request.fixturenames

    def refuse(what: str) -> _ty.NoReturn:
        message = (
            f"{request.node.nodeid} called {what}; tests must never leave the host. "
            "Keep the datagram on loopback, or request `allow_off_host_destination` "
            "and say in the test why."
        )
        escapes.append(message)
        raise NetworkEscape(message)

    def check_destination(what: str, host: object) -> None:
        if not (allowed or _stays_on_host(host)):
            refuse(f"{what}({host!r})")

    for method in ("connect", "connect_ex", "sendto"):
        real = getattr(socket.socket, method)

        def wrapper(self, *args, _real=real, _name=method, **kwargs):
            address = args[-1] if args else None
            if (
                self.family in (socket.AF_INET, socket.AF_INET6)
                and isinstance(address, tuple)
                and address
            ):
                check_destination(f"socket.{_name}", address[0])
            return _real(self, *args, **kwargs)

        monkeypatch.setattr(socket.socket, method, wrapper)

    for method in ("send", "asend"):
        real_send = getattr(netimps.UDPEndpoint, method)

        def send_wrapper(
            self, data, dst, *args, _real=real_send, _name=method, **kwargs
        ):
            check_destination(f"UDPEndpoint.{_name}", dst)
            return _real(self, data, dst, *args, **kwargs)

        monkeypatch.setattr(netimps.UDPEndpoint, method, send_wrapper)

    for name in _LOOKUPS:
        real_lookup = getattr(socket, name)

        def lookup(first, *args, _real=real_lookup, _name=name, **kwargs):
            if not _lookup_is_local(first):
                refuse(f"socket.{_name}({first!r})")
            return _real(first, *args, **kwargs)

        monkeypatch.setattr(socket, name, lookup)

    yield escapes
    if escapes:
        pytest.fail("; ".join(escapes), pytrace=False)


@pytest.fixture
def network_escapes(_network_guard: "list[str]") -> "list[str]":
    """The escapes the guard has recorded in this test.

    For the test of the guard itself, which provokes one on purpose and clears
    the record so the teardown check does not fail it as well.
    """
    return _network_guard


class _Enumerations:
    """How many real adapter enumerations happened since the fixture began.

    `len()` of it is the count, read live from `netimps.interface_enumerations()`
    -- which counts the syscall, never a cached hit.
    """

    def __init__(self) -> None:
        import netimps

        self._netimps = netimps
        self._start = netimps.interface_enumerations()

    def __len__(self) -> int:
        return int(self._netimps.interface_enumerations() - self._start)


@pytest.fixture
def enumerations() -> "_Enumerations":
    """Count the host-adapter enumerations netimps actually performs.

    pydhcp's per-packet lookups go through netimps' enumeration cache, so a
    lookup and an enumeration are no longer the same thing -- the cost that
    matters, and that a flood multiplies, is the enumeration. netimps counts it
    publicly (`interface_enumerations()`). Starts from an empty cache.
    """
    import netimps

    netimps.clear_interface_cache()
    yield _Enumerations()
    netimps.clear_interface_cache()


@pytest.fixture
def fake_adapters(monkeypatch):
    """Describe the host's adapters, so the library's own selection runs over them.

    `install(*adapters)` replaces what netimps enumerates with the given
    `netimps.Interface` objects and makes its address lookups answer from the
    same list. Nothing of pydhcp is replaced: the enumeration, the default
    link-local filter and the lookups are the real functions.
    """
    import netimps

    def install(*adapters: "netimps.Interface") -> "list[netimps.Interface]":
        held = list(adapters)

        def holder(address: _ty.Any) -> _ty.Any:
            for adapter in held:
                if any(ip.ip == address for ip in adapter.ips):
                    return adapter
            return None

        monkeypatch.setattr(netimps, "get_interfaces", lambda **_kw: list(held))
        monkeypatch.setattr(
            netimps, "get_interface", lambda address, **_kw: holder(address)
        )
        monkeypatch.setattr(
            netimps,
            "is_local_address",
            lambda address, **_kw: holder(address) is not None,
        )
        return held

    return install
