"""Constructors take the first one or two arguments positionally, the rest by keyword,
and perform no I/O: no socket, no adapter enumeration, no file."""

from __future__ import annotations

import inspect
import socket
import typing as _ty

import pytest

from pydhcp import AsyncDHCPClient, DHCPClient
from pydhcp.capture import AsyncDHCPCapture, DHCPCapture
from pydhcp.lease import FileLeaseBackend
from pydhcp.listener import AsyncDHCPListener, DHCPListener
from pydhcp.relay import AsyncDHCPRelay, DHCPRelay
from pydhcp.server import AsyncDHCPServer, DHCPServer

#: Class -> how many arguments it takes positionally.
POSITIONAL = {
    DHCPListener: 1,
    AsyncDHCPListener: 1,
    DHCPServer: 1,
    AsyncDHCPServer: 1,
    DHCPRelay: 2,
    AsyncDHCPRelay: 2,
    DHCPCapture: 1,
    AsyncDHCPCapture: 1,
    DHCPClient: 1,
    AsyncDHCPClient: 1,
    FileLeaseBackend: 1,
}
LISTENERS = [cls for cls in POSITIONAL if cls is not FileLeaseBackend]


def _build(cls: type, **kwargs: _ty.Any) -> _ty.Any:
    if cls in (DHCPRelay, AsyncDHCPRelay):
        kwargs.setdefault("server_addresses", ["192.0.2.1"])
    return cls(**kwargs)


@pytest.mark.parametrize("cls", POSITIONAL, ids=lambda c: c.__name__)
def test_every_option_after_the_first_ones_is_keyword_only(cls: type) -> None:
    parameters = list(inspect.signature(cls).parameters.values())
    positional = [
        p for p in parameters if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]
    assert len(positional) == POSITIONAL[cls], [p.name for p in positional]
    assert all(p.kind is p.KEYWORD_ONLY for p in parameters[POSITIONAL[cls] :])


@pytest.mark.parametrize("cls", LISTENERS, ids=lambda c: c.__name__)
def test_an_extra_positional_argument_is_a_type_error(cls: type) -> None:
    extra = ["192.0.2.1"] if cls in (DHCPRelay, AsyncDHCPRelay) else []
    with pytest.raises(TypeError):
        cls("*", *extra, 1.0)  # type: ignore[call-arg]


@pytest.mark.parametrize("cls", LISTENERS, ids=lambda c: c.__name__)
def test_a_constructor_opens_no_socket_and_enumerates_no_adapter(
    cls: type, enumerations: _ty.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The packet-info probe asks a socket and the wildcard expansion lists the
    adapters; both wait for `bind()`."""

    def refuse(*args: _ty.Any, **kwargs: _ty.Any) -> _ty.Any:
        raise AssertionError("a constructor opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    for per_interface in (None, True, False):
        _build(cls, listen="*", per_interface=per_interface)
    assert len(enumerations) == 0


@pytest.mark.parametrize("cls", LISTENERS, ids=lambda c: c.__name__)
def test_reuse_address_and_receive_buffer_size_are_arguments(
    cls: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: "dict[str, _ty.Any]" = {}

    def record(*args: _ty.Any, **kwargs: _ty.Any) -> None:
        seen.update(kwargs)

    # private: the name is looked up in the module that reads it, so the host or the clock can be stood for
    monkeypatch.setattr("pydhcp.listener._core._bind_sockets", record)
    _build(
        cls, listen=("127.0.0.1", 0), reuse_address=True, receive_buffer_size=4096
    ).bind()
    assert seen["reuse_address"] is True and seen["receive_buffer"] == 4096

    seen.clear()
    _build(cls, listen=("127.0.0.1", 0)).bind()
    assert seen["reuse_address"] is cls.REUSE_ADDRESS  # type: ignore[attr-defined]
    assert seen["receive_buffer"] == cls.RECEIVE_BUFFER_SIZE  # type: ignore[attr-defined]


def test_the_poll_interval_is_a_keyword_and_select_timeout_is_gone() -> None:
    # private: the wait bound as stored
    assert DHCPListener(poll_interval=0.25)._poll_interval == 0.25
    with pytest.raises(TypeError):
        DHCPListener(select_timeout=0.25)  # type: ignore[call-arg]


# --- FileLeaseBackend ---


def test_the_path_is_required() -> None:
    with pytest.raises(TypeError):
        FileLeaseBackend()  # type: ignore[call-arg]


def test_construction_touches_no_file(tmp_path: _ty.Any) -> None:
    missing = tmp_path / "nowhere" / "leases.json"
    FileLeaseBackend(str(missing))
    assert not missing.parent.exists()

    corrupt = tmp_path / "leases.json"
    corrupt.write_bytes(b"{not json")
    FileLeaseBackend(str(corrupt))
    assert corrupt.read_bytes() == b"{not json"
    assert not (tmp_path / "leases.json.corrupt").exists()


def test_open_reads_the_file_once_and_sets_a_corrupt_one_aside(
    tmp_path: _ty.Any,
) -> None:
    corrupt = tmp_path / "leases.json"
    corrupt.write_bytes(b"{not json")
    backend = FileLeaseBackend(str(corrupt))
    backend.open()
    assert not corrupt.exists()
    assert (tmp_path / "leases.json.corrupt").read_bytes() == b"{not json"
    backend.open()  # idempotent


def test_a_lease_survives_a_restart_whichever_way_the_file_is_opened(
    tmp_path: _ty.Any,
) -> None:
    from ipaddress import IPv4Address

    path = str(tmp_path / "leases.json")
    with FileLeaseBackend(path) as first:
        first.allocate("client", IPv4Address("192.0.2.9"), 3600)

    with FileLeaseBackend(path) as second:
        lease = second.lookup("client")
    assert lease is not None and lease.ip == IPv4Address("192.0.2.9")

    # No explicit open: the first lease operation reads the file.
    lease = FileLeaseBackend(path).lookup("client")
    assert lease is not None and lease.ip == IPv4Address("192.0.2.9")
