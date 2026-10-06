import errno

import netimps
import pytest

from pydhcp import DHCPServer


def _bind_raising(monkeypatch, error: OSError) -> None:
    def refuse(*args, **kwargs):
        raise error

    monkeypatch.setattr(netimps, "bind", refuse)


def test_bind_permission_error(monkeypatch):
    """The bind error is netimps' own, raised as it came."""
    server = DHCPServer(listen=[("127.0.0.1", 67)])
    error = PermissionError(errno.EACCES, "permission denied binding port 67")
    _bind_raising(monkeypatch, error)

    with pytest.raises(PermissionError) as exc_info:
        server.bind()

    assert exc_info.value is error


def test_bind_address_in_use(monkeypatch):
    """`netimps.bind` raises `AddressInUseError` for every in-use shape; it
    reaches the caller as it was, with no suggestion appended."""
    server = DHCPServer(listen=[("127.0.0.1", 6767)])
    error = netimps.AddressInUseError(errno.EADDRINUSE, "Port 6767 is already in use")
    _bind_raising(monkeypatch, error)

    with pytest.raises(netimps.AddressInUseError) as exc_info:
        server.bind()

    assert exc_info.value is error
    assert not isinstance(exc_info.value, PermissionError)
