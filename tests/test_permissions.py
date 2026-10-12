import errno
import importlib
import socket

import netimps
import pytest

from pydhcp import DHCPServer


def _privileged_port_is_refused() -> bool:
    """Does this host refuse an unprivileged bind of UDP port 67?

    Linux and macOS do unless the process has the capability (or the sysctl
    lowers the limit); Windows has no privileged ports.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 67))
    except PermissionError:
        return True
    except OSError:
        return False
    else:
        return False
    finally:
        probe.close()


@pytest.mark.skipif(
    not _privileged_port_is_refused(),
    reason="this process can bind port 67 (root, a capability, or a host without privileged ports)",
)
def test_a_privileged_port_is_refused_as_a_permission_error_of_the_host() -> None:
    server = DHCPServer(listen=[("127.0.0.1", 67)])
    try:
        with pytest.raises(PermissionError) as exc_info:
            server.bind()
    finally:
        server.close()

    assert not isinstance(exc_info.value, netimps.AddressInUseError)
    assert "67" in str(exc_info.value)


class _Refusing:
    """Stands for the host in `netimps`' `bind` and checks that it was reached.

    The module is private to netimps and the name is read before it is replaced,
    so a name that has moved is an `AttributeError`, and `verify()` fails a test
    that the stand-in was never reached.
    """

    # private: the module `bind_listen` reads `bind` from; this host does not refuse the bind
    MODULE = "netimps._listen._binding"

    def __init__(self, monkeypatch: pytest.MonkeyPatch, error: OSError) -> None:
        module = importlib.import_module(self.MODULE)
        getattr(module, "bind")
        self.calls = 0
        self._error = error
        # private: the name is looked up in the module that reads it, so the host can be stood for
        monkeypatch.setattr(module, "bind", self.bind)

    def bind(self, *args, **kwargs):
        self.calls += 1
        raise self._error

    def verify(self) -> None:
        assert self.calls, f"{self.MODULE}.bind was never called"


def test_bind_permission_error(monkeypatch):
    """The bind error is netimps' own, raised as it came."""
    server = DHCPServer(listen=[("127.0.0.1", 67)])
    error = PermissionError(errno.EACCES, "permission denied binding port 67")
    refusing = _Refusing(monkeypatch, error)

    with pytest.raises(PermissionError) as exc_info:
        server.bind()

    refusing.verify()
    assert exc_info.value is error


def test_bind_address_in_use():
    """`netimps.bind` raises `AddressInUseError` for a port that is taken; it
    reaches the caller as it was, with no suggestion appended."""
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    server = DHCPServer(listen=[("127.0.0.1", port)])
    try:
        with pytest.raises(netimps.AddressInUseError) as exc_info:
            server.bind()
    finally:
        holder.close()
        server.close()

    assert not isinstance(exc_info.value, PermissionError)
    message = str(exc_info.value)
    assert str(port) in message
    assert "try port" not in message.lower()
