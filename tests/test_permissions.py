import pytest
import errno
from unittest.mock import MagicMock
from pydhcp import DHCPServer
from pydhcp.network import SocketAddress, IPv4


def test_bind_permission_error():
    server = DHCPServer(listen=[("127.0.0.1", 67)])
    mock_address = MagicMock()
    mock_address.port = 67
    mock_address.ip = IPv4("127.0.0.1")
    mock_address.listen.side_effect = PermissionError("[Errno 13] Permission denied")
    server._listen = [mock_address]

    with pytest.raises(PermissionError) as exc_info:
        server.bind()
    # Wording comes from netimps.bind_error_hint plus the DHCP-specific
    # suggestion; assert the facts a user needs rather than the exact phrasing.
    message = str(exc_info.value)
    assert "67" in message
    assert "root" in message.lower()
    assert "6767" in message


def test_bind_address_in_use():
    """`netimps.bind` raises `AddressInUseError` for every in-use shape, so
    that is what the mocked `listen` raises; the DHCP suggestion is appended."""
    import netimps

    server = DHCPServer(listen=[("127.0.0.1", 6767)])
    mock_address = MagicMock()
    mock_address.port = 6767
    mock_address.ip = IPv4("127.0.0.1")
    err = netimps.AddressInUseError(errno.EADDRINUSE, "Port 6767 is already in use")
    mock_address.listen.side_effect = err
    server._listen = [mock_address]

    with pytest.raises(OSError) as exc_info:
        server.bind()
    message = str(exc_info.value)
    assert "6767" in message
    assert "in use" in message
    assert "7767" in message  # the suggested alternative
    assert isinstance(exc_info.value, netimps.AddressInUseError)
    assert not isinstance(exc_info.value, PermissionError)
