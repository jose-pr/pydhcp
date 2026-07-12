import pytest
import errno
from unittest.mock import MagicMock
from pydhcp import DhcpServer
from pydhcp.netutils import SocketAddress, IPv4


def test_bind_permission_error():
    server = DhcpServer(listen=[("127.0.0.1", 67)])
    mock_address = MagicMock()
    mock_address.port = 67
    mock_address.ip = IPv4("127.0.0.1")
    mock_address.listen.side_effect = PermissionError("[Errno 13] Permission denied")
    server._listen = [mock_address]

    with pytest.raises(PermissionError) as exc_info:
        server.bind()
    assert "Port 67 requires root; try 6767 for testing" in str(exc_info.value)


def test_bind_address_in_use():
    server = DhcpServer(listen=[("127.0.0.1", 6767)])
    mock_address = MagicMock()
    mock_address.port = 6767
    mock_address.ip = IPv4("127.0.0.1")
    err = OSError(errno.EADDRINUSE, "Address already in use")
    mock_address.listen.side_effect = err
    server._listen = [mock_address]

    with pytest.raises(OSError) as exc_info:
        server.bind()
    assert "Port 6767 already in use; try port 7767" in str(exc_info.value)
