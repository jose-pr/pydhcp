import pytest
from pydhcp.netutils import MACAddress, SocketAddress, IPv4

def test_mac_address():
    mac = MACAddress("00-11-22-33-44-55")
    assert str(mac) == "00-11-22-33-44-55"
    assert mac.hex("-").upper() == "00-11-22-33-44-55"

    with pytest.raises(ValueError):
        MACAddress("00-11-22")

def test_socket_address():
    addr = SocketAddress("127.0.0.1", 8080)
    assert addr.ip == IPv4("127.0.0.1")
    assert addr.port == 8080
    assert addr.compat() == ("127.0.0.1", 8080)
    assert str(addr) == "127.0.0.1:8080"
