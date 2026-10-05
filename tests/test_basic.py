import pytest
from pydhcp.network import MACAddress, SocketAddress, IPv4


def test_mac_address():
    mac = MACAddress("00-11-22-33-44-55")
    assert str(mac) == "00-11-22-33-44-55"
    assert mac.hex("-").upper() == "00-11-22-33-44-55"

    with pytest.raises(ValueError):
        MACAddress("00-11-22")


def test_mac_address_renders_the_same_through_every_formatting_path():
    mac = MACAddress("00:11:22:aa:bb:cc")
    assert str(mac) == f"{mac}" == "%s" % mac == "00-11-22-AA-BB-CC"
    assert isinstance(MACAddress.try_parse("00:11:22:aa:bb:cc"), MACAddress)


def test_link_local_network_is_the_rfc_3927_range():
    from pydhcp.network import LINK_LOCAL_V4

    assert str(LINK_LOCAL_V4) == "169.254.0.0/16"
    assert IPv4("169.254.1.1") in LINK_LOCAL_V4
    assert IPv4("192.0.2.1") not in LINK_LOCAL_V4


def test_socket_address():
    addr = SocketAddress("127.0.0.1", 8080)
    assert addr.ip == IPv4("127.0.0.1")
    assert addr.port == 8080
    assert addr.compat() == ("127.0.0.1", 8080)
    assert str(addr) == "127.0.0.1:8080"


def test_classless_route():
    from pydhcp.options.type import ClasslessRoute
    from pydhcp.network import IPv4Network

    # 24-bit subnet, router 192.168.1.1, network 192.168.1.0/24
    net = IPv4Network("192.168.1.0/24")
    gw = IPv4("192.168.1.1")
    route = ClasslessRoute(gw, net)

    # Encode
    encoded = route._dhcp_encode()
    # Expect 1 byte mask (24), 3 bytes prefix (192.168.1), 4 bytes router (192.168.1.1)
    assert len(encoded) == 8
    assert encoded[0] == 24
    assert encoded[1:4] == b"\xc0\xa8\x01"  # 192.168.1
    assert encoded[4:] == b"\xc0\xa8\x01\x01"  # 192.168.1.1

    # Decode
    decoded = ClasslessRoute._dhcp_decode(encoded)
    assert decoded.network == net
    assert decoded.gateway == gw
