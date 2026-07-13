import ipaddress

from pydhcp.listener import _parselisteners
from pydhcp.netutils import IPv4, NetworkInterface, SocketAddress
from pydhcp.server import AsyncDhcpServer, DhcpServer


def test_parse_single_tuple() -> None:
    assert _parselisteners(("127.0.0.1", 6767)) == [
        SocketAddress("127.0.0.1", 6767)
    ]


def test_parse_list_of_tuples_preserves_order_and_deduplicates() -> None:
    assert _parselisteners(
        [
            ("127.0.0.1", 6767),
            ("127.0.0.1", 6767),
            ("127.0.0.1", 6768),
        ]
    ) == [
        SocketAddress("127.0.0.1", 6767),
        SocketAddress("127.0.0.1", 6768),
    ]


def test_parse_wildcard_expands_ipv4_interfaces(monkeypatch) -> None:
    interfaces = [
        NetworkInterface("eth0", ipaddress.IPv4Interface("192.0.2.10/24")),
        NetworkInterface("eth1", ipaddress.IPv4Interface("198.51.100.10/24")),
    ]
    monkeypatch.setattr("pydhcp.listener._net.host_ip_interfaces", lambda: iter(interfaces))

    assert _parselisteners("*", (67,)) == [
        SocketAddress("192.0.2.10", 67),
        SocketAddress("198.51.100.10", 67),
    ]


def test_parse_string_host_with_default_port() -> None:
    assert _parselisteners("127.0.0.1", (6767,)) == [
        SocketAddress("127.0.0.1", 6767)
    ]


def test_parse_host_port_string() -> None:
    assert _parselisteners("127.0.0.1:6767") == [
        SocketAddress("127.0.0.1", 6767)
    ]


def test_parse_comma_separated_host_port_string() -> None:
    assert _parselisteners("127.0.0.1:6767,127.0.0.1:6768") == [
        SocketAddress("127.0.0.1", 6767),
        SocketAddress("127.0.0.1", 6768),
    ]


def test_parse_multi_port_tuple() -> None:
    assert _parselisteners(("127.0.0.1", [6767, 6768])) == [
        SocketAddress("127.0.0.1", 6767),
        SocketAddress("127.0.0.1", 6768),
    ]


def test_server_constructors_accept_per_interface_and_multiple_endpoints() -> None:
    listen = [("127.0.0.1", [6767, 6768])]

    server = DhcpServer(listen=listen, per_interface=True)
    async_server = AsyncDhcpServer(listen=listen, per_interface=True)

    expected = [
        SocketAddress("127.0.0.1", 6767),
        SocketAddress("127.0.0.1", 6768),
    ]
    assert server._listen == expected
    assert async_server._listen == expected
