import ipaddress

from pydhcp.listener import _parselisteners
from pydhcp.network import IPv4, NetworkInterface, SocketAddress
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


# --- IP_PKTINFO interface resolution ---
#
# The pktinfo receive path only runs on a wildcard bind, where getsockname()
# reports 0.0.0.0. Resolving the interface from the socket there yields a
# synthetic unknown[0.0.0.0], which the server turns into SERVER_IDENTIFIER
# 0.0.0.0 and the relay into giaddr 0.0.0.0 -- i.e. the library's default
# configuration is non-functional on POSIX. These tests pin the resolution
# itself, which needs no recvmsg support and so runs on every platform.


def _wildcard_socket():
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    return sock


def _a_real_interface():
    import pytest

    from pydhcp.network import _iter_indexed_interfaces

    for index, interface in _iter_indexed_interfaces(family=4):
        if index and not interface.ip.is_loopback:
            return index, interface
    pytest.skip("no non-loopback IPv4 interface with a usable index on this host")


def test_resolve_interface_prefers_pktinfo_over_getsockname() -> None:
    from pydhcp.listener import _resolve_interface

    index, expected = _a_real_interface()
    sock = _wildcard_socket()
    try:
        resolved = _resolve_interface(sock, expected.ip, index)
    finally:
        sock.close()

    assert resolved.ip == expected.ip
    assert resolved.name == expected.name
    assert not resolved.name.startswith("unknown["), (
        "fell back to a synthetic interface despite valid pktinfo data"
    )


def test_resolve_interface_without_pktinfo_still_falls_back() -> None:
    """Unchanged behaviour for the address-bound receive path."""
    from pydhcp.listener import _resolve_interface

    sock = _wildcard_socket()
    try:
        resolved = _resolve_interface(sock)
    finally:
        sock.close()

    assert resolved.name == "unknown[0.0.0.0]"


def test_resolve_interface_falls_back_to_address_when_index_is_unknown() -> None:
    """A stale or unmatched ifindex must not lose an otherwise valid address."""
    from pydhcp.listener import _resolve_interface

    _index, expected = _a_real_interface()
    sock = _wildcard_socket()
    try:
        resolved = _resolve_interface(sock, expected.ip, 99999)
    finally:
        sock.close()

    assert resolved.ip == expected.ip
    assert resolved.name == expected.name
