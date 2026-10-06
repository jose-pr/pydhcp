import ipaddress

import pytest

from pydhcp.listener import DHCPListener, _parselisteners
from ipaddress import IPv4Address as IPv4
from pydhcp.network import NetworkInterface, SocketAddress
from pydhcp.server import AsyncDHCPServer, DHCPServer


def test_parse_single_tuple() -> None:
    assert _parselisteners(("127.0.0.1", 6767)) == [SocketAddress("127.0.0.1", 6767)]


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
    monkeypatch.setattr("pydhcp.network.host_ip_interfaces", lambda: iter(interfaces))

    assert _parselisteners("*", (67,)) == [
        SocketAddress("192.0.2.10", 67),
        SocketAddress("198.51.100.10", 67),
    ]


def test_parse_string_host_with_default_port() -> None:
    assert _parselisteners("127.0.0.1", (6767,)) == [SocketAddress("127.0.0.1", 6767)]


def test_parse_host_port_string() -> None:
    assert _parselisteners("127.0.0.1:6767") == [SocketAddress("127.0.0.1", 6767)]


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


@pytest.mark.parametrize(
    "listen, message",
    [
        ("127.0.0.1:+6767", "invalid port"),
        ("127.0.0.1: 6767", "invalid port"),
        ("127.0.0.1:8_0", "invalid port"),
        ("[127.0.0.1]:6767", "bracketed but not an IPv6 address"),
        (("127.0.0.1:+6767", 67), "invalid port"),
    ],
)
@pytest.mark.parametrize("per_interface", [False, True])
def test_a_malformed_port_or_bracket_is_named_as_such(
    listen, message, per_interface
) -> None:
    """A port that is not ASCII digits, and brackets around an IPv4 address,
    are refused, and the message blames the port or the brackets, not the
    address -- on the wildcard-detecting path and on the per-interface one."""
    with pytest.raises(ValueError, match=message):
        DHCPListener(listen=listen, per_interface=per_interface)


@pytest.mark.parametrize("listen", ["localhost:6767", "eth0", ("localhost", 6767)])
@pytest.mark.parametrize("per_interface", [False, True])
def test_a_host_name_is_refused_as_not_an_ipv4_address(listen, per_interface) -> None:
    """`listen` takes addresses; a name is not one, and both paths say so in the
    same words (`ipaddress`'s), not a wildcard-detection error."""
    with pytest.raises(ipaddress.AddressValueError, match="Expected 4 octets"):
        DHCPListener(listen=listen, per_interface=per_interface)


@pytest.mark.parametrize(
    "listen", ["*", "*:6767", ":6767", "0.0.0.0:6767", "127.0.0.1:6767"]
)
def test_the_listen_forms_that_stay_valid(listen) -> None:
    DHCPListener(listen=listen)


def test_server_constructors_accept_per_interface_and_multiple_endpoints() -> None:
    listen = [("127.0.0.1", [6767, 6768])]

    server = DHCPServer(listen=listen, per_interface=True)
    async_server = AsyncDHCPServer(listen=listen, per_interface=True)

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
    """A non-loopback adapter with an index and a routable IPv4 address.

    Not simply "the first non-loopback one with an index": this box grows and
    drops transient `Wi-Fi 2/3/4` adapters holding only link-local (APIPA,
    169.254.0.0/16) addresses, and one appearing at the head of the list once
    made a test fail mid-sweep on a docs-only commit. APIPA resolution has its
    own test with a constructed host.
    """
    import netimps
    import pytest

    from netimps import LINK_LOCAL_V4

    for adapter in netimps.get_interfaces():
        if not adapter.index or adapter.is_loopback:
            continue
        for entry in adapter.ips:
            if (
                isinstance(entry, ipaddress.IPv4Interface)
                and entry.ip not in LINK_LOCAL_V4
            ):
                return adapter.index, NetworkInterface(adapter.name, entry)
    pytest.skip("no non-loopback adapter with a routable IPv4 address")


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
    assert not resolved.name.startswith(
        "unknown["
    ), "fell back to a synthetic interface despite valid pktinfo data"


def test_resolve_interface_without_pktinfo_still_falls_back() -> None:
    """Unchanged behaviour for the address-bound receive path."""
    from pydhcp.listener import _resolve_interface

    sock = _wildcard_socket()
    try:
        resolved = _resolve_interface(sock)
    finally:
        sock.close()

    assert resolved.name == "unknown[0.0.0.0]"


def test_resolve_interface_by_index_alone_answers_from_the_adapter() -> None:
    """No address to match -- a zero-filled or missing local address -- so the
    index picks the adapter and its own routable address answers."""
    import netimps

    from pydhcp.listener import _resolve_interface

    index, expected = _a_real_interface()
    netimps.clear_interface_cache()
    sock = _wildcard_socket()
    try:
        resolved = _resolve_interface(sock, IPv4("0.0.0.0"), index)
    finally:
        sock.close()

    assert resolved.name == expected.name
    assert not resolved.name.startswith("unknown[")
    assert resolved.ip not in netimps.LINK_LOCAL_V4


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


# --- Lifecycle: sockets, the SIGINT handler, and the interface cache ---


def test_close_releases_every_bound_socket() -> None:
    """stop() only ends the receive loop. Without close(), a process creating a
    listener per operation leaks a bound UDP socket and its port each time."""
    from pydhcp.listener import DHCPListener

    listener = DHCPListener(listen=("127.0.0.1", 0))
    listener.bind()
    # The private list on purpose: the claim is that the OS sockets were
    # *closed*, which `bound_addresses` cannot express -- it reports addresses,
    # and a closed socket simply stops appearing.
    sockets = list(listener._sockets)
    assert sockets

    listener.close()

    assert listener.bound_addresses == ()
    for sock in sockets:
        assert sock.fileno() == -1


def test_listener_is_a_context_manager() -> None:
    from pydhcp.listener import DHCPListener

    with DHCPListener(listen=("127.0.0.1", 0)) as listener:
        assert listener.bound_addresses
        sockets = list(listener._sockets)  # see above: closed-ness, not addresses

    assert listener.bound_addresses == ()
    for sock in sockets:
        assert sock.fileno() == -1


def test_start_off_the_main_thread_does_not_wedge_the_listener() -> None:
    """signal.signal raises off the main thread. It used to do so after the
    cancellation token was set, leaving the listener permanently 'started'."""
    import threading

    from pydhcp.listener import DHCPListener

    listener = DHCPListener(listen=("127.0.0.1", 0))
    listener._select_timeout = 0.05
    result = {}

    def run() -> None:
        try:
            result["thread"] = listener.start()
        except Exception as exc:  # pragma: no cover - the bug being pinned
            result["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    worker.join(5)

    assert "error" not in result, result.get("error")
    assert result["thread"] is not None
    listener.stop()
    result["thread"].join(5)
    assert not result["thread"].is_alive()
    listener.close()


def test_start_restores_the_previous_sigint_handler_on_close() -> None:
    """Library code must not keep a process-wide handler after it is done."""
    import signal

    from pydhcp.listener import DHCPListener

    original = signal.getsignal(signal.SIGINT)
    listener = DHCPListener(listen=("127.0.0.1", 0))
    listener._select_timeout = 0.05
    thread = listener.start()
    assert thread is not None
    assert signal.getsignal(signal.SIGINT) is not original

    listener.stop()
    thread.join(5)
    listener.close()

    assert signal.getsignal(signal.SIGINT) is original


def test_interface_resolution_is_cached_and_cleared_by_bind(enumerations) -> None:
    """Enumerating every host adapter per datagram was expensive enough that a
    modest flood denied service on its own. Twenty-five datagrams' worth of
    resolution now costs one enumeration, and a bind forces the next."""
    import socket

    from pydhcp.listener import DHCPListener, _resolve_interface

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    try:
        for _ in range(25):
            _resolve_interface(sock)
        assert len(enumerations) == 1, "resolution was not cached"

        DHCPListener(listen=("127.0.0.1", 0)).__enter__().close()
        _resolve_interface(sock)
        assert len(enumerations) == 2, "a bind did not force a re-enumeration"
    finally:
        sock.close()


def test_bound_addresses_reports_the_ephemeral_port() -> None:
    """Binding port 0 gives a port only the socket knows.

    Without a public accessor the only way to learn it was to reach into the
    private `_sockets` list, which the suite did in twenty-one places -- and
    which anyone writing a test or a tool against pydhcp had to do too.
    """
    from pydhcp.listener import DHCPListener

    listener = DHCPListener(listen=("127.0.0.1", 0))
    assert listener.bound_addresses == ()

    listener.bind()
    try:
        addresses = listener.bound_addresses
        assert len(addresses) == 1
        assert str(addresses[0].ip) == "127.0.0.1"
        assert addresses[0].port != 0, "the ephemeral port was not reported"
    finally:
        listener.close()

    assert listener.bound_addresses == ()
