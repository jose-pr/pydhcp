"""RELEASE and DECLINE are verified before they act (`server-31`, `server-14`)."""

import ipaddress
from unittest.mock import Mock

import pytest

from pydhcp import DHCPMessage, DHCPOptions, NetworkInterface, DHCPRequestContext
from pydhcp.lease import InMemoryLeaseBackend
from ipaddress import IPv4Address as IPv4
from pydhcp import SocketAddress
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
from pydhcp.server import DHCPServer
from conftest import build_request

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
IFACE_A = ipaddress.IPv4Interface("10.0.0.1/24")
IFACE_B = ipaddress.IPv4Interface("10.0.0.2/24")


def _message(
    message_type: DHCPMessageType,
    ciaddr: str = "0.0.0.0",
    server_id: "IPv4 | None" = None,
    requested_ip: "IPv4 | None" = None,
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = message_type
    if server_id is not None:
        options[DHCPOptionCode.SERVER_IDENTIFIER] = server_id
    if requested_ip is not None:
        options[DHCPOptionCode.REQUESTED_IP] = requested_ip
    return build_request(options=options, ciaddr=IPv4(ciaddr))


def _context(interface: ipaddress.IPv4Interface) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", interface),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


@pytest.fixture
def server() -> DHCPServer:
    return DHCPServer(lease_backend=InMemoryLeaseBackend())


def _seed(server: DHCPServer, ip: str = "10.0.0.50") -> str:
    client_id = _message(DHCPMessageType.DHCPREQUEST).get_client_id()
    server.lease_backend.allocate(client_id, IPv4(ip), 3600.0, DHCPOptions())
    return client_id


def test_release_naming_another_address_is_ignored(server) -> None:
    """A late RELEASE for an old address must not delete the current binding."""
    client_id = _seed(server, "10.0.0.50")
    server.handle_release(
        _message(DHCPMessageType.DHCPRELEASE, ciaddr="10.0.0.99"), _context(IFACE_A)
    )
    assert server.lease_backend.lookup(client_id) is not None
    assert server.metrics.releases_ignored == 1
    assert server.metrics.leases_released == 0


def test_release_for_the_held_address_still_works(server) -> None:
    client_id = _seed(server, "10.0.0.50")
    server.handle_release(
        _message(DHCPMessageType.DHCPRELEASE, ciaddr="10.0.0.50"), _context(IFACE_A)
    )
    assert server.lease_backend.lookup(client_id) is None
    assert server.metrics.leases_released == 1
    assert server.metrics.releases_ignored == 0


def test_decline_counts_as_a_decline_not_a_release(server) -> None:
    """A DECLINE means the address was already in use -- the opposite of a release."""
    _seed(server, "10.0.0.50")
    server.handle_decline(
        _message(DHCPMessageType.DHCPDECLINE, requested_ip=IPv4("10.0.0.50")),
        _context(IFACE_A),
    )
    assert server.metrics.leases_declined == 1
    assert server.metrics.leases_released == 0


def test_a_second_address_of_this_host_does_not_delete_the_binding(
    server, monkeypatch
) -> None:
    """`server-14`: two sockets on one broadcast domain, one shared backend.

    Socket A ACKs the REQUEST; socket B receives the same broadcast, reads
    option 54 as a foreign server and used to delete the binding the client had
    just accepted -- freeing the address while the client was using it.
    """
    import pydhcp.server as server_module

    monkeypatch.setattr(
        server_module._net,
        "host_ip_interfaces",
        lambda *a, **k: iter(
            [NetworkInterface("eth0", IFACE_A), NetworkInterface("eth1", IFACE_B)]
        ),
    )
    monkeypatch.setattr(
        server_module._netimps,
        "is_local_address",
        lambda address, **_kw: address in {IFACE_A.ip, IFACE_B.ip},
    )
    client_id = _seed(server, "10.0.0.50")

    # The client selected address A; this is B's copy of the same broadcast.
    server.handle(
        _message(
            DHCPMessageType.DHCPREQUEST,
            server_id=IPv4("10.0.0.1"),
            requested_ip=IPv4("10.0.0.50"),
        ),
        _context(IFACE_B),
    )
    assert (
        server.lease_backend.lookup(client_id) is not None
    ), "a second address of this same host deleted the binding"


def test_the_identity_check_asks_the_real_host(server) -> None:
    """Unmocked: loopback is this host and a TEST-NET-3 address (RFC 5737) is
    not, whatever this machine's adapters hold."""
    assert server._is_our_server_id(IPv4("127.0.0.1"), IPv4("10.255.0.1")) is True
    assert server._is_our_server_id(IPv4("203.0.113.77"), IPv4("10.255.0.1")) is False


def _foreign_request(server, monkeypatch) -> str:
    """Seed nothing; send a REQUEST that names a server that is not this host."""
    import pydhcp.server as server_module

    monkeypatch.setattr(
        server_module._net,
        "host_ip_interfaces",
        lambda *a, **k: iter([NetworkInterface("eth0", IFACE_A)]),
    )
    monkeypatch.setattr(
        server_module._netimps,
        "is_local_address",
        lambda address, **_kw: address == IFACE_A.ip,
    )
    request = _message(
        DHCPMessageType.DHCPREQUEST,
        server_id=IPv4("192.0.2.77"),
        requested_ip=IPv4("10.0.0.50"),
    )
    server.handle(request, _context(IFACE_A))
    return request.get_client_id()


def test_a_request_naming_another_server_gives_back_the_offer(
    server, monkeypatch
) -> None:
    """RFC 2131 s4.3.2: the client chose another server, so the address held for
    it by an offer is released. Pinned so the fix above is not widened into
    "never reclaim", which would hold an address for every client that picked a
    different server."""
    client_id = _message(DHCPMessageType.DHCPREQUEST).get_client_id()
    held = server.lease_backend.offer(client_id, IPv4("10.0.0.50"), 120.0)
    assert held is not None and held.offered

    assert _foreign_request(server, monkeypatch) == client_id

    assert server.lease_backend.lookup(client_id) is None
    assert server.metrics.offers_withdrawn == 1
    assert server.metrics.leases_released == 0


def test_a_request_naming_another_server_keeps_a_binding(server, monkeypatch) -> None:
    """A binding the client accepted is not the sender's to cancel: the server
    identifier of a REQUEST is unauthenticated, and anyone can name another
    server for someone else's client identifier."""
    client_id = _seed(server, "10.0.0.50")

    _foreign_request(server, monkeypatch)

    kept = server.lease_backend.lookup(client_id)
    assert kept is not None and not kept.offered
    assert server.metrics.offers_withdrawn == 0
    assert server.metrics.leases_released == 0
