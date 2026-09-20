"""RELEASE and DECLINE are verified before they act (`server-31`, `server-14`)."""

import ipaddress
from unittest.mock import Mock

import pytest

from pydhcp import DhcpMessage, DhcpOptions, NetworkInterface, RequestContext
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.network import IPv4, SocketAddress
from pydhcp.options import DhcpOptionCode
from pydhcp.packet import DhcpMessageType
from pydhcp.server import DhcpServer
from conftest import build_request

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
IFACE_A = ipaddress.IPv4Interface("10.0.0.1/24")
IFACE_B = ipaddress.IPv4Interface("10.0.0.2/24")


def _message(
    message_type: DhcpMessageType,
    ciaddr: str = "0.0.0.0",
    server_id: "IPv4 | None" = None,
    requested_ip: "IPv4 | None" = None,
) -> DhcpMessage:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = message_type
    if server_id is not None:
        options[DhcpOptionCode.SERVER_IDENTIFIER] = server_id
    if requested_ip is not None:
        options[DhcpOptionCode.REQUESTED_IP] = requested_ip
    return build_request(options=options, ciaddr=IPv4(ciaddr))


def _context(interface: ipaddress.IPv4Interface) -> RequestContext:
    return RequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", interface),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


@pytest.fixture
def server() -> DhcpServer:
    return DhcpServer(lease_backend=InMemoryLeaseBackend())


def _seed(server: DhcpServer, ip: str = "10.0.0.50") -> str:
    client_id = _message(DhcpMessageType.DHCPREQUEST).client_id()
    server.lease_backend.allocate(client_id, IPv4(ip), 3600.0, DhcpOptions())
    return client_id


def test_release_naming_another_address_is_ignored(server) -> None:
    """A late RELEASE for an old address must not delete the current binding."""
    client_id = _seed(server, "10.0.0.50")
    server.handle_release(
        _message(DhcpMessageType.DHCPRELEASE, ciaddr="10.0.0.99"), _context(IFACE_A)
    )
    assert server.lease_backend.lookup(client_id) is not None
    assert server.metrics.releases_ignored == 1
    assert server.metrics.leases_released == 0


def test_release_for_the_held_address_still_works(server) -> None:
    client_id = _seed(server, "10.0.0.50")
    server.handle_release(
        _message(DhcpMessageType.DHCPRELEASE, ciaddr="10.0.0.50"), _context(IFACE_A)
    )
    assert server.lease_backend.lookup(client_id) is None
    assert server.metrics.leases_released == 1
    assert server.metrics.releases_ignored == 0


def test_decline_counts_as_a_decline_not_a_release(server) -> None:
    """A DECLINE means the address was already in use -- the opposite of a release."""
    _seed(server, "10.0.0.50")
    server.handle_decline(
        _message(DhcpMessageType.DHCPDECLINE, requested_ip=IPv4("10.0.0.50")),
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
    client_id = _seed(server, "10.0.0.50")

    # The client selected address A; this is B's copy of the same broadcast.
    server.handle(
        _message(
            DhcpMessageType.DHCPREQUEST,
            server_id=IPv4("10.0.0.1"),
            requested_ip=IPv4("10.0.0.50"),
        ),
        _context(IFACE_B),
    )
    assert (
        server.lease_backend.lookup(client_id) is not None
    ), "a second address of this same host deleted the binding"


def test_a_genuinely_foreign_server_id_still_reclaims(server, monkeypatch) -> None:
    """The counterpart: choosing another server does give the reservation back.

    Pinned so the fix above is not widened into "never reclaim", which would
    leak a reservation for every client that picked a different server.
    """
    import pydhcp.server as server_module

    monkeypatch.setattr(
        server_module._net,
        "host_ip_interfaces",
        lambda *a, **k: iter([NetworkInterface("eth0", IFACE_A)]),
    )
    client_id = _seed(server, "10.0.0.50")

    server.handle(
        _message(
            DhcpMessageType.DHCPREQUEST,
            server_id=IPv4("192.0.2.77"),
            requested_ip=IPv4("10.0.0.50"),
        ),
        _context(IFACE_A),
    )
    assert server.lease_backend.lookup(client_id) is None
    assert server.metrics.leases_released == 1
