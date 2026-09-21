"""A server does not allocate leases from a link-local network.

RFC 3927 §1.5 excludes 169.254/16 from DHCP assignment: an address in that
range is self-assigned by definition, so handing one out collides with whatever
already picked it.

`host_ip_interfaces(<callable>)` **replaces** its APIPA-excluding default
rather than composing with it — documented behaviour of the enumerator, and it
silently un-filtered the server's serving-interface lookup, which passes a
predicate. Measured: looking up a link-local address returned the adapter
holding it.
"""

import ipaddress
from unittest.mock import Mock

import pytest

from pydhcp import DhcpOptions, NetworkInterface, RequestContext
from pydhcp import network as net
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.network import IPv4, SocketAddress
from pydhcp.options import DhcpOptionCode
from pydhcp.packet import DhcpMessageType
from pydhcp.server import DhcpServer

from conftest import build_request

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
LINK_LOCAL = ipaddress.IPv4Interface("169.254.11.89/16")
ROUTABLE = ipaddress.IPv4Interface("10.0.0.1/24")


@pytest.fixture
def host(monkeypatch):
    """A host holding one link-local address and one routable one."""
    interfaces = [
        NetworkInterface("Wi-Fi 2", LINK_LOCAL),
        NetworkInterface("eth0", ROUTABLE),
    ]

    def fake(filter=True, family=4):
        if filter is True:
            filter = lambda ni: ni.ip not in net.APIPA
        for ni in interfaces:
            if not filter or filter(ni):
                yield ni

    import pydhcp.server as server_module

    monkeypatch.setattr(server_module._net, "host_ip_interfaces", fake)
    monkeypatch.setattr(server_module, "_SERVABLE_INTERFACES", {})
    return interfaces


def _context(interface) -> RequestContext:
    return RequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", interface),
        client=SocketAddress("169.254.11.200", 68),
        client_mac=CHADDR,
    )


def _request(requested: str):
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    options[DhcpOptionCode.REQUESTED_IP] = IPv4(requested)
    return build_request(options=options)


def test_a_link_local_interface_is_not_servable(host) -> None:
    from pydhcp.server import _servable_interface

    assert (
        _servable_interface(IPv4("169.254.11.89")) is None
    ), "the server would allocate from 169.254/16"


def test_a_routable_interface_still_is(host) -> None:
    from pydhcp.server import _servable_interface

    found = _servable_interface(IPv4("10.0.0.1"))
    assert found is not None and found.name == "eth0"


def test_no_lease_is_allocated_from_a_link_local_network(host) -> None:
    server = DhcpServer(lease_backend=InMemoryLeaseBackend())
    msg = _request("169.254.11.200")

    lease = server.acquire_lease(msg.client_id(), IPv4("169.254.11.89"), msg)

    assert lease is None, "allocated a lease from a link-local network"


def test_the_identity_check_still_sees_a_link_local_address(host) -> None:
    """The counterpart: "do we hold this address" is a different question.

    `_is_our_server_id` passes `filter=False` deliberately — a second socket on
    a link-local address is still this host, and treating it as foreign is what
    made a multi-address host delete its own bindings.
    """
    server = DhcpServer(lease_backend=InMemoryLeaseBackend())

    assert server._is_our_server_id(IPv4("169.254.11.89"), IPv4("10.0.0.1")) is True
