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

import netimps
import ipaddress
from unittest.mock import Mock

import pytest

from pydhcp import DHCPOptions, NetworkInterface, DHCPRequestContext
from pydhcp.lease import InMemoryLeaseBackend
from ipaddress import IPv4Address as IPv4
from pydhcp import SocketAddress
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
from pydhcp.server import DHCPServer

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

    def fake(filter=True, family=4, *, cache=False):
        if filter is True:
            filter = lambda ni: ni.ip not in netimps.LINK_LOCAL_V4
        for ni in interfaces:
            if not filter or filter(ni):
                yield ni

    import pydhcp.server as server_module

    monkeypatch.setattr(server_module._net, "host_ip_interfaces", fake)
    # The identity question ("do we hold this address") is netimps', and it
    # answers from the same fake host: link-local included, unfiltered.
    held = {ni.ip for ni in interfaces}
    monkeypatch.setattr(
        server_module._netimps,
        "is_local_address",
        lambda address, **_kw: address in held,
    )
    return interfaces


def _context(interface) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", interface),
        client=SocketAddress("169.254.11.200", 68),
        client_mac=CHADDR,
    )


def _request(requested: str):
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    options[DHCPOptionCode.REQUESTED_IP] = IPv4(requested)
    return build_request(options=options)


def test_a_link_local_interface_is_not_servable(host) -> None:
    # the server's lease-selection helper is not public
    from pydhcp.server.policy import _servable_interface

    assert (
        _servable_interface(IPv4("169.254.11.89")) is None
    ), "the server would allocate from 169.254/16"


def test_a_routable_interface_still_is(host) -> None:
    # the server's lease-selection helper is not public
    from pydhcp.server.policy import _servable_interface

    found = _servable_interface(IPv4("10.0.0.1"))
    assert found is not None and found.name == "eth0"


def test_no_lease_is_allocated_from_a_link_local_network(host) -> None:
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())
    msg = _request("169.254.11.200")

    lease = server.acquire_lease(msg.client_id(), IPv4("169.254.11.89"), msg)

    assert lease is None, "allocated a lease from a link-local network"


def test_the_identity_check_still_sees_a_link_local_address(host) -> None:
    """The counterpart: "do we hold this address" is a different question.

    `_is_our_server_id` asks `netimps.is_local_address`, which does not filter
    link-local — a second socket on a link-local address is still this host,
    and treating it as foreign is what made a multi-address host delete its own
    bindings.
    """
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())

    assert server._is_our_server_id(IPv4("169.254.11.89"), IPv4("10.0.0.1")) is True
