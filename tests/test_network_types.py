"""What `pydhcp.network` keeps: pydhcp's own types, and nothing of netimps' or
the standard library's under another door."""

from __future__ import annotations

import ipaddress

import netimps

from pydhcp import network
from pydhcp.network import NetworkInterface, SocketAddress
from pydhcp.listener.interfaces import _network_interface


def test_network_holds_only_pydhcps_own_names() -> None:
    public = {
        name
        for name in vars(network)
        if not name.startswith("_") and name != "annotations"
    }

    assert public == {
        "HardwareAddressType",
        "NetworkInterface",
        "SocketAddress",
        "host_ip_interfaces",
    }


def test_a_socket_address_does_not_bind_a_socket() -> None:
    """Binding is `netimps.bind`'s, called by the listener."""
    assert not hasattr(SocketAddress, "listen")


def test_a_network_interface_carries_netimps_hardware_address() -> None:
    mac = netimps.MACAddress("00:11:22:33:44:55")
    interface = NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.5/24"), mac)

    assert interface.mac is mac
    assert mac.format("-", upper=True) == "00-11-22-33-44-55"


def test_an_adapter_with_loopback_and_routable_addresses_resolves_to_the_routable() -> (
    None
):
    """`Interface.primary_ip()` ranks routable, then loopback, then link-local.
    The choice made here before took the first address that was not link-local
    in the adapter's own order, which on an adapter listing 127.0.0.1 first was
    the loopback address."""
    adapter = netimps.Interface(
        "lo",
        1,
        ips=[
            ipaddress.IPv4Interface("127.0.0.1/8"),
            ipaddress.IPv4Interface("169.254.1.1/16"),
            ipaddress.IPv4Interface("10.0.0.5/24"),
        ],
    )

    found = _network_interface(adapter)

    assert found is not None
    assert str(found.ip) == "10.0.0.5"


def test_a_loopback_only_adapter_resolves_to_loopback() -> None:
    adapter = netimps.Interface("lo", 1, ips=[ipaddress.IPv4Interface("127.0.0.1/8")])

    found = _network_interface(adapter)

    assert found is not None
    assert str(found.ip) == "127.0.0.1"
