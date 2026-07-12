import pytest
from ipaddress import IPv4Address, IPv6Address
from pydhcp.netutils import host_ip_interfaces, NetworkInterface

def test_pure_python_interfaces() -> None:
    """Verify interfaces enumerate and have required attributes."""
    interfaces = list(host_ip_interfaces(filter=False))
    assert len(interfaces) > 0, "At least one interface should be enumerated"
    
    for iface in interfaces:
        assert isinstance(iface, NetworkInterface)
        assert iface.name, "Interface name must not be empty"
        assert iface.ip_interface, "IP interface must be present"
        assert isinstance(iface.ip, (IPv4Address, IPv6Address))

def test_ipv4_addresses_present() -> None:
    """Verify that at least one IPv4 interface is found."""
    ipv4_interfaces = [
        iface for iface in host_ip_interfaces(filter=False)
        if isinstance(iface.ip, IPv4Address)
    ]
    assert len(ipv4_interfaces) > 0, "Should find at least one IPv4 interface"

def test_graceful_degradation() -> None:
    """Verify that accessing MAC address properties does not crash."""
    for iface in host_ip_interfaces(filter=False):
        # Should not raise even if mac is None
        _ = iface.mac
        assert str(iface)
