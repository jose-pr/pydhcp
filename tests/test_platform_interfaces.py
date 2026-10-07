import pytest
from ipaddress import IPv4Address, IPv6Address
from pydhcp import NetworkInterface

# the host-interface enumeration is not public
from pydhcp._network import host_ip_interfaces


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
        iface
        for iface in host_ip_interfaces(filter=False)
        if isinstance(iface.ip, IPv4Address)
    ]
    assert len(ipv4_interfaces) > 0, "Should find at least one IPv4 interface"


def test_graceful_degradation() -> None:
    """Verify that accessing MAC address properties does not crash."""
    for iface in host_ip_interfaces(filter=False):
        # Should not raise even if mac is None
        _ = iface.mac
        assert str(iface)


def test_family_is_given_as_a_number_or_a_socket_constant() -> None:
    import socket

    def addresses(family):
        return sorted(
            str(i.ip) for i in host_ip_interfaces(filter=False, family=family)
        )

    assert addresses(socket.AF_INET) == addresses(4)
    assert addresses(socket.AF_INET6) == addresses(6)
    assert all(isinstance(i.ip, IPv4Address) for i in host_ip_interfaces(family=2))
    assert all(
        isinstance(i.ip, IPv6Address)
        for i in host_ip_interfaces(filter=False, family=socket.AF_INET6)
    )


def _host(fake_adapters):
    import ipaddress

    import netimps

    return fake_adapters(
        netimps.Interface("lo", 1, ips=[ipaddress.IPv4Interface("127.0.0.1/8")]),
        netimps.Interface("eth0", 2, ips=[ipaddress.IPv4Interface("192.168.1.5/24")]),
        netimps.Interface(
            "Wi-Fi 2", 3, ips=[ipaddress.IPv4Interface("169.254.11.89/16")]
        ),
    )


def test_the_default_leaves_out_a_link_local_address(fake_adapters) -> None:
    """RFC 3927 s1.5: 169.254/16 is self-assigned, so it is never served from."""
    _host(fake_adapters)

    assert [str(i.ip) for i in host_ip_interfaces()] == ["127.0.0.1", "192.168.1.5"]


def test_filter_false_lists_a_link_local_address_too(fake_adapters) -> None:
    _host(fake_adapters)

    assert [str(i.ip) for i in host_ip_interfaces(filter=False)] == [
        "127.0.0.1",
        "192.168.1.5",
        "169.254.11.89",
    ]


def test_a_predicate_of_the_callers_replaces_the_default(fake_adapters) -> None:
    _host(fake_adapters)

    named = host_ip_interfaces(lambda ni: ni.name == "Wi-Fi 2")

    assert [str(i.ip) for i in named] == ["169.254.11.89"]
