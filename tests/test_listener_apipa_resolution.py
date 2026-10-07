"""An APIPA-only interface is still an interface (`gap1-posix-pktinfo-12`).

`_resolve_interface` used to match the address against `host_ip_interfaces()`.
That call took the default filter, which excludes APIPA (169.254/16) -- so an
interface holding only a link-local address was absent from the list it
searched and could never be resolved by address. It now asks
`netimps.get_interface`, which does not filter.

Found by a transient `Wi-Fi 2` adapter appearing on the Windows box mid-sweep
and failing a listener test on a docs-only commit. The test helper was made
specific first (`d9aeb1d`); this is the library half.
"""

import netimps
from ipaddress import IPv4Address as IPv4
import ipaddress
import socket

import pytest

from pydhcp import _network as net  # the host-interface enumeration is not public

# the arrival-interface lookup is not public
from pydhcp.listener._interfaces import _resolve_interface

APIPA = ipaddress.IPv4Interface("169.254.11.89/16")


@pytest.fixture
def apipa_only(fake_adapters):
    """A host whose only non-loopback interface is link-local.

    Constructed rather than waiting for the machine to grow one -- which is
    exactly the dependency that made the original failure look like a
    commit regression.
    """
    fake_adapters(
        netimps.Interface("lo", 1, ips=[ipaddress.IPv4Interface("127.0.0.1/8")]),
        netimps.Interface("Wi-Fi 2", 2, ips=[APIPA]),
    )


def _wildcard_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    return sock


def test_an_apipa_only_interface_resolves_by_address(apipa_only) -> None:
    sock = _wildcard_socket()
    try:
        resolved = _resolve_interface(sock, IPv4("169.254.11.89"), None)
    finally:
        sock.close()

    assert resolved.name == "Wi-Fi 2", "fell back to a synthetic interface"
    assert not resolved.name.startswith("unknown[")
    # The prefix is the point: the synthetic fallback produced a /32, which
    # loses the network the server derives its pool and broadcast address from.
    assert resolved.network.prefixlen == 16


def test_the_default_filter_still_hides_apipa_from_serving(apipa_only) -> None:
    """The counterpart: `filter=False` must not leak into address *selection*.

    Which addresses are worth serving from is a different question, and the
    APIPA default belongs there -- a DHCP server should not hand out 169.254/16.
    """
    servable = [str(i.ip) for i in net.host_ip_interfaces(family=None)]
    assert "169.254.11.89" not in servable
    unfiltered = [str(i.ip) for i in net.host_ip_interfaces(filter=False, family=None)]
    assert "169.254.11.89" in unfiltered
