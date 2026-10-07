"""Host-address lookups cost at most one adapter enumeration per second.

`server-15`: `acquire_lease` and `get_inform_options` each enumerated every
host adapter for every packet, to answer a question whose answer only changes
when the host's addresses do. Measured on this box before any cache:

    host_ip_interfaces(), the server's filtered form   1181 us
    DHCPServer.handle() on a DHCPDISCOVER              1539 us   (77% of it)
    DHCPServer.handle() on a DHCPINFORM                1497 us

pydhcp first fixed that with its own per-bind caches; they are now netimps'
enumeration cache (`cache=True`, a one-second TTL), which a bind also clears.
These tests count real enumerations through the `enumerations` fixture -- a
lookup is not the cost, the enumeration behind it is. It must come *after*
`served_interface` in a test's parameters: pytest sets fixtures up in that
order, and the host lookup that fixture makes would otherwise be counted.
"""

from __future__ import annotations

import netimps
from ipaddress import IPv4Address as IPv4
import ipaddress

import pytest

from helpers import build_request

# private: the unit under test is not exported from a public module
from pydhcp import _network as net  # the host-interface enumeration is not public
from pydhcp import server as server_module
from pydhcp.listener import (
    AsyncDHCPListener,
    DHCPListener,
    DHCPRequestContext,
    DHCPTransport,
)
from pydhcp.options import DHCPOptionCode, DHCPOptions
from pydhcp.packet import DHCPMessageType
from pydhcp.server import DHCPServer


class Silent(DHCPTransport):
    """A transport that accepts everything and sends nothing."""

    def __init__(self) -> None:
        self.sent: list = []

    def send(self, data, dst, port, client_mac) -> int:
        self.sent.append((dst, port))
        return len(data)


@pytest.fixture
def served_interface():
    """A real host interface this server would be willing to serve from."""
    for interface in net.host_ip_interfaces():
        if not interface.ip.is_loopback and interface.network.prefixlen < 31:
            return interface
    pytest.skip("no non-loopback IPv4 interface to serve from")


def _context(interface) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Silent(),
        interface=interface,
        client=net.SocketAddress(IPv4("0.0.0.0"), 68),
        client_mac=b"\x00\x11\x22\x33\x44\x55",
    )


def test_twenty_packets_cost_at_most_one_enumeration(
    served_interface, enumerations
) -> None:
    """It used to be twenty: one full enumeration per DISCOVER."""
    server = DHCPServer(listen=("127.0.0.1", 0))
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    options[DHCPOptionCode.REQUESTED_IP] = IPv4(
        str(list(served_interface.network.hosts())[5])
    )
    context = _context(served_interface)

    for _ in range(20):
        server.handle(build_request(options=options), context)

    assert len(enumerations) <= 1, f"enumerated {len(enumerations)} times for 20"


def test_a_second_dhcpinform_enumerates_nothing(served_interface, enumerations) -> None:
    """The finding recorded two enumerations per DHCPINFORM. Measured, it was
    one -- and the second packet now costs none."""
    server = DHCPServer(listen=("127.0.0.1", 0))
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPINFORM
    context = _context(served_interface)
    inform = build_request(options=options, ciaddr=IPv4(str(served_interface.ip)))

    server.handle(inform, context)
    first = len(enumerations)
    server.handle(inform, context)

    assert first <= 1
    assert len(enumerations) == first, "the second packet enumerated again"


def test_binding_forces_a_fresh_enumeration(enumerations) -> None:
    """The host's addresses can change, and binding is when pydhcp knows it
    might have: the next lookup must not be answered from before the bind."""
    import netimps

    netimps.get_interface(IPv4("127.0.0.1"), cache=True)
    netimps.get_interface(IPv4("127.0.0.1"), cache=True)
    assert len(enumerations) == 1, "the cache did not hold"

    DHCPListener(listen=("127.0.0.1", 0)).__enter__().close()
    netimps.get_interface(IPv4("127.0.0.1"), cache=True)

    assert len(enumerations) == 2, "bind() left the old enumeration in place"


def test_an_async_bind_forces_it_too(enumerations) -> None:
    """`AsyncDHCPServer`'s MRO resolves `bind()` to `AsyncDHCPListener`, so an
    invalidation hung off `DHCPServer.bind` would never have run for it."""
    import netimps

    netimps.get_interface(IPv4("127.0.0.1"), cache=True)
    listener = AsyncDHCPListener(listen=("127.0.0.1", 0))
    listener.bind()
    try:
        netimps.get_interface(IPv4("127.0.0.1"), cache=True)
        assert len(enumerations) == 2
    finally:
        # private: the release path, called directly
        listener._close_sockets()


def test_a_synthetic_interface_is_still_refused() -> None:
    """Why the servable lookup is not answered from `context.interface`.

    `_resolve_interface` never returns None -- it invents `unknown[<ip>]` with
    a /32 and no MAC when nothing matches, and the base allocator reads
    SUBNET_MASK and BROADCAST_ADDRESS off the interface's network. Handing that
    to a client means a 255.255.255.255 subnet mask. The lookup returns None
    for an address no adapter holds, and the server stays silent.
    """
    synthetic = net.NetworkInterface(
        "unknown[203.0.113.9]", ipaddress.IPv4Interface("203.0.113.9/32")
    )
    server = DHCPServer(listen=("127.0.0.1", 0))
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    options[DHCPOptionCode.REQUESTED_IP] = IPv4("203.0.113.20")

    transport = Silent()
    context = DHCPRequestContext(
        transport=transport,
        interface=synthetic,
        client=net.SocketAddress(IPv4("0.0.0.0"), 68),
        client_mac=b"\x00\x11\x22\x33\x44\x55",
    )

    server.handle(build_request(options=options), context)
    server.handle(build_request(options=options), context)

    assert transport.sent == [], "offered a lease from an address we do not hold"
    # private: the host's adapters decide the pool: a fabricated interface stands for one
    assert server_module._servable_interface(IPv4("203.0.113.9")) is None


def test_the_lookup_does_not_apply_the_apipa_filter(monkeypatch) -> None:
    """Measured, not assumed: `host_ip_interfaces(<callable>)` *replaces* the
    default predicate rather than composing with it, so `_servable_interface`
    spells the APIPA exclusion out itself -- and the enumerator it calls must
    not filter on its own. Pinned so the caching change can be seen to have
    preserved that.

    (`test_the_default_filter_still_hides_apipa_from_serving` in
    `test_listener_apipa_resolution.py` pins the *intent*; this pins what the
    enumerator is asked.)
    """
    apipa = net.NetworkInterface("Wi-Fi 2", ipaddress.IPv4Interface("169.254.11.89/16"))
    seen: list = []

    def fake(filter=True, family=4, *, cache=False):
        seen.append(cache)
        return iter([apipa] if not filter or filter(apipa) else [])

    # private: the module's own name for the host enumeration, replaced to stand for a host
    monkeypatch.setattr(server_module._net, "host_ip_interfaces", fake)

    # The predicate excludes APIPA, so nothing is servable...
    assert server_module._servable_interface(IPv4("169.254.11.89")) is None
    # ...and the lookup went through netimps' cache.
    assert seen == [True]
