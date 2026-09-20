"""Host-address lookups are answered once per bind, not once per packet.

`server-15`: `acquire_lease` and `get_inform_options` each enumerated every
host adapter for every packet, to answer a question whose answer only changes
when the host's addresses do. Measured on this box before the fix:

    host_ip_interfaces(), the server's filtered form   1181 us
    DhcpServer.handle() on a DHCPDISCOVER              1539 us   (77% of it)
    DhcpServer.handle() on a DHCPINFORM                1497 us

and afterwards 148 us and 136 us. (The finding claimed DHCPINFORM enumerated
twice; measured, it is once -- see `test_..._exactly_once`.)

The cache lives in `server.py` but is invalidated from `listener.py`, so the
tests for both halves are here.
"""

from __future__ import annotations

import ipaddress

import pytest

from conftest import build_request
from pydhcp import listener as listener_module
from pydhcp import network as net
from pydhcp import server as server_module
from pydhcp.listener import DhcpListener, RequestContext, Transport
from pydhcp.options import DhcpOptionCode, DhcpOptions
from pydhcp.packet import DhcpMessageType
from pydhcp.server import DhcpServer


class Silent(Transport):
    """A transport that accepts everything and sends nothing."""

    def __init__(self) -> None:
        self.sent: list = []

    def send(self, data, dest, port, client_mac) -> int:
        self.sent.append((dest, port))
        return len(data)


@pytest.fixture
def served_interface():
    """A real host interface this server would be willing to serve from."""
    for interface in net.host_ip_interfaces():
        if not interface.ip.is_loopback and interface.network.prefixlen < 31:
            return interface
    pytest.skip("no non-loopback IPv4 interface to serve from")


def _context(interface) -> RequestContext:
    return RequestContext(
        transport=Silent(),
        interface=interface,
        client=net.SocketAddress(net.IPv4("0.0.0.0"), 68),
        client_mac=b"\x00\x11\x22\x33\x44\x55",
    )


def _counted(monkeypatch) -> list:
    calls: list = []
    original = net.host_ip_interfaces

    def counting(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(server_module._net, "host_ip_interfaces", counting)
    return calls


def test_the_server_enumerates_host_adapters_at_most_once_per_address(
    monkeypatch, served_interface
) -> None:
    """Twenty packets, one enumeration. It used to be twenty."""
    # getattr: the cache is part of the fix, and this test has to reach its own
    # assertion -- not an AttributeError -- against a server without one.
    getattr(server_module, "_SERVABLE_INTERFACES", {}).clear()
    calls = _counted(monkeypatch)

    server = DhcpServer(listen=("127.0.0.1", 0))
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    options[DhcpOptionCode.REQUESTED_IP] = net.IPv4(
        str(list(served_interface.network.hosts())[5])
    )
    context = _context(served_interface)

    for _ in range(20):
        server.handle(build_request(options=options), context)

    assert len(calls) == 1, f"enumerated {len(calls)} times for 20 packets"


def test_a_dhcpinform_enumerates_exactly_once(monkeypatch, served_interface) -> None:
    """The finding recorded two enumerations per DHCPINFORM. Measured, it is
    one -- and now zero after the first packet."""
    getattr(server_module, "_SERVABLE_INTERFACES", {}).clear()
    calls = _counted(monkeypatch)

    server = DhcpServer(listen=("127.0.0.1", 0))
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPINFORM
    context = _context(served_interface)

    server.handle(
        build_request(options=options, ciaddr=net.IPv4(str(served_interface.ip))),
        context,
    )
    assert len(calls) == 1

    server.handle(
        build_request(options=options, ciaddr=net.IPv4(str(served_interface.ip))),
        context,
    )
    assert len(calls) == 1, "the second packet enumerated again"


def test_binding_drops_the_cached_answer() -> None:
    """The host's addresses can change, and binding is when that is noticed --
    the same invalidation point `listener._INTERFACE_CACHE` already uses."""
    server_module._SERVABLE_INTERFACES[net.IPv4("192.0.2.1")] = None
    listener_module._INTERFACE_CACHE[(0, "192.0.2.1")] = None  # type: ignore[assignment]

    DhcpListener(listen=("127.0.0.1", 0)).__enter__().close()

    assert server_module._SERVABLE_INTERFACES == {}
    assert listener_module._INTERFACE_CACHE == {}


def test_an_async_bind_drops_it_too() -> None:
    """`AsyncDhcpServer`'s MRO resolves `bind()` to `AsyncDhcpListener`, so an
    invalidation hung off `DhcpServer.bind` would never have run for it."""
    from pydhcp.listener import AsyncDhcpListener

    server_module._SERVABLE_INTERFACES[net.IPv4("192.0.2.1")] = None

    listener = AsyncDhcpListener(listen=("127.0.0.1", 0))
    listener.bind()
    try:
        assert server_module._SERVABLE_INTERFACES == {}
    finally:
        for sock in listener._sockets:
            sock.close()
        listener._sockets.clear()


def test_a_synthetic_interface_is_still_refused_and_the_refusal_is_cached() -> None:
    """Why this is not answered from `context.interface`.

    `_resolve_interface` never returns None -- it invents `unknown[<ip>]` with
    a /32 and no MAC when nothing matches, and the base allocator reads
    SUBNET_MASK and BROADCAST_ADDRESS off the interface's network. Handing that
    to a client means a 255.255.255.255 subnet mask. The lookup returns None
    instead, and the cache must not turn that None into an answer.
    """
    synthetic = net.NetworkInterface(
        "unknown[203.0.113.9]", ipaddress.IPv4Interface("203.0.113.9/32")
    )
    server_module._SERVABLE_INTERFACES.clear()

    server = DhcpServer(listen=("127.0.0.1", 0))
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    options[DhcpOptionCode.REQUESTED_IP] = net.IPv4("203.0.113.20")

    transport = Silent()
    context = RequestContext(
        transport=transport,
        interface=synthetic,
        client=net.SocketAddress(net.IPv4("0.0.0.0"), 68),
        client_mac=b"\x00\x11\x22\x33\x44\x55",
    )

    server.handle(build_request(options=options), context)
    server.handle(build_request(options=options), context)

    assert transport.sent == [], "offered a lease from an address we do not hold"
    assert server_module._SERVABLE_INTERFACES[net.IPv4("203.0.113.9")] is None


def test_the_lookup_does_not_apply_the_apipa_filter(monkeypatch) -> None:
    """Measured, not assumed: `host_ip_interfaces(<callable>)` *replaces* the
    default predicate rather than composing with it, so 169.254/16 has never
    been excluded on this path. Pinned so the caching change can be seen to
    have preserved it -- and so that changing it later is a deliberate act.

    (`test_the_default_filter_still_hides_apipa_from_serving` in
    `test_listener_apipa_resolution.py` pins the *intent*; this pins what the
    server actually does.)
    """
    apipa = net.NetworkInterface("Wi-Fi 2", ipaddress.IPv4Interface("169.254.11.89/16"))
    monkeypatch.setattr(
        server_module._net, "host_ip_interfaces", lambda f=True, family=4: iter([apipa])
    )
    server_module._SERVABLE_INTERFACES.clear()

    assert server_module._servable_interface(net.IPv4("169.254.11.89")) is apipa
