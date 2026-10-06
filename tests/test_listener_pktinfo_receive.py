"""The packet-info receive path, observed on real sockets.

Every assertion here is about what a datagram actually carried, never about the
library's opinion of itself. The receive path was silently off on CPython
3.9-3.11 everywhere (`getattr(socket, "IP_PKTINFO", None)` is None before 3.12)
while the suite stayed green, because nothing asserted that it was *on*; and
netimps' own guard against the same bug consulted the function that was wrong.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
import time

import pytest

from conftest import LOOPBACK_ALIAS_BINDABLE, build_request
from pydhcp import DHCPServer
import netimps

from pydhcp.listener import AsyncDHCPListener, DHCPListener

# the receive path is not public
from pydhcp.listener._receive import _pktinfo_supported
from ipaddress import IPv4Address as IPv4
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessage, DHCPMessageType

#: Where netimps documents packet info as supported. Anywhere else the tests
#: that need it skip -- but here they must not, or a broken probe would switch
#: the whole module off and still pass.
_PKTINFO_PLATFORMS = ("linux", "win32", "darwin")

needs_pktinfo = pytest.mark.skipif(
    not netimps.has_pktinfo(socket.AF_INET),
    reason="no packet info on this platform",
)


def test_packet_info_is_available_where_netimps_supports_it() -> None:
    if not sys.platform.startswith(_PKTINFO_PLATFORMS):
        pytest.skip(f"packet info is not promised on {sys.platform}")
    assert netimps.has_pktinfo(socket.AF_INET), (
        f"packet info reported unavailable on {sys.platform} "
        f"{sys.version.split()[0]}"
    )


class _Recording(DHCPListener):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.contexts: list = []

    def handle(self, msg, context) -> None:
        self.contexts.append(context)


def _wait(predicate, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not predicate():
        time.sleep(0.02)


@needs_pktinfo
def test_a_wildcard_listener_learns_where_a_datagram_arrived() -> None:
    """The datagram must say which address and interface it reached: the
    reply's SERVER_IDENTIFIER and egress are derived from them."""
    listener = _Recording(listen=("0.0.0.0", 0), poll_interval=0.05)
    listener.bind()
    port = listener.bound_addresses[0].port
    listener.start()
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(build_request().encode(), ("127.0.0.1", port))
        _wait(lambda: listener.contexts)
    finally:
        sender.close()
        listener.close()

    assert listener.contexts, "nothing reached handle()"
    context = listener.contexts[0]
    assert context.local_ip == IPv4("127.0.0.1")
    assert context.ifindex, "no interface index was observed"
    assert context.interface.ip == IPv4("127.0.0.1")


@pytest.mark.parametrize(
    "spec",
    [
        ("0.0.0.0", 6767),
        "0.0.0.0:6767",
        "*:6767",
        ["0.0.0.0:6767"],
        "0.0.0.0:6767,127.0.0.1:6768",
    ],
)
@needs_pktinfo
def test_every_wildcard_spelling_takes_the_packet_info_path(spec) -> None:
    """`"0.0.0.0:67"` and `"*:67"` used to compare unequal to the wildcard,
    skip packet info and expand into one socket per address -- which on Linux
    hears no broadcast DISCOVER at all."""
    assert _pktinfo_supported(spec, None), spec
    assert DHCPListener(listen=spec)._pktinfo, spec


def _exchange_discover(
    server_port: int, server: _ty.Any = None
) -> "DHCPMessage | None":
    """Send one DISCOVER over loopback and return the reply, if any.

    The client is bound to the wildcard: over loopback the server unicasts the
    OFFER to yiaddr (127.0.0.50 here), which an address-bound client would not
    receive.
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("0.0.0.0", 0))
    client.settimeout(2.0)
    if server is not None:
        # The client is on an ephemeral port, not 68.
        server.REPLY_TO_CLIENT_PORT = client.getsockname()[1]
    try:
        discover = build_request(DHCPMessageType.DHCPDISCOVER)
        discover.options[DHCPOptionCode.REQUESTED_IP] = IPv4("127.0.0.50")
        client.sendto(discover.encode(), ("127.0.0.1", server_port))
        try:
            data, _ = client.recvfrom(4096)
        except socket.timeout:
            return None
        return DHCPMessage.decode(data)
    finally:
        client.close()


@pytest.mark.parametrize("spec", [("0.0.0.0", 0), "0.0.0.0:0", "*:0"])
@needs_pktinfo
@pytest.mark.skipif(
    not LOOPBACK_ALIAS_BINDABLE,
    reason="the OFFER is unicast to 127.0.0.50; macOS aliases only 127.0.0.1",
)
def test_a_wildcard_server_allocates_and_replies(spec) -> None:
    """End to end, on the base allocator. A wrong local address does not raise:
    it resolved a synthetic /32 interface with nothing in it to lease, and the
    server received the DISCOVER and stayed silent. Only an offer and a
    reply prove the path works."""
    server = DHCPServer(listen=spec, poll_interval=0.05)
    server.bind()
    port = server.bound_addresses[0].port
    server.start()
    try:
        reply = _exchange_discover(port, server)
    finally:
        server.close()

    assert server.metrics.leases_offered == 1, server.metrics.snapshot()
    assert reply is not None, "the server offered but no reply arrived"
    assert reply.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) is (
        DHCPMessageType.DHCPOFFER
    )
    assert reply.options.get(DHCPOptionCode.SERVER_IDENTIFIER) == IPv4("127.0.0.1")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux semantics")
@pytest.mark.parametrize("spelling", ["tuple", "0.0.0.0:p", "*:p"])
def test_every_wildcard_spelling_hears_a_limited_broadcast(spelling) -> None:
    """The failure the spelling bug produced: on Linux an address-bound socket
    receives no limited broadcast. Measured before the fix: 0 of 3 seen for the
    string spellings, 3 of 3 for the tuple."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("0.0.0.0", 0))
    port = probe.getsockname()[1]
    probe.close()
    spec = {
        "tuple": ("0.0.0.0", port),
        "0.0.0.0:p": f"0.0.0.0:{port}",
        "*:p": f"*:{port}",
    }

    listener = _Recording(listen=spec[spelling], poll_interval=0.05)
    listener.bind()
    listener.start()
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sender.sendto(build_request().encode(), ("255.255.255.255", port))
        _wait(lambda: listener.contexts)
    finally:
        sender.close()
        listener.close()

    assert listener.contexts, f"{spelling}: the broadcast never arrived"


@needs_pktinfo
def test_the_async_listener_learns_where_a_datagram_arrived() -> None:
    """On the platform's *default* loop -- Windows' proactor included, where
    `add_reader` does not exist and the old fallback could carry no packet
    info at all."""

    class Recording(AsyncDHCPListener):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self.contexts: list = []
            self.seen = threading.Event()

        def handle(self, msg, context) -> None:
            self.contexts.append(context)
            self.seen.set()

    async def scenario() -> "list":
        listener = Recording(listen=("0.0.0.0", 0))
        await listener.start()
        port = listener.bound_addresses[0].port
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(build_request().encode(), ("127.0.0.1", port))
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, listener.seen.wait, 3.0)
        finally:
            sender.close()
            await listener.aclose()
        assert listener.bound_addresses == (), "aclose() did not close the sockets"
        return listener.contexts

    contexts = asyncio.run(scenario())

    assert contexts, "nothing reached handle()"
    assert contexts[0].local_ip == IPv4("127.0.0.1")
    assert contexts[0].ifindex
