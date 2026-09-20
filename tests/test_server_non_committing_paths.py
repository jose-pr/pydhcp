"""A probe must not extend a binding (`server-18`).

RFC 2131 s4.3.1 makes DHCPDISCOVER a probe: the server looks for a binding and
offers it, but nothing is agreed until the client REQUESTs. The server renewed
anyway, and a DHCPREQUEST that was about to be NAKed renewed before deciding --
so a client asking for the wrong address had the address it was being refused
held open longer.
"""

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
SERVED = ipaddress.IPv4Interface("10.0.0.1/24")


def _message(
    message_type: DhcpMessageType,
    requested_ip: "IPv4 | None" = None,
    lease_time: "int | None" = None,
) -> DhcpMessage:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = message_type
    if requested_ip is not None:
        options[DhcpOptionCode.REQUESTED_IP] = requested_ip
    if lease_time is not None:
        options[DhcpOptionCode.IP_ADDRESS_LEASE_TIME] = lease_time
    return build_request(options=options)


def _context(transport: Mock) -> RequestContext:
    return RequestContext(
        transport=transport,
        interface=NetworkInterface("eth0", SERVED),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


class _ServedServer(DhcpServer):
    """A server whose served interface is fixed, so no host config is needed.

    `acquire_lease` resolves the serving interface through
    `host_ip_interfaces()`, which on a test host would not contain 10.0.0.1.
    Overriding the lookup keeps the real allocate/renew path -- the thing under
    test -- while removing the dependency on this machine's addresses.
    """

    def __init__(self, backend: InMemoryLeaseBackend) -> None:
        super().__init__(lease_backend=backend)

    def acquire_lease(self, client_id, server_id, msg):
        import pydhcp.server as server_module

        real = server_module._net.host_ip_interfaces
        server_module._net.host_ip_interfaces = lambda *a, **k: iter(
            [NetworkInterface("eth0", SERVED)]
        )
        try:
            return super().acquire_lease(client_id, server_id, msg)
        finally:
            server_module._net.host_ip_interfaces = real


@pytest.fixture
def backend() -> InMemoryLeaseBackend:
    return InMemoryLeaseBackend()


def _client_id(msg: DhcpMessage) -> str:
    return msg.client_id()


def test_discover_does_not_extend_an_existing_lease(backend) -> None:
    """The measured repro: option 51 = 999999 on a DISCOVER moved expiry 12 days."""
    server = _ServedServer(backend)
    seed = _message(DhcpMessageType.DHCPREQUEST, requested_ip=IPv4("10.0.0.50"))
    lease = server.acquire_lease(_client_id(seed), IPv4("10.0.0.1"), seed)
    assert lease is not None
    before = backend.lookup(_client_id(seed))
    assert before is not None

    renewed_before = server.metrics.leases_renewed
    probe = _message(DhcpMessageType.DHCPDISCOVER, lease_time=999999)
    server.handle_discover(probe, _context(Mock(send=Mock(return_value=1))))

    after = backend.lookup(_client_id(probe))
    assert after is not None
    assert after.expires == before.expires, "a DISCOVER extended the binding"
    assert server.metrics.leases_renewed == renewed_before, "probe counted as a renewal"


def test_a_naked_request_leaves_the_binding_untouched(backend) -> None:
    server = _ServedServer(backend)
    seed = _message(DhcpMessageType.DHCPREQUEST, requested_ip=IPv4("10.0.0.50"))
    assert server.acquire_lease(_client_id(seed), IPv4("10.0.0.1"), seed) is not None
    before = backend.lookup(_client_id(seed))
    assert before is not None

    transport = Mock(send=Mock(return_value=1))
    # Asking for a different address than the one held: this is NAKed.
    wrong = _message(
        DhcpMessageType.DHCPREQUEST,
        requested_ip=IPv4("10.0.0.77"),
        lease_time=999999,
    )
    server.handle_request(wrong, _context(transport))

    after = backend.lookup(_client_id(wrong))
    assert after is not None
    assert after.expires == before.expires, "a NAKed REQUEST extended the binding"
    assert after.ip == before.ip


def test_an_acked_request_still_commits_the_renewal(backend) -> None:
    """The other half: suppressing the probe must not stop a real renewal."""
    server = _ServedServer(backend)
    seed = _message(DhcpMessageType.DHCPREQUEST, requested_ip=IPv4("10.0.0.50"))
    assert server.acquire_lease(_client_id(seed), IPv4("10.0.0.1"), seed) is not None
    before = backend.lookup(_client_id(seed))
    assert before is not None

    renewed_before = server.metrics.leases_renewed
    good = _message(
        DhcpMessageType.DHCPREQUEST,
        requested_ip=IPv4("10.0.0.50"),
        lease_time=7200,
    )
    server.handle_request(good, _context(Mock(send=Mock(return_value=1))))

    after = backend.lookup(_client_id(good))
    assert after is not None
    assert after.expires > before.expires, "an ACKed REQUEST did not renew"
    assert server.metrics.leases_renewed == renewed_before + 1
