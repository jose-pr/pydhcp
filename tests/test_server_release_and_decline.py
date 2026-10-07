"""RELEASE and DECLINE are verified before they act (`server-31`, `server-14`)."""

import ipaddress
from unittest.mock import Mock

import pytest

from pydhcp import (
    DHCPLease,
    DHCPMessage,
    DHCPOptions,
    NetworkInterface,
    DHCPRequestContext,
)
from pydhcp.lease import InMemoryLeaseBackend
from ipaddress import IPv4Address as IPv4
from pydhcp import SocketAddress
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
from pydhcp import AsyncDHCPServer
from pydhcp.server import DHCPServer
from helpers import build_request

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
IFACE_A = ipaddress.IPv4Interface("10.0.0.1/24")
IFACE_B = ipaddress.IPv4Interface("10.0.0.2/24")


def _message(
    message_type: DHCPMessageType,
    ciaddr: str = "0.0.0.0",
    server_id: "IPv4 | None" = None,
    requested_ip: "IPv4 | None" = None,
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = message_type
    if server_id is not None:
        options[DHCPOptionCode.SERVER_IDENTIFIER] = server_id
    if requested_ip is not None:
        options[DHCPOptionCode.REQUESTED_IP] = requested_ip
    return build_request(options=options, ciaddr=IPv4(ciaddr))


def _context(interface: ipaddress.IPv4Interface) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", interface),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


@pytest.fixture
def served(monkeypatch) -> None:
    """The host serves 10.0.0.0/24 from 10.0.0.1, whatever adapters this machine has."""
    # private: the name is looked up in the module that reads it, so the host or the clock can be stood for
    monkeypatch.setattr(
        "pydhcp.server._policy._servable_interface",
        lambda _ip: NetworkInterface("eth0", IFACE_A),
    )


@pytest.fixture
def server() -> DHCPServer:
    return DHCPServer(lease_backend=InMemoryLeaseBackend())


def _seed(server: DHCPServer, ip: str = "10.0.0.50") -> str:
    client_id = _message(DHCPMessageType.DHCPREQUEST).get_client_id()
    server.lease_backend.allocate(client_id, IPv4(ip), 3600.0, DHCPOptions())
    return client_id


def test_release_naming_another_address_is_ignored(server) -> None:
    """A late RELEASE for an old address must not delete the current binding."""
    client_id = _seed(server, "10.0.0.50")
    server.handle_release(
        _message(DHCPMessageType.DHCPRELEASE, ciaddr="10.0.0.99"), _context(IFACE_A)
    )
    assert server.lease_backend.lookup(client_id) is not None
    assert server.metrics.releases_ignored == 1
    assert server.metrics.leases_released == 0


def test_release_for_the_held_address_still_works(server) -> None:
    client_id = _seed(server, "10.0.0.50")
    server.handle_release(
        _message(DHCPMessageType.DHCPRELEASE, ciaddr="10.0.0.50"), _context(IFACE_A)
    )
    assert server.lease_backend.lookup(client_id) is None
    assert server.metrics.leases_released == 1
    assert server.metrics.releases_ignored == 0


def test_decline_counts_as_a_decline_not_a_release(server, served) -> None:
    """A DECLINE means the address was already in use -- the opposite of a release."""
    _seed(server, "10.0.0.50")
    server.handle_decline(
        _message(DHCPMessageType.DHCPDECLINE, requested_ip=IPv4("10.0.0.50")),
        _context(IFACE_A),
    )
    assert server.metrics.leases_declined == 1
    assert server.metrics.leases_released == 0


def test_a_second_address_of_this_host_does_not_delete_the_binding(
    server, monkeypatch
) -> None:
    """`server-14`: two sockets on one broadcast domain, one shared backend.

    Socket A ACKs the REQUEST; socket B receives the same broadcast, reads
    option 54 as a foreign server and used to delete the binding the client had
    just accepted -- freeing the address while the client was using it.
    """
    import pydhcp.server as server_module

    # private: the module's own name for the host enumeration, replaced to stand for a host
    monkeypatch.setattr(
        server_module._net,
        "host_ip_interfaces",
        lambda *a, **k: iter(
            [NetworkInterface("eth0", IFACE_A), NetworkInterface("eth1", IFACE_B)]
        ),
    )
    # private: the module's own name for netimps, replaced to stand for a host
    monkeypatch.setattr(
        server_module._netimps,
        "is_local_address",
        lambda address, **_kw: address in {IFACE_A.ip, IFACE_B.ip},
    )
    client_id = _seed(server, "10.0.0.50")

    # The client selected address A; this is B's copy of the same broadcast.
    server.handle(
        _message(
            DHCPMessageType.DHCPREQUEST,
            server_id=IPv4("10.0.0.1"),
            requested_ip=IPv4("10.0.0.50"),
        ),
        _context(IFACE_B),
    )
    assert (
        server.lease_backend.lookup(client_id) is not None
    ), "a second address of this same host deleted the binding"


def test_the_identity_check_asks_the_real_host(server) -> None:
    """Unmocked: loopback is this host and a TEST-NET-3 address (RFC 5737) is
    not, whatever this machine's adapters hold."""
    # private: the server's identifier rule, called directly
    assert server._is_our_server_id(IPv4("127.0.0.1"), IPv4("10.255.0.1")) is True
    assert server._is_our_server_id(IPv4("203.0.113.77"), IPv4("10.255.0.1")) is False


def _foreign_request(server, monkeypatch) -> str:
    """Seed nothing; send a REQUEST that names a server that is not this host."""
    import pydhcp.server as server_module

    # private: the module's own name for the host enumeration, replaced to stand for a host
    monkeypatch.setattr(
        server_module._net,
        "host_ip_interfaces",
        lambda *a, **k: iter([NetworkInterface("eth0", IFACE_A)]),
    )
    # private: the module's own name for netimps, replaced to stand for a host
    monkeypatch.setattr(
        server_module._netimps,
        "is_local_address",
        lambda address, **_kw: address == IFACE_A.ip,
    )
    request = _message(
        DHCPMessageType.DHCPREQUEST,
        server_id=IPv4("192.0.2.77"),
        requested_ip=IPv4("10.0.0.50"),
    )
    server.handle(request, _context(IFACE_A))
    return request.get_client_id()


def test_a_request_naming_another_server_gives_back_the_offer(
    server, monkeypatch
) -> None:
    """RFC 2131 s4.3.2: the client chose another server, so the address held for
    it by an offer is released. Pinned so the fix above is not widened into
    "never reclaim", which would hold an address for every client that picked a
    different server."""
    client_id = _message(DHCPMessageType.DHCPREQUEST).get_client_id()
    held = server.lease_backend.offer(client_id, IPv4("10.0.0.50"), 120.0)
    assert held is not None and held.offered

    assert _foreign_request(server, monkeypatch) == client_id

    assert server.lease_backend.lookup(client_id) is None
    assert server.metrics.offers_withdrawn == 1
    assert server.metrics.leases_released == 0


def test_a_request_naming_another_server_keeps_a_binding(server, monkeypatch) -> None:
    """A binding the client accepted is not the sender's to cancel: the server
    identifier of a REQUEST is unauthenticated, and anyone can name another
    server for someone else's client identifier."""
    client_id = _seed(server, "10.0.0.50")

    _foreign_request(server, monkeypatch)

    kept = server.lease_backend.lookup(client_id)
    assert kept is not None and not kept.offered
    assert server.metrics.offers_withdrawn == 0
    assert server.metrics.leases_released == 0


# --- DHCPDECLINE marks the address it names, whoever sent it (RFC 2131 s4.3.3) ---

OTHER_CHADDR = bytes([0x02, 0, 0, 0, 0x0B, 0xAD])


def _decline_from(
    chaddr: bytes, address: str, server_id: "IPv4 | None" = None
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDECLINE
    options[DHCPOptionCode.REQUESTED_IP] = IPv4(address)
    if server_id is not None:
        options[DHCPOptionCode.SERVER_IDENTIFIER] = server_id
    return build_request(options=options, chaddr=chaddr)


def _holder_id() -> str:
    return _message(DHCPMessageType.DHCPREQUEST).get_client_id()


@pytest.fixture(params=[DHCPServer, AsyncDHCPServer], ids=["thread", "asyncio"])
def either(request, served):
    """The server of each driver, serving 10.0.0.0/24 from 10.0.0.1."""
    return request.param(lease_backend=InMemoryLeaseBackend())


def _discover_for(chaddr: bytes, address: str) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    options[DHCPOptionCode.REQUESTED_IP] = IPv4(address)
    return build_request(options=options, chaddr=chaddr)


def test_the_holders_decline_quarantines_its_binding_and_releases_it(
    server, served
) -> None:
    _seed(server, "10.0.0.50")
    server.handle(
        _decline_from(CHADDR, "10.0.0.50", IPv4("10.0.0.1")), _context(IFACE_A)
    )
    assert server.is_quarantined(IPv4("10.0.0.50"))
    assert server.lease_backend.lookup(_holder_id()) is None
    assert server.metrics.leases_declined == 1
    assert server.metrics.declines_ignored == 0


def test_the_decline_of_an_outstanding_offer_quarantines_it(server, served) -> None:
    server.lease_backend.offer(_holder_id(), IPv4("10.0.0.50"), 120.0)
    server.handle(_decline_from(CHADDR, "10.0.0.50"), _context(IFACE_A))
    assert server.is_quarantined(IPv4("10.0.0.50"))
    assert server.metrics.leases_declined == 1


def test_a_decline_from_a_client_that_holds_nothing_quarantines_the_address(
    either,
) -> None:
    """RFC 2131 s4.3.3: "The server MUST mark the network address as not available"."""
    either.handle(_decline_from(OTHER_CHADDR, "10.0.0.60"), _context(IFACE_A))

    assert either.is_quarantined(IPv4("10.0.0.60"))
    assert either.metrics.leases_declined == 1
    assert either.metrics.declines_ignored == 0


def test_the_next_discover_for_a_declined_address_gets_no_offer(either) -> None:
    either.handle(_decline_from(OTHER_CHADDR, "10.0.0.60"), _context(IFACE_A))

    asked = _context(IFACE_A)
    either.handle(_discover_for(CHADDR, "10.0.0.60"), asked)

    assert asked.transport.send.call_count == 0
    assert either.lease_backend.lookup(_holder_id()) is None


def test_an_address_not_declined_is_still_offered(either) -> None:
    """The control of the test above: the same DISCOVER for another address is answered."""
    either.handle(_decline_from(OTHER_CHADDR, "10.0.0.60"), _context(IFACE_A))

    asked = _context(IFACE_A)
    either.handle(_discover_for(CHADDR, "10.0.0.61"), asked)

    assert asked.transport.send.call_count == 1


@pytest.mark.parametrize(
    "address, why",
    [
        ("10.0.0.50", "another client's binding"),
        ("10.0.0.51", "an address nobody was offered"),
    ],
)
def test_a_decline_from_a_client_that_does_not_hold_the_address_marks_it(
    either, address, why
) -> None:
    holder = _seed(either, "10.0.0.50")
    either.handle(_decline_from(OTHER_CHADDR, address), _context(IFACE_A))
    assert either.is_quarantined(IPv4(address)), why
    # Only a record the sender holds is released: the other client keeps its own.
    assert either.lease_backend.lookup(holder) is not None
    assert either.metrics.leases_declined == 1
    assert either.metrics.declines_ignored == 0


def test_the_holder_of_an_address_another_client_declined_is_refused_its_renewal(
    either,
) -> None:
    """What believing a DECLINE costs: the holder of the address is told to start over."""
    _seed(either, "10.0.0.50")
    either.handle(_decline_from(OTHER_CHADDR, "10.0.0.50"), _context(IFACE_A))

    renewal = _context(IFACE_A)
    either.handle(_message(DHCPMessageType.DHCPREQUEST, ciaddr="10.0.0.50"), renewal)

    reply = DHCPMessage.decode(renewal.transport.send.call_args.args[0])
    assert (
        reply.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == DHCPMessageType.DHCPNAK
    )
    assert either.metrics.addresses_refused == 1


def test_with_the_switch_the_holder_keeps_renewing_through_another_clients_decline(
    either,
) -> None:
    """The control of the test above: under the stricter rule the renewal is acknowledged."""
    either.DECLINE_REQUIRES_LEASE = True
    _seed(either, "10.0.0.50")
    either.handle(_decline_from(OTHER_CHADDR, "10.0.0.50"), _context(IFACE_A))

    renewal = _context(IFACE_A)
    either.handle(_message(DHCPMessageType.DHCPREQUEST, ciaddr="10.0.0.50"), renewal)

    reply = DHCPMessage.decode(renewal.transport.send.call_args.args[0])
    assert (
        reply.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == DHCPMessageType.DHCPACK
    )
    assert either.metrics.addresses_refused == 0


@pytest.mark.parametrize(
    "address, why",
    [
        ("198.51.100.7", "an address outside the served network"),
        ("10.0.0.1", "the server's own address"),
    ],
)
def test_a_decline_for_an_address_that_cannot_be_served_changes_nothing(
    either, address, why
) -> None:
    holder = _seed(either, "10.0.0.50")
    either.handle(_decline_from(OTHER_CHADDR, address), _context(IFACE_A))
    assert not either.is_quarantined(IPv4(address)), why
    assert either.lease_backend.lookup(holder) is not None
    assert either.metrics.declines_ignored == 1
    assert either.metrics.leases_declined == 0


def test_a_decline_of_the_servers_own_address_the_sender_holds_a_lease_on_is_believed(
    either,
) -> None:
    """The store's record is the sender's: an override that leases it is not second-guessed."""
    _seed(either, "10.0.0.1")
    either.handle(_decline_from(CHADDR, "10.0.0.1"), _context(IFACE_A))
    assert either.is_quarantined(IPv4("10.0.0.1"))
    assert either.lease_backend.lookup(_holder_id()) is None


def test_a_decline_naming_another_address_than_the_one_held_marks_that_one(
    either,
) -> None:
    """The sender's own binding is another address, and stays: only what it holds is released."""
    holder = _seed(either, "10.0.0.50")
    either.handle(_decline_from(CHADDR, "10.0.0.51"), _context(IFACE_A))
    assert either.is_quarantined(IPv4("10.0.0.51"))
    assert not either.is_quarantined(IPv4("10.0.0.50"))
    held = either.lease_backend.lookup(holder)
    assert held is not None and held.ip == IPv4("10.0.0.50")
    assert either.metrics.leases_declined == 1


def test_a_decline_from_a_client_that_holds_nothing_is_bounded(either) -> None:
    """The bound a holder's decline has: a new address is refused, no older one pushed out."""
    either.MAX_DECLINED_ADDRESSES = 2
    for last in (60, 61, 62, 63):
        either.handle(_decline_from(OTHER_CHADDR, f"10.0.0.{last}"), _context(IFACE_A))
    assert either.is_quarantined(IPv4("10.0.0.60"))
    assert either.is_quarantined(IPv4("10.0.0.61"))
    assert not either.is_quarantined(IPv4("10.0.0.62"))
    assert not either.is_quarantined(IPv4("10.0.0.63"))
    assert either.metrics.quarantines_refused == 2


def test_a_decline_from_a_client_that_holds_nothing_and_names_another_server_is_ignored(
    either, monkeypatch
) -> None:
    # private: the name is looked up in the module that reads it, so the host or the clock can be stood for
    monkeypatch.setattr(
        "pydhcp.server._policy._netimps.is_local_address", lambda a, **_k: False
    )
    either.handle_decline(
        _decline_from(OTHER_CHADDR, "10.0.0.60", IPv4("192.0.2.77")), _context(IFACE_A)
    )
    assert not either.is_quarantined(IPv4("10.0.0.60"))
    assert either.metrics.declines_ignored == 1


# --- DECLINE_REQUIRES_LEASE: the stricter rule, for a site that wants it ---------


def test_the_switch_is_a_class_attribute_that_is_off() -> None:
    assert DHCPServer.DECLINE_REQUIRES_LEASE is False
    assert AsyncDHCPServer.DECLINE_REQUIRES_LEASE is False


@pytest.mark.parametrize(
    "address, why",
    [
        ("10.0.0.50", "another client's binding"),
        ("10.0.0.51", "an address nobody was offered"),
        ("198.51.100.7", "an address outside the served network"),
        ("10.0.0.1", "the server's own address"),
    ],
)
def test_with_the_switch_a_decline_from_a_client_that_does_not_hold_the_address_changes_nothing(
    either, address, why
) -> None:
    either.DECLINE_REQUIRES_LEASE = True
    holder = _seed(either, "10.0.0.50")
    either.handle(_decline_from(OTHER_CHADDR, address), _context(IFACE_A))
    assert not either.is_quarantined(IPv4(address)), why
    assert either.lease_backend.lookup(holder) is not None
    assert either.metrics.declines_ignored == 1
    assert either.metrics.leases_declined == 0


def test_with_the_switch_a_decline_naming_another_address_than_the_one_held_changes_nothing(
    either,
) -> None:
    either.DECLINE_REQUIRES_LEASE = True
    holder = _seed(either, "10.0.0.50")
    either.handle(_decline_from(CHADDR, "10.0.0.51"), _context(IFACE_A))
    assert not either.is_quarantined(IPv4("10.0.0.51"))
    assert not either.is_quarantined(IPv4("10.0.0.50"))
    assert either.lease_backend.lookup(holder) is not None
    assert either.metrics.declines_ignored == 1


def test_with_the_switch_the_holders_decline_still_quarantines_and_releases(
    either,
) -> None:
    either.DECLINE_REQUIRES_LEASE = True
    _seed(either, "10.0.0.50")
    either.handle(_decline_from(CHADDR, "10.0.0.50"), _context(IFACE_A))
    assert either.is_quarantined(IPv4("10.0.0.50"))
    assert either.lease_backend.lookup(_holder_id()) is None
    assert either.metrics.leases_declined == 1


def test_a_held_address_outside_the_served_network_is_not_quarantined(
    server, served
) -> None:
    """A store can hold anything; the quarantine is for this server's network."""
    server.lease_backend.allocate(_holder_id(), IPv4("198.51.100.7"), 3600.0)
    server.handle_decline(_decline_from(CHADDR, "198.51.100.7"), _context(IFACE_A))
    assert not server.is_quarantined(IPv4("198.51.100.7"))
    assert server.metrics.declines_ignored == 1


def test_a_decline_from_a_holder_naming_another_server_is_ignored(
    server, served, monkeypatch
) -> None:
    """Option 54 is the one thing a DECLINE says about who it is for."""
    # private: the name is looked up in the module that reads it, so the host or the clock can be stood for
    monkeypatch.setattr(
        "pydhcp.server._policy._netimps.is_local_address", lambda a, **_k: False
    )
    _seed(server, "10.0.0.50")
    server.handle_decline(
        _decline_from(CHADDR, "10.0.0.50", IPv4("192.0.2.77")), _context(IFACE_A)
    )
    assert not server.is_quarantined(IPv4("10.0.0.50"))
    assert server.metrics.declines_ignored == 1


def test_a_decline_flood_does_not_push_a_genuine_report_out(server, served) -> None:
    """The bound refuses new addresses instead of evicting old ones."""
    server.MAX_DECLINED_ADDRESSES = 4
    _seed(server, "10.0.0.50")
    server.handle(_decline_from(CHADDR, "10.0.0.50"), _context(IFACE_A))
    for n in range(40):
        server.quarantine_address(IPv4(f"10.0.0.{100 + n}"))
    assert server.is_quarantined(IPv4("10.0.0.50"))
    # private: the quarantine table: its bound is the subject
    assert len(server._declined) == 4
    assert server.metrics.quarantines_refused == 37


class _FixedAddress(DHCPServer):
    """An override that stores nothing: every client is given 10.0.0.50."""

    def lookup_lease(self, client_id):
        return DHCPLease(IPv4("10.0.0.50"))

    def acquire_lease(self, client_id, server_id, msg, *, commit=True):
        return DHCPLease(IPv4("10.0.0.50"))


def test_the_quarantine_applies_to_the_lease_an_override_returns(served) -> None:
    server = _FixedAddress()
    discover = _message(DHCPMessageType.DHCPDISCOVER)
    first = _context(IFACE_A)
    server.handle(discover, first)
    assert first.transport.send.call_count == 1

    server.handle(
        _decline_from(CHADDR, "10.0.0.50", IPv4("10.0.0.1")), _context(IFACE_A)
    )
    assert server.is_quarantined(IPv4("10.0.0.50"))

    again = _context(IFACE_A)
    server.handle(discover, again)
    assert again.transport.send.call_count == 0
    assert server.metrics.addresses_refused == 1
