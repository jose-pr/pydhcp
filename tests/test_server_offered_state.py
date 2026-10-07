"""An address offered in a DHCPOFFER is held for a short time, not for a lease.

RFC 2131 s3.1 step 4 and s4.3.1: an OFFER reserves an address for the client
while it decides; only the REQUEST it sends makes a lease. The store records
that as a state (`DHCPLease.offered`), so a DISCOVER from a forged identity holds
an address for `OFFER_HOLD_SECONDS` and no longer.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import typing as _ty
from ipaddress import IPv4Address as IPv4
from unittest.mock import Mock

import pytest

from pydhcp import (
    AsyncDHCPServer,
    DHCPLease,
    DHCPMessage,
    DHCPOptions,
    DHCPRequestContext,
    DHCPServer,
    InMemoryLeaseBackend,
    NetworkInterface,
    SocketAddress,
)
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType

# The allocator reads the host's adapters through this name in the private
# module that owns it; a test serves a fixed interface by replacing it there.
from pydhcp.server import _policy
from helpers import build_request

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
SERVED = ipaddress.IPv4Interface("10.0.0.1/29")


class _Stepped(InMemoryLeaseBackend):
    """A store whose clock the test passes in."""

    now = T0

    def _now(self) -> dt.datetime:
        return self.now

    def step(self, seconds: float) -> None:
        self.now = self.now + dt.timedelta(seconds=seconds)


@pytest.fixture(autouse=True)
def _served_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _policy,
        "_servable_interface",
        lambda server_id: (
            NetworkInterface("eth0", SERVED) if server_id == SERVED.ip else None
        ),
    )


def _mac(n: int) -> bytes:
    return bytes([0x02, 0, 0, 0, n >> 8, n & 0xFF])


def _message(
    message_type: DHCPMessageType,
    chaddr: bytes,
    *,
    requested_ip: _ty.Optional[str] = None,
    server_id: _ty.Optional[str] = None,
    lease_time: _ty.Optional[int] = None,
    ciaddr: str = "0.0.0.0",
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = message_type
    if requested_ip is not None:
        options[DHCPOptionCode.REQUESTED_IP] = IPv4(requested_ip)
    if server_id is not None:
        options[DHCPOptionCode.SERVER_IDENTIFIER] = IPv4(server_id)
    if lease_time is not None:
        options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = lease_time
    return build_request(options=options, chaddr=chaddr, ciaddr=IPv4(ciaddr))


def _send(server: DHCPServer, message: DHCPMessage) -> _ty.List[DHCPMessage]:
    """The replies the server sends to `message`, decoded from the wire octets."""
    transport = Mock(send=Mock(return_value=1))
    # A store with a stepped clock puts the server on the same clock: the
    # datagram arrives at the instant the test says it does.
    now = getattr(server.lease_backend, "now", None)
    context = DHCPRequestContext(
        transport=transport,
        interface=NetworkInterface("eth0", SERVED),
        client=SocketAddress("0.0.0.0", 68),
        client_mac=message.chaddr,
        received_at=now,
        received_monotonic=None if now is None else (now - T0).total_seconds(),
    )
    server.handle(message, context)
    return [
        DHCPMessage.decode(memoryview(bytes(call.args[0])))
        for call in transport.send.call_args_list
    ]


def _type(reply: DHCPMessage) -> DHCPMessageType:
    found = reply.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
    assert found is not None
    return found


def _client(chaddr: bytes) -> str:
    return _message(DHCPMessageType.DHCPDISCOVER, chaddr).get_client_id()


@pytest.fixture
def backend() -> _Stepped:
    return _Stepped()


@pytest.fixture
def server(backend: _Stepped) -> DHCPServer:
    return DHCPServer(lease_backend=backend)


def test_a_discover_holds_the_address_as_an_offer_and_commits_nothing(
    server: DHCPServer, backend: _Stepped
) -> None:
    (offer,) = _send(
        server, _message(DHCPMessageType.DHCPDISCOVER, _mac(1), requested_ip="10.0.0.5")
    )

    assert _type(offer) is DHCPMessageType.DHCPOFFER
    assert offer.yiaddr == IPv4("10.0.0.5")
    held = backend.lookup(_client(_mac(1)))
    assert held is not None and held.offered
    assert held.expires == T0 + dt.timedelta(seconds=server.OFFER_HOLD_SECONDS)
    assert server.metrics.leases_offered == 1
    assert server.metrics.leases_allocated == 0


def test_the_hold_is_a_class_attribute_of_120_seconds(server: DHCPServer) -> None:
    assert DHCPServer.OFFER_HOLD_SECONDS == 120.0
    assert AsyncDHCPServer.OFFER_HOLD_SECONDS == 120.0


def test_the_offer_advertises_the_lease_the_ack_would_grant_not_the_hold(
    server: DHCPServer,
) -> None:
    (offer,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPDISCOVER,
            _mac(1),
            requested_ip="10.0.0.5",
            lease_time=7200,
        ),
    )
    assert offer.options.get(DHCPOptionCode.IP_ADDRESS_LEASE_TIME) == 7200


def test_the_request_that_accepts_the_offer_commits_it(
    server: DHCPServer, backend: _Stepped
) -> None:
    _send(
        server,
        _message(
            DHCPMessageType.DHCPDISCOVER,
            _mac(1),
            requested_ip="10.0.0.5",
            lease_time=7200,
        ),
    )
    backend.step(30)

    (ack,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST,
            _mac(1),
            requested_ip="10.0.0.5",
            server_id="10.0.0.1",
            lease_time=7200,
        ),
    )

    assert _type(ack) is DHCPMessageType.DHCPACK
    assert ack.options.get(DHCPOptionCode.IP_ADDRESS_LEASE_TIME) == 7200
    bound = backend.lookup(_client(_mac(1)))
    assert bound is not None and not bound.offered
    assert bound.expires == backend.now + dt.timedelta(seconds=7200)
    assert server.metrics.leases_offered == 1
    assert server.metrics.leases_allocated == 1


def test_the_binding_outlives_the_hold(server: DHCPServer, backend: _Stepped) -> None:
    _send(
        server, _message(DHCPMessageType.DHCPDISCOVER, _mac(1), requested_ip="10.0.0.5")
    )
    _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST,
            _mac(1),
            requested_ip="10.0.0.5",
            server_id="10.0.0.1",
        ),
    )
    backend.step(server.OFFER_HOLD_SECONDS * 3)
    assert backend.lookup(_client(_mac(1))) is not None


def test_a_forged_flood_cannot_hold_the_pool_past_the_hold(
    server: DHCPServer, backend: _Stepped
) -> None:
    """The bound: every address of a /29 offered to a forged identity, each asking
    for a day, is free again `OFFER_HOLD_SECONDS` after the flood; nothing is
    committed. Before the offered state the same flood held the pool for the
    lease time each forged client asked for (up to MAX_LEASE_SECONDS)."""
    pool = [f"10.0.0.{n}" for n in range(2, 7)]  # .1 is the server, .7 the broadcast
    for n, address in enumerate(pool):
        (offer,) = _send(
            server,
            _message(
                DHCPMessageType.DHCPDISCOVER,
                _mac(0x100 + n),
                requested_ip=address,
                lease_time=86400,
            ),
        )
        assert _type(offer) is DHCPMessageType.DHCPOFFER
    assert server.metrics.leases_allocated == 0

    real = _mac(1)
    wanted = _message(DHCPMessageType.DHCPDISCOVER, real, requested_ip=pool[0])

    backend.step(server.OFFER_HOLD_SECONDS - 1)
    assert _send(server, wanted) == []  # still held, so the real client waits

    backend.step(1)
    (offer,) = _send(server, wanted)
    assert _type(offer) is DHCPMessageType.DHCPOFFER
    assert offer.yiaddr == IPv4(pool[0])


def test_forged_offers_hold_each_forged_client_to_one_address(
    server: DHCPServer, backend: _Stepped
) -> None:
    for address in ("10.0.0.2", "10.0.0.3"):
        _send(
            server,
            _message(
                DHCPMessageType.DHCPDISCOVER,
                _mac(0x200),
                requested_ip=address,
                lease_time=86400,
            ),
        )
    held = backend.lookup(_client(_mac(0x200)))
    assert held is not None and held.ip == IPv4("10.0.0.2")
    assert backend.lookup_by_ip(IPv4("10.0.0.3")) is None


# --- a backend written from the shipped header alone -------------------------


class _HeaderBackend:
    """A `LeaseBackend` written from the shipped header, subclassing nothing.

    It has no `lookup_by_ip` (the header marks that one optional), so the
    server's own address check is skipped and `offer` and `allocate` are what
    refuse an address another client holds.
    """

    def __init__(self) -> None:
        self.records: _ty.Dict[str, DHCPLease] = {}

    @staticmethod
    def _now() -> dt.datetime:
        return dt.datetime.now(UTC)

    def _live(self, client_id: str) -> _ty.Optional[DHCPLease]:
        lease = self.records.get(client_id)
        if lease is not None and lease.expires is not None:
            if lease.expires <= self._now():
                del self.records[client_id]
                return None
        return lease

    def _held_by_other(self, client_id: str, ip: IPv4) -> bool:
        return any(
            other != client_id and self._live(other) is not None and lease.ip == ip
            for other, lease in list(self.records.items())
        )

    def _expiry(self, seconds: float) -> _ty.Optional[dt.datetime]:
        return (
            None
            if seconds == float("inf")
            else self._now() + dt.timedelta(seconds=seconds)
        )

    def allocate(self, client_id, ip, ttl, options=None):  # type: ignore[no-untyped-def]
        if self._held_by_other(client_id, ip):
            return None
        lease = DHCPLease(ip, self._expiry(ttl), options)
        self.records[client_id] = lease
        return lease

    def offer(self, client_id, ip, hold_seconds, options=None):  # type: ignore[no-untyped-def]
        if self._held_by_other(client_id, ip):
            return None
        existing = self._live(client_id)
        if existing is not None and not existing.offered:
            return existing if existing.ip == ip else None
        lease = DHCPLease(ip, self._expiry(hold_seconds), options, offered=True)
        self.records[client_id] = lease
        return lease

    def commit(self, client_id, ttl):  # type: ignore[no-untyped-def]
        lease = self._live(client_id)
        if lease is None or not lease.offered:
            return None
        bound = DHCPLease(lease.ip, self._expiry(ttl), lease.options)
        self.records[client_id] = bound
        return bound

    def lookup(self, client_id):  # type: ignore[no-untyped-def]
        return self._live(client_id)

    def release(self, client_id):  # type: ignore[no-untyped-def]
        return self.records.pop(client_id, None) is not None

    def renew(self, client_id, ttl):  # type: ignore[no-untyped-def]
        lease = self._live(client_id)
        if lease is None or lease.offered:
            return None
        renewed = DHCPLease(lease.ip, self._expiry(ttl), lease.options)
        self.records[client_id] = renewed
        return renewed


def test_a_backend_written_from_the_header_serves_a_whole_exchange() -> None:
    backend = _HeaderBackend()
    server = DHCPServer(lease_backend=backend)
    chaddr = _mac(1)

    (offer,) = _send(
        server, _message(DHCPMessageType.DHCPDISCOVER, chaddr, requested_ip="10.0.0.5")
    )
    assert _type(offer) is DHCPMessageType.DHCPOFFER
    assert backend.lookup(_client(chaddr)).offered  # type: ignore[union-attr]

    (ack,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST,
            chaddr,
            requested_ip="10.0.0.5",
            server_id="10.0.0.1",
        ),
    )
    assert _type(ack) is DHCPMessageType.DHCPACK
    assert not backend.lookup(_client(chaddr)).offered  # type: ignore[union-attr]

    first_expiry = backend.lookup(_client(chaddr)).expires  # type: ignore[union-attr]
    (renewed,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST, chaddr, ciaddr="10.0.0.5", lease_time=86400
        ),
    )
    assert _type(renewed) is DHCPMessageType.DHCPACK
    assert backend.lookup(_client(chaddr)).expires > first_expiry  # type: ignore[union-attr,operator]

    _send(server, _message(DHCPMessageType.DHCPRELEASE, chaddr, ciaddr="10.0.0.5"))
    assert backend.lookup(_client(chaddr)) is None
    assert server.metrics.leases_offered == 1
    assert server.metrics.leases_allocated == 1
    assert server.metrics.leases_renewed == 1
    assert server.metrics.leases_released == 1


def test_a_backend_that_holds_an_offer_for_another_client_refuses_the_address() -> None:
    backend = _HeaderBackend()
    server = DHCPServer(lease_backend=backend)
    _send(
        server,
        _message(DHCPMessageType.DHCPDISCOVER, _mac(1), requested_ip="10.0.0.5"),
    )
    assert (
        _send(
            server,
            _message(DHCPMessageType.DHCPDISCOVER, _mac(2), requested_ip="10.0.0.5"),
        )
        == []
    )


# --- a backend written before the offered state ------------------------------


class _BeforeTheOfferedState:
    """The four methods `LeaseBackend` had before an offer was a state."""

    def allocate(self, client_id, ip, ttl, options=None):  # type: ignore[no-untyped-def]
        return None

    def lookup(self, client_id):  # type: ignore[no-untyped-def]
        return None

    def release(self, client_id):  # type: ignore[no-untyped-def]
        return False

    def renew(self, client_id, ttl):  # type: ignore[no-untyped-def]
        return None


@pytest.mark.parametrize("server_class", [DHCPServer, AsyncDHCPServer])
def test_a_backend_without_offer_and_commit_is_refused_at_construction(
    server_class: type,
) -> None:
    with pytest.raises(TypeError) as raised:
        server_class(lease_backend=_BeforeTheOfferedState())

    message = str(raised.value)
    assert "_BeforeTheOfferedState" in message
    assert "offer, commit" in message
    assert "LeaseBackend" in message


def test_a_backend_missing_only_one_method_is_named_by_it() -> None:
    class _NoCommit(_BeforeTheOfferedState):
        def offer(self, client_id, ip, hold_seconds, options=None):  # type: ignore[no-untyped-def]
            return None

    with pytest.raises(TypeError, match="it has no commit "):
        DHCPServer(lease_backend=_NoCommit())
