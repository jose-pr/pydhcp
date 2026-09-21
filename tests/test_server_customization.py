import pytest
import ipaddress
from datetime import datetime, timedelta
from unittest.mock import Mock

from pydhcp import DhcpLease, DhcpMessage, DhcpOptions, NetworkInterface, RequestContext
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.options import DhcpOptionCode
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.network import IPv4, SocketAddress
from pydhcp.server import DhcpServer
from conftest import build_request


def _message(message_type: DhcpMessageType) -> DhcpMessage:
    return build_request(message_type)


def _context(transport: Mock) -> RequestContext:
    return RequestContext(
        transport=transport,
        interface=NetworkInterface("lo", ipaddress.IPv4Interface("127.0.0.1/24")),
        client=SocketAddress("127.0.0.1", 68),
        client_mac=b"\x00\x11\x22\x33\x44\x55",
    )


def _lan_context(transport: Mock) -> RequestContext:
    """A context that is NOT loopback.

    Loopback is a special case for reply delivery -- no ARP to fail, and POSIX
    refuses a broadcast from a 127.0.0.1-bound socket -- so the broadcast rule
    has to be asserted on a normal segment.
    """
    return RequestContext(
        transport=transport,
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
    )


def test_subclass_can_allocate_fixed_lease_and_custom_options() -> None:
    class FixedLeaseServer(DhcpServer):
        def acquire_lease(self, client_id, server_id, msg):
            options = DhcpOptions()
            options[DhcpOptionCode.ROUTER] = [IPv4("127.0.0.1")]
            options[DhcpOptionCode.DNS] = [IPv4("1.1.1.1")]
            return DhcpLease(
                IPv4("127.0.0.10"),
                datetime.now() + timedelta(seconds=3600),
                options,
            )

    transport = Mock()
    server = FixedLeaseServer()
    server.handle(_message(DhcpMessageType.DHCPDISCOVER), _context(transport))

    data, dest, port, _ = transport.send.call_args.args
    response = DhcpMessage.decode(data)
    # Unicast here because this exchange is over loopback, where there is no ARP
    # to fail and POSIX refuses a broadcast anyway. On a real segment the same
    # reply is broadcast -- see test_reply_to_an_unconfigured_client_is_broadcast.
    assert dest == IPv4("127.0.0.10")
    assert port == 68
    assert response.yiaddr == IPv4("127.0.0.10")
    assert response.options.get(DhcpOptionCode.DNS) == [IPv4("1.1.1.1")]


def test_inform_can_customize_options_without_allocating_address() -> None:
    class InformOnlyServer(DhcpServer):
        def get_inform_options(self, server_id, msg):
            options = DhcpOptions()
            options[DhcpOptionCode.DNS] = [IPv4("9.9.9.9")]
            return options

    transport = Mock()
    server = InformOnlyServer()
    server.handle(_message(DhcpMessageType.DHCPINFORM), _context(transport))

    data, dest, port, _ = transport.send.call_args.args
    response = DhcpMessage.decode(data)
    assert dest == IPv4("255.255.255.255")
    assert port == 68
    assert response.yiaddr == IPv4("0.0.0.0")
    assert response.options.get(DhcpOptionCode.DNS) == [IPv4("9.9.9.9")]


class _BackendServer(DhcpServer):
    """Server whose `acquire_lease` only consults the lease backend.

    The stock `acquire_lease` needs a real host interface owning `server_id`,
    which loopback is not on every platform; this keeps the lease-sourced
    response path (the one that used to alias `lease.options`) exercised
    without any interface enumeration.
    """

    def acquire_lease(self, client_id, server_id, msg):
        return self.lease_backend.lookup(client_id)


def _seeded_backend(client_id: str) -> InMemoryLeaseBackend:
    backend = InMemoryLeaseBackend()
    options = DhcpOptions()
    options[DhcpOptionCode.SUBNET_MASK] = IPv4("255.255.255.0")
    options[DhcpOptionCode.ROUTER] = [IPv4("127.0.0.1")]
    options[DhcpOptionCode.DNS] = [IPv4("1.1.1.1")]
    backend.allocate(client_id, IPv4("127.0.0.10"), 3600, options)
    return backend


def test_parameter_request_list_filtering_does_not_delete_lease_options() -> None:
    msg = _message(DhcpMessageType.DHCPDISCOVER)
    # Ask for SUBNET_MASK only: pre-fix this filter wrote through to the lease
    # and permanently deleted ROUTER/DNS from the backend.
    msg.options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = bytearray(
        [int(DhcpOptionCode.SUBNET_MASK)]
    )
    client_id = msg.client_id()
    backend = _seeded_backend(client_id)

    server = _BackendServer(lease_backend=backend)
    server.handle(msg, _context(Mock()))

    stored = backend.lookup(client_id)
    assert stored is not None
    assert DhcpOptionCode.ROUTER in stored.options
    assert DhcpOptionCode.DNS in stored.options
    assert DhcpOptionCode.SUBNET_MASK in stored.options
    # Response-only bookkeeping must never be persisted into the lease.
    assert DhcpOptionCode.DHCP_MESSAGE_TYPE not in stored.options
    assert DhcpOptionCode.SERVER_IDENTIFIER not in stored.options
    assert DhcpOptionCode.IP_ADDRESS_LEASE_TIME not in stored.options
    assert DhcpOptionCode.RELAY_AGENT_INFORMATION not in stored.options


def test_relay_agent_information_echo_is_not_stored_in_the_lease() -> None:
    msg = _message(DhcpMessageType.DHCPREQUEST)
    msg.options[DhcpOptionCode.REQUESTED_IP] = IPv4("127.0.0.10")
    relay_info = bytearray(b"\x01\x04port")
    msg.options[DhcpOptionCode.RELAY_AGENT_INFORMATION] = relay_info
    client_id = msg.client_id()
    backend = _seeded_backend(client_id)
    seeded = backend.lookup(client_id)
    assert seeded is not None
    before = dict(seeded.options.items(decoded=False))

    transport = Mock()
    server = _BackendServer(lease_backend=backend)
    server.handle(msg, _context(transport))

    # The echo reaches the wire ...
    data, _dest, _port, _ = transport.send.call_args.args
    response = DhcpMessage.decode(data)
    assert (
        response.options.get(DhcpOptionCode.RELAY_AGENT_INFORMATION, decode=False)
        == relay_info
    )
    # ... but the stored lease is byte-for-byte what it was before the exchange.
    stored = backend.lookup(client_id)
    assert stored is not None
    assert dict(stored.options.items(decoded=False)) == before


def test_inform_does_not_strip_lease_time_from_the_stored_lease() -> None:
    msg = _message(DhcpMessageType.DHCPINFORM)
    client_id = msg.client_id()
    backend = _seeded_backend(client_id)
    seeded = backend.lookup(client_id)
    assert seeded is not None
    seeded.options[DhcpOptionCode.IP_ADDRESS_LEASE_TIME] = 3600

    server = _BackendServer(lease_backend=backend)
    server.handle(msg, _context(Mock()))

    stored = backend.lookup(client_id)
    assert stored is not None
    assert DhcpOptionCode.IP_ADDRESS_LEASE_TIME in stored.options


# --- DHCPNAK construction and delivery (RFC 2131 4.3.2 / Table 3) ---


class _NakServer(DhcpServer):
    """Refuses every request, so _filter_and_send takes the NAK path."""

    def acquire_lease(self, client_id, server_id, msg):
        return DhcpLease(
            IPv4("10.0.0.10"), datetime.now() + timedelta(seconds=3600), DhcpOptions()
        )


def _nak_request(giaddr: str = "0.0.0.0", requested: str = "10.0.0.99") -> DhcpMessage:
    """A SELECTING DHCPREQUEST asking for an address the server will not grant.

    The server identifier names this server, which is what puts the request in
    SELECTING rather than INIT-REBOOT: an INIT-REBOOT request from a client the
    server has no record of must be answered with silence, not a NAK
    (RFC 2131 4.3.2).
    """
    msg = _message(DhcpMessageType.DHCPREQUEST)
    msg.options[DhcpOptionCode.REQUESTED_IP] = IPv4(requested)
    msg.options[DhcpOptionCode.SERVER_IDENTIFIER] = IPv4("127.0.0.1")
    msg.giaddr = IPv4(giaddr)
    return msg


def _sent(transport: Mock) -> tuple[DhcpMessage, str, int]:
    data, dest, port, _ = transport.send.call_args.args
    return DhcpMessage.decode(bytearray(data)), str(dest), port


def test_nak_is_broadcast_when_giaddr_is_zero() -> None:
    """The client may hold no usable address, so a unicast NAK never arrives."""
    transport = Mock()
    server = _NakServer()
    server.handle(_nak_request(), _context(transport))

    reply, dest, _port = _sent(transport)
    assert (
        reply.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPNAK
    )
    assert dest == "255.255.255.255"


def test_nak_carries_no_address_and_no_lease_time() -> None:
    """RFC 2131 Table 3: a NAK has yiaddr 0, ciaddr 0 and no lease time -- it is
    a refusal, not an offer of the address being refused."""
    transport = Mock()
    server = _NakServer()
    server.handle(_nak_request(), _context(transport))

    reply, _dest, _port = _sent(transport)
    assert reply.yiaddr == IPv4("0.0.0.0")
    assert reply.ciaddr == IPv4("0.0.0.0")
    assert reply.siaddr == IPv4("0.0.0.0")
    assert DhcpOptionCode.IP_ADDRESS_LEASE_TIME not in reply.options
    assert reply.options.get(DhcpOptionCode.SERVER_IDENTIFIER) is not None


def test_nak_through_a_relay_sets_the_broadcast_bit() -> None:
    """RFC 2131 4.3.2: with giaddr set the server MUST set the broadcast bit and
    send to the relay on port 67."""
    transport = Mock()
    server = _NakServer()
    server.handle(_nak_request(giaddr="10.0.0.1"), _context(transport))

    reply, dest, port = _sent(transport)
    assert dest == "10.0.0.1"
    assert port == 67
    assert reply.flags is Flags.BROADCAST


# --- RFC 3046 2.2: the option 82 echo survives the request-list filter ---


def test_relay_agent_information_is_echoed_even_when_a_request_list_is_sent() -> None:
    """Practically every client sends option 55, and the echo was filtered out by
    it -- so relays that validate the echo dropped every reply."""

    class LeaseServer(DhcpServer):
        def acquire_lease(self, client_id, server_id, msg):
            return DhcpLease(
                IPv4("10.0.0.10"),
                datetime.now() + timedelta(seconds=3600),
                DhcpOptions(),
            )

    msg = _message(DhcpMessageType.DHCPDISCOVER)
    msg.options[DhcpOptionCode.RELAY_AGENT_INFORMATION] = bytearray(b"\x01\x04port")
    msg.options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = bytearray(
        [DhcpOptionCode.SUBNET_MASK, DhcpOptionCode.ROUTER]
    )
    transport = Mock()
    LeaseServer().handle(msg, _context(transport))

    reply, _dest, _port = _sent(transport)
    assert reply.options.get(
        DhcpOptionCode.RELAY_AGENT_INFORMATION, decode=False
    ) == bytearray(b"\x01\x04port")
    # The machinery options survive too, or the reply is not a usable DHCP message.
    assert (
        reply.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPOFFER
    )
    assert reply.options.get(DhcpOptionCode.SERVER_IDENTIFIER) is not None
    assert DhcpOptionCode.IP_ADDRESS_LEASE_TIME in reply.options


def _reply_option_codes(transport: Mock) -> set:
    reply, _dest, _port = _sent(transport)
    return {int(code) for code, _ in reply.options.items(decoded=False)}


def test_reply_carries_exactly_the_requested_options_and_the_machinery() -> None:
    """RFC 2131 4.3.1: the reply carries the requested parameters, and no more.

    Every existing assertion about option 55 is one-sided -- "this option
    survived the filter" or "the lease still has it". Nothing said what the
    reply must *not* contain, so a filter that stopped filtering, or was
    bypassed entirely, passed the whole suite while leaking every option the
    server holds to a client that asked for two of them. On a real server that
    is the lease's full option set, which is why the seeded lease here carries
    a DNS entry the request never asks for.

    The three machinery options are the documented exceptions (4.3.1: message
    type, server identifier, lease time), so the expected set is exactly the
    request list plus those.
    """
    msg = _message(DhcpMessageType.DHCPDISCOVER)
    msg.options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = bytearray(
        [int(DhcpOptionCode.SUBNET_MASK), int(DhcpOptionCode.ROUTER)]
    )
    backend = _seeded_backend(msg.client_id())
    transport = Mock()

    _BackendServer(lease_backend=backend).handle(msg, _context(transport))

    assert _reply_option_codes(transport) == {
        int(DhcpOptionCode.SUBNET_MASK),
        int(DhcpOptionCode.ROUTER),
        int(DhcpOptionCode.DHCP_MESSAGE_TYPE),
        int(DhcpOptionCode.SERVER_IDENTIFIER),
        int(DhcpOptionCode.IP_ADDRESS_LEASE_TIME),
    }


def test_a_client_that_sends_no_request_list_is_told_everything() -> None:
    """The other half of the filter: no option 55 means no filtering.

    Asserted alongside the exact-set test above so that "the filter dropped
    everything" and "the filter dropped nothing" cannot both pass. RFC 2131
    3.5: absent a request list the server supplies the parameters it has.
    """
    msg = _message(DhcpMessageType.DHCPDISCOVER)
    assert DhcpOptionCode.PARAMETER_REQUEST_LIST not in msg.options
    backend = _seeded_backend(msg.client_id())
    transport = Mock()

    _BackendServer(lease_backend=backend).handle(msg, _context(transport))

    assert _reply_option_codes(transport) == {
        int(DhcpOptionCode.SUBNET_MASK),
        int(DhcpOptionCode.ROUTER),
        int(DhcpOptionCode.DNS),
        int(DhcpOptionCode.DHCP_MESSAGE_TYPE),
        int(DhcpOptionCode.SERVER_IDENTIFIER),
        int(DhcpOptionCode.IP_ADDRESS_LEASE_TIME),
    }


# --- RFC 2131 4.3.2 / 4.3.5: INIT-REBOOT silence and DHCPINFORM ---


def test_init_reboot_from_an_unknown_client_is_answered_with_silence() -> None:
    """RFC 2131 4.3.2: with no record of the client the server MUST remain
    silent. Answering makes it a rogue server for clients that belong to another
    server on the same segment."""
    msg = _message(DhcpMessageType.DHCPREQUEST)
    msg.options[DhcpOptionCode.REQUESTED_IP] = IPv4("10.0.0.99")  # no server id
    transport = Mock()

    _NakServer().handle(msg, _context(transport))

    transport.send.assert_not_called()


def test_init_reboot_from_a_known_client_is_answered() -> None:
    """The silence rule keys on having no record, not on the message shape."""
    server = _NakServer()
    msg = _message(DhcpMessageType.DHCPREQUEST)
    msg.options[DhcpOptionCode.REQUESTED_IP] = IPv4("10.0.0.10")
    server.lease_backend.allocate(msg.client_id(), IPv4("10.0.0.10"), 3600)
    transport = Mock()

    server.handle(msg, _context(transport))

    reply, _dest, _port = _sent(transport)
    assert (
        reply.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
    )


def test_inform_does_not_create_a_lease() -> None:
    """RFC 2131 4.3.5: an INFORM client already has its address and is asking
    only for configuration. Allocating let an INFORM flood grow the store."""

    class AllocatingServer(DhcpServer):
        """Allocates through the backend, as the stock acquire_lease does."""

        def acquire_lease(self, client_id, server_id, msg):
            return self.lease_backend.allocate(client_id, IPv4("10.0.0.10"), 3600)

    server = AllocatingServer()
    msg = _message(DhcpMessageType.DHCPINFORM)
    msg.ciaddr = IPv4("10.0.0.77")
    transport = Mock()

    server.handle(msg, _context(transport))

    reply, _dest, _port = _sent(transport)
    assert (
        reply.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
    )
    assert reply.yiaddr == IPv4("0.0.0.0")
    assert DhcpOptionCode.IP_ADDRESS_LEASE_TIME not in reply.options
    assert server.lease_backend.lookup(msg.client_id()) is None


def test_inform_uses_the_documented_allocation_free_hook() -> None:
    """get_inform_options is documented as the INFORM path's hook, but a client
    that happened to hold a lease bypassed it entirely."""

    class InformServer(_NakServer):
        def get_inform_options(self, server_id, msg):
            options = DhcpOptions()
            options[DhcpOptionCode.DNS] = [IPv4("9.9.9.9")]
            return options

    server = InformServer()
    msg = _message(DhcpMessageType.DHCPINFORM)
    msg.ciaddr = IPv4("10.0.0.77")
    server.lease_backend.allocate(msg.client_id(), IPv4("10.0.0.10"), 3600)
    transport = Mock()

    server.handle(msg, _context(transport))

    reply, _dest, _port = _sent(transport)
    assert reply.options.get(DhcpOptionCode.DNS) == [IPv4("9.9.9.9")]


# --- Stock allocator safety (RFC 2131 4.3.1/4.3.3) ---


class _LoopbackServer(DhcpServer):
    """Stock allocator, but with a served interface that exists in tests.

    The real acquire_lease resolves server_id against the host's interfaces;
    pinning one keeps the address-validation logic under test without depending
    on whatever this machine happens to have configured.
    """

    NETWORK = ipaddress.IPv4Interface("10.0.0.1/24")

    def acquire_lease(self, client_id, server_id, msg):
        interface = NetworkInterface("test0", self.NETWORK)
        requested = msg.options.get(DhcpOptionCode.REQUESTED_IP)
        ip = IPv4(str(requested)) if requested is not None else msg.ciaddr
        refusal = self._address_refusal(ip, interface, client_id)
        if refusal is not None:
            return None
        return self.lease_backend.allocate(client_id, ip, 3600)


def _request_for(ip: str, client: bytes = b"\x01\x02\x03") -> DhcpMessage:
    msg = _message(DhcpMessageType.DHCPDISCOVER)
    msg.options[DhcpOptionCode.REQUESTED_IP] = IPv4(ip)
    msg.options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray(client)
    return msg


@pytest.mark.parametrize(
    "address,reason",
    [
        ("192.168.5.5", "outside the served network"),
        ("10.0.0.1", "the server's own address"),
        ("10.0.0.0", "the network address"),
        ("10.0.0.255", "the broadcast address"),
    ],
)
def test_allocator_refuses_addresses_it_must_not_hand_out(address, reason) -> None:
    server = _LoopbackServer()

    assert (
        server.acquire_lease("client-a", IPv4("10.0.0.1"), _request_for(address))
        is None
    )


def test_allocator_refuses_an_address_another_client_holds() -> None:
    server = _LoopbackServer()
    server.lease_backend.allocate("client-a", IPv4("10.0.0.50"), 3600)

    assert (
        server.acquire_lease("client-b", IPv4("10.0.0.1"), _request_for("10.0.0.50"))
        is None
    )
    # The holder itself is still served.
    assert (
        server.acquire_lease("client-a", IPv4("10.0.0.1"), _request_for("10.0.0.50"))
        is not None
    )


def test_allocator_grants_a_free_in_subnet_address() -> None:
    server = _LoopbackServer()

    lease = server.acquire_lease(
        "client-a", IPv4("10.0.0.1"), _request_for("10.0.0.50")
    )

    assert lease is not None and lease.ip == IPv4("10.0.0.50")


def test_declined_address_is_quarantined_and_not_reoffered() -> None:
    """RFC 2131 4.3.3: the client found the address in use, so the server must
    not hand it out again -- releasing the binding alone left it first in line."""
    server = _LoopbackServer()
    server.lease_backend.allocate("client-a", IPv4("10.0.0.50"), 3600)

    decline = _message(DhcpMessageType.DHCPDECLINE)
    decline.options[DhcpOptionCode.REQUESTED_IP] = IPv4("10.0.0.50")
    server.handle(decline, _context(Mock()))

    assert IPv4("10.0.0.50") in server._declined
    assert (
        server.acquire_lease("client-b", IPv4("10.0.0.1"), _request_for("10.0.0.50"))
        is None
    )


def test_quarantine_is_bounded_and_expires() -> None:
    server = _LoopbackServer()
    server.MAX_DECLINED_ADDRESSES = 3
    for last in range(5):
        server.quarantine_address(IPv4(f"10.0.0.{10 + last}"))
    assert len(server._declined) == 3
    assert IPv4("10.0.0.10") not in server._declined

    server.DECLINE_QUARANTINE_SECONDS = -1.0  # already elapsed
    server.quarantine_address(IPv4("10.0.0.60"))
    assert (
        server.acquire_lease("client-a", IPv4("10.0.0.1"), _request_for("10.0.0.60"))
        is not None
    )


def test_client_identifier_is_echoed() -> None:
    """RFC 6842: when the client sends option 61 the server MUST return it."""
    server = _LoopbackServer()
    transport = Mock()

    server.handle(
        _request_for("10.0.0.50", client=b"\x01\xaa\xbb"), _context(transport)
    )

    reply, _dest, _port = _sent(transport)
    assert reply.options.get(
        DhcpOptionCode.CLIENT_IDENTIFIER, decode=False
    ) == bytearray(b"\x01\xaa\xbb")


def test_reply_to_an_unconfigured_client_is_broadcast() -> None:
    """A client with no address cannot answer ARP for yiaddr.

    RFC 2131 4.1 has the server unicast to the client's hardware address and
    yiaddr when the broadcast flag is clear, which needs an L2 send the plain UDP
    transport cannot do -- the kernel drops the reply with no error. Measured
    against ISC dhclient 4.4.3: every OFFER was logged as sent to yiaddr:68 and
    the client saw none of them.
    """
    transport = Mock()
    msg = _message(DhcpMessageType.DHCPDISCOVER)  # flags=UNICAST, ciaddr=0
    _NakServer().handle(msg, _lan_context(transport))

    _reply, dest, _port = _sent(transport)
    assert dest == "255.255.255.255"


def test_reply_over_loopback_is_unicast() -> None:
    """Loopback inverts the trade-off: no ARP to fail, and POSIX refuses a
    broadcast from a socket bound to 127.0.0.1 -- which hung this suite on Linux
    while it passed on Windows."""
    transport = Mock()
    _NakServer().handle(_message(DhcpMessageType.DHCPDISCOVER), _context(transport))

    _reply, dest, _port = _sent(transport)
    assert dest == "10.0.0.10"


def test_unicast_to_unconfigured_client_can_be_opted_into() -> None:
    """For a transport that can address the client's hardware address."""

    class L2Server(_NakServer):
        UNICAST_TO_UNCONFIGURED_CLIENT = True

    transport = Mock()
    L2Server().handle(_message(DhcpMessageType.DHCPDISCOVER), _lan_context(transport))

    _reply, dest, _port = _sent(transport)
    assert dest == "10.0.0.10"


def test_configured_client_still_gets_a_unicast_reply() -> None:
    """ciaddr set means the client holds the address and ARP resolves."""
    transport = Mock()
    msg = _message(DhcpMessageType.DHCPREQUEST)
    msg.options[DhcpOptionCode.SERVER_IDENTIFIER] = IPv4("127.0.0.1")
    msg.options[DhcpOptionCode.REQUESTED_IP] = IPv4("10.0.0.10")
    msg.ciaddr = IPv4("10.0.0.10")
    _NakServer().handle(msg, _context(transport))

    _reply, dest, _port = _sent(transport)
    assert dest == "10.0.0.10"


# --- lease time is the server's policy, not the client's choice ---


def _discover_requesting(seconds=None):
    from pydhcp.options import type as _optype

    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    if seconds is not None:
        options[DhcpOptionCode.IP_ADDRESS_LEASE_TIME] = _optype.U32(seconds)
    return build_request(options=options, xid=0x1234)


def test_client_cannot_choose_its_own_lease_length():
    """RFC 2131 §4.3.1 honours the request only "if acceptable to local policy".

    There was no policy: the requested value went straight to the backend, so a
    client asking for 0xFFFFFFFE held the address until 2162.
    """
    server = DhcpServer(listen=("127.0.0.1", 0))
    try:
        assert server.lease_seconds(_discover_requesting(None)) == (
            server.DEFAULT_LEASE_SECONDS
        )
        assert server.lease_seconds(_discover_requesting(3600)) == 3600
        # clamped at both ends
        assert server.lease_seconds(_discover_requesting(1)) == server.MIN_LEASE_SECONDS
        assert server.lease_seconds(_discover_requesting(999_999)) == (
            server.MAX_LEASE_SECONDS
        )
        assert server.lease_seconds(_discover_requesting(0xFFFFFFFE)) == (
            server.MAX_LEASE_SECONDS
        )
    finally:
        server.close()


def test_infinity_sentinel_is_infinity_not_136_years():
    """RFC 2132 §3.3: 0xFFFFFFFF means infinite, not 4294967295 seconds.

    Read literally it became an expiry in 2162, and the reply then advertised
    4294967294 -- one second short of the sentinel, so the client was told a
    different number than it asked for.
    """
    import math

    class Permissive(DhcpServer):
        ALLOW_INFINITE_LEASE = True

    denied = DhcpServer(listen=("127.0.0.1", 0))
    allowed = Permissive(listen=("127.0.0.1", 0))
    try:
        # Default policy: not granted, but clamped -- never a 136-year lease.
        assert denied.lease_seconds(_discover_requesting(0xFFFFFFFF)) == (
            denied.MAX_LEASE_SECONDS
        )
        # Opted in: actually infinite, which the reply path renders as the
        # sentinel rather than as a finite countdown.
        assert math.isinf(allowed.lease_seconds(_discover_requesting(0xFFFFFFFF)))
    finally:
        denied.close()
        allowed.close()


def test_lease_policy_is_overridable():
    """The knobs are the supported way to change it, not editing the method."""

    class Corporate(DhcpServer):
        DEFAULT_LEASE_SECONDS = 7200
        MIN_LEASE_SECONDS = 300
        MAX_LEASE_SECONDS = 4 * 3600

    server = Corporate(listen=("127.0.0.1", 0))
    try:
        assert server.lease_seconds(_discover_requesting(None)) == 7200
        assert server.lease_seconds(_discover_requesting(10)) == 300
        assert server.lease_seconds(_discover_requesting(86400)) == 4 * 3600
    finally:
        server.close()


def test_base_server_does_not_claim_to_be_a_router_or_resolver():
    """The default option set used to set ROUTER and DNS to the server's own IP.

    That is a guess, and on an ordinary host a wrong one: every client was told
    to send all off-link traffic and every name lookup to a machine that routes
    and resolves nothing, so it had neither connectivity nor name resolution.
    Omitting them leaves whatever the client already has, which is recoverable.
    """
    interface = _servable_interface()

    server = DhcpServer(listen=("127.0.0.1", 0))
    try:
        wanted = _free_host_in(interface)
        lease = server.acquire_lease(
            "client-a", interface.ip, _discover_requesting_ip(wanted)
        )
        assert lease is not None
        assert DhcpOptionCode.ROUTER not in lease.options
        assert DhcpOptionCode.DNS not in lease.options
        # what it does know first-hand is still offered
        assert DhcpOptionCode.SUBNET_MASK in lease.options
        assert DhcpOptionCode.BROADCAST_ADDRESS in lease.options

        inform = server.get_inform_options(
            interface.ip, _discover_requesting_ip(wanted)
        )
        assert DhcpOptionCode.ROUTER not in inform
        assert DhcpOptionCode.DNS not in inform
    finally:
        server.close()


def test_relayed_client_on_another_subnet_is_refused_not_misconfigured():
    """A server with no configuration for the client's subnet must not guess.

    The concern was that a relayed client would receive the *server's* mask and
    router, unreachable from its own segment. It cannot: the requested address
    is outside the served network, so the allocator refuses it outright rather
    than answering with values that do not apply.
    """
    interface = _servable_interface()

    server = DhcpServer(listen=("127.0.0.1", 0))
    try:
        msg = _discover_requesting_ip("192.0.2.50")
        msg.giaddr = IPv4("192.0.2.1")
        assert server.acquire_lease("client-b", interface.ip, msg) is None
    finally:
        server.close()


def _discover_requesting_ip(ip):
    from pydhcp.options import type as _optype

    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    options[DhcpOptionCode.REQUESTED_IP] = _optype.IPv4Address(ip)
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x1234,
        secs=timedelta(0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        sname="",
        file="",
        options=options,
    )


def _servable_interface():
    """A host interface whose network has a spare address to hand out.

    Not simply "the first non-loopback one": this machine's WSL instance puts
    10.255.255.254/32 first, a host route with no room in it at all, so asking
    for network_address + 50 was refused for being off-subnet -- on Linux only,
    while the same test passed on Windows.
    """
    from pydhcp.network import host_ip_interfaces

    for interface in host_ip_interfaces(lambda i: not i.ip.is_loopback):
        if interface.network.prefixlen <= 29:
            return interface
    pytest.skip("no host interface with a usable subnet to serve from")


def _free_host_in(interface):
    """An address in `interface`'s network the allocator will accept."""
    for candidate in interface.network.hosts():
        if candidate != interface.ip:
            return str(candidate)
    raise AssertionError(  # pragma: no cover - guarded by _servable_interface
        f"no usable host address in {interface.network}"
    )
