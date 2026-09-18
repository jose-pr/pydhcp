import ipaddress
from datetime import datetime, timedelta
from unittest.mock import Mock

from pydhcp import DhcpLease, DhcpMessage, DhcpOptions, NetworkInterface, RequestContext
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.options import DhcpOptionCode
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.network import IPv4, SocketAddress
from pydhcp.server import DhcpServer


def _message(message_type: DhcpMessageType) -> DhcpMessage:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = message_type
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x12345678,
        secs=timedelta(seconds=0),
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


def _context(transport: Mock) -> RequestContext:
    return RequestContext(
        transport=transport,
        interface=NetworkInterface("lo", ipaddress.IPv4Interface("127.0.0.1/24")),
        client=SocketAddress("127.0.0.1", 68),
        client_mac=b"\x00\x11\x22\x33\x44\x55",
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
    assert reply.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPNAK
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
    assert reply.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPOFFER
    assert reply.options.get(DhcpOptionCode.SERVER_IDENTIFIER) is not None
    assert DhcpOptionCode.IP_ADDRESS_LEASE_TIME in reply.options


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
    assert reply.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK


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
    assert reply.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
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
