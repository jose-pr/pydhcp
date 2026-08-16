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
