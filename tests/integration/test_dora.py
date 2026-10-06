import contextlib
import socket
import pytest
import ipaddress
from unittest.mock import Mock
from pydhcp import (
    DHCPServer,
    DHCPMessage,
    DHCPOptions,
    DHCPRequestContext,
    NetworkInterface,
)
from pydhcp.packet import DHCPMessageType, DHCPFlags, DHCPOpcode
from pydhcp.options import DHCPOptionCode
from ipaddress import IPv4Address as IPv4
from pydhcp.network import SocketAddress
from conftest import FixedLeaseServer, build_request, running

CHADDR = b"\x11\x22\x33\x44\x55\x66"


class MockDHCPServer(FixedLeaseServer):
    LEASE_SECONDS = 10


@pytest.fixture
def run_dora_server():
    with running(MockDHCPServer(listen=[("127.0.0.1", 0)])) as server:
        yield server


def test_dora_sequence(run_dora_server):
    server_port = run_dora_server.bound_addresses[0].port
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(2.0)

    try:
        # 1. Send DISCOVER
        opts = DHCPOptions()
        opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
        discover = build_request(options=opts, chaddr=CHADDR)
        client.sendto(discover.encode(), ("127.0.0.1", server_port))

        # 2. Recv OFFER
        data, addr = client.recvfrom(2048)
        offer = DHCPMessage.decode(data)
        assert offer.op == DHCPOpcode.BOOTREPLY
        assert (
            offer.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
            == DHCPMessageType.DHCPOFFER
        )
        assert offer.yiaddr == IPv4("127.0.0.1")

        # 3. Send REQUEST
        req_opts = DHCPOptions()
        req_opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPREQUEST
        req_opts[DHCPOptionCode.REQUESTED_IP] = IPv4("127.0.0.1")
        req_opts[DHCPOptionCode.SERVER_IDENTIFIER] = offer.options.get(
            DHCPOptionCode.SERVER_IDENTIFIER
        )

        request = build_request(options=req_opts, chaddr=CHADDR)
        client.sendto(request.encode(), ("127.0.0.1", server_port))

        # 4. Recv ACK
        data, addr = client.recvfrom(2048)
        ack = DHCPMessage.decode(data)
        assert ack.op == DHCPOpcode.BOOTREPLY
        assert (
            ack.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == DHCPMessageType.DHCPACK
        )
        assert ack.yiaddr == IPv4("127.0.0.1")

        assert run_dora_server.metrics.packets_received > 0
        assert run_dora_server.metrics.packets_sent > 0
    finally:
        client.close()


def test_routing_rfc2131():
    server = MockDHCPServer()
    transport_mock = Mock()
    interface = NetworkInterface(
        "eth0", ipaddress.IPv4Interface(("127.0.0.1", 24)), None
    )
    context = DHCPRequestContext(
        transport=transport_mock,
        interface=interface,
        client=SocketAddress("127.0.0.1", 68),
        client_mac=b"\x11\x22\x33\x44\x55\x66",
    )

    # Test case 1: giaddr set (should send to giaddr on port 67)
    opts = DHCPOptions()
    opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    msg = build_request(options=opts, giaddr=IPv4("192.168.1.1"), chaddr=CHADDR)

    server.handle(msg, context)
    args, kwargs = transport_mock.send.call_args
    assert args[1] == IPv4("192.168.1.1")
    assert args[2] == 67
    assert server.metrics.packets_sent == 1

    # Test case 2: ciaddr set (should send to ciaddr on port 68)
    transport_mock.reset_mock()
    msg.giaddr = IPv4("0.0.0.0")
    msg.ciaddr = IPv4("192.168.1.15")
    server.handle(msg, context)
    args, kwargs = transport_mock.send.call_args
    assert args[1] == IPv4("192.168.1.15")
    assert args[2] == 68
    assert server.metrics.packets_sent == 2

    # Test case 3: broadcast flag set (should send to 255.255.255.255 on port 68)
    transport_mock.reset_mock()
    msg.ciaddr = IPv4("0.0.0.0")
    msg.flags = DHCPFlags.BROADCAST
    server.handle(msg, context)
    args, kwargs = transport_mock.send.call_args
    assert args[1] == IPv4("255.255.255.255")
    assert args[2] == 68


def test_relay_agent_information_echoed_in_reply():
    from pydhcp.packet.message import DHCPMessage as _DHCPMessage
    from pydhcp.options.type import RelayAgentInformation, TLVOption

    server = MockDHCPServer()
    transport_mock = Mock()
    interface = NetworkInterface(
        "eth0", ipaddress.IPv4Interface(("127.0.0.1", 24)), None
    )
    context = DHCPRequestContext(
        transport=transport_mock,
        interface=interface,
        client=SocketAddress("127.0.0.1", 68),
        client_mac=b"\x11\x22\x33\x44\x55\x66",
    )

    opts = DHCPOptions()
    opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    relay_info = RelayAgentInformation([TLVOption(1, b"circuit-id")])
    opts[DHCPOptionCode.RELAY_AGENT_INFORMATION] = relay_info
    msg = build_request(options=opts, giaddr=IPv4("192.168.1.1"), chaddr=CHADDR)

    server.handle(msg, context)
    args, kwargs = transport_mock.send.call_args
    assert args[1] == IPv4("192.168.1.1")
    assert args[2] == 67

    reply = _DHCPMessage.decode(memoryview(args[0]))
    replied_relay_info = reply.options.get(
        DHCPOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation
    )
    assert replied_relay_info == relay_info


class MockDHCPServerWithBackend(DHCPServer):
    DEFAULT_PORTS = (6767,)

    def acquire_lease(self, client_id, server_id, msg, *, commit=True):
        from pydhcp.options.type import IPv4AddressOption, U32

        existing = self.lease_backend.lookup(client_id)
        if existing:
            requested_ttl = msg.options.get(
                DHCPOptionCode.IP_ADDRESS_LEASE_TIME, decode=U32
            )
            ttl = int(requested_ttl) if requested_ttl is not None else 3600
            renewed = self.lease_backend.renew(client_id, ttl)
            if renewed:
                return renewed
            return existing

        requested_ip = msg.options.get(
            DHCPOptionCode.REQUESTED_IP, decode=IPv4AddressOption
        )
        requested_ttl = msg.options.get(
            DHCPOptionCode.IP_ADDRESS_LEASE_TIME, decode=U32
        )
        ttl = int(requested_ttl) if requested_ttl is not None else 3600

        ip = requested_ip if requested_ip else IPv4("127.0.0.1")
        options = DHCPOptions()
        options[DHCPOptionCode.SUBNET_MASK] = IPv4("255.255.255.0")
        options[DHCPOptionCode.ROUTER] = [server_id]
        options[DHCPOptionCode.DNS] = [server_id]

        return self.lease_backend.allocate(client_id, ip, ttl, options)


def test_dora_with_lease_persistence(tmp_path):
    from pydhcp import FileLeaseBackend

    filepath = str(tmp_path / "dora_leases.json")
    backend = FileLeaseBackend(filepath=filepath)
    server = MockDHCPServerWithBackend(listen=[("127.0.0.1", 0)], lease_backend=backend)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(2.0)

    with running(server), contextlib.closing(client):
        server_port = server.bound_addresses[0].port

        # 1. Send DISCOVER
        opts = DHCPOptions()
        opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
        opts[DHCPOptionCode.REQUESTED_IP] = IPv4("127.0.0.1")
        discover = build_request(options=opts, chaddr=CHADDR)
        client.sendto(discover.encode(), ("127.0.0.1", server_port))

        # 2. Recv OFFER
        data, addr = client.recvfrom(2048)
        offer = DHCPMessage.decode(data)
        assert offer.op == DHCPOpcode.BOOTREPLY
        assert (
            offer.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
            == DHCPMessageType.DHCPOFFER
        )
        assert offer.yiaddr == IPv4("127.0.0.1")

        # Check backend has a lease allocated
        client_id = discover.client_id()
        lease = backend.lookup(client_id)
        assert lease is not None
        assert lease.ip == IPv4("127.0.0.1")

        # 3. Send REQUEST
        req_opts = DHCPOptions()
        req_opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPREQUEST
        req_opts[DHCPOptionCode.REQUESTED_IP] = IPv4("127.0.0.1")
        req_opts[DHCPOptionCode.SERVER_IDENTIFIER] = offer.options.get(
            DHCPOptionCode.SERVER_IDENTIFIER
        )

        request = build_request(options=req_opts, chaddr=CHADDR)
        client.sendto(request.encode(), ("127.0.0.1", server_port))

        # 4. Recv ACK
        data, addr = client.recvfrom(2048)
        ack = DHCPMessage.decode(data)
        assert ack.op == DHCPOpcode.BOOTREPLY
        assert (
            ack.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == DHCPMessageType.DHCPACK
        )
        assert ack.yiaddr == IPv4("127.0.0.1")

        # Verify persistence: load a new backend from the same file
        new_backend = FileLeaseBackend(filepath=filepath)
        persisted = new_backend.lookup(client_id)
        assert persisted is not None
        assert persisted.ip == IPv4("127.0.0.1")
