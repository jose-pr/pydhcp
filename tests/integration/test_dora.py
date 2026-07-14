import socket
import threading
import time
import pytest
import ipaddress
from datetime import timedelta
from unittest.mock import Mock
from pydhcp import DhcpServer, DhcpMessage, DhcpLease, DhcpOptions, RequestContext, NetworkInterface
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.options import DhcpOptionCode
from pydhcp.network import SocketAddress, IPv4

class MockDhcpServer(DhcpServer):
    DEFAULT_PORTS = (6767,)
    
    def acquire_lease(self, client_id, server_id, msg):
        from datetime import datetime, timedelta
        options = DhcpOptions()
        options[DhcpOptionCode.ROUTER] = IPv4("127.0.0.1")
        return DhcpLease(IPv4("127.0.0.1"), datetime.now() + timedelta(seconds=10), options)

@pytest.fixture
def run_dora_server():
    server = MockDhcpServer(listen=[("127.0.0.1", 0)])
    thread = server.start()
    
    import time
    start_t = time.time()
    while not server._sockets and time.time() - start_t < 2.0:
        time.sleep(0.01)
        
    yield server
    server.stop()
    if thread:
        thread.join(timeout=1.0)

def test_dora_sequence(run_dora_server):
    server_port = run_dora_server._sockets[0].getsockname()[1]
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(2.0)
    
    try:
        # 1. Send DISCOVER
        opts = DhcpOptions()
        opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
        discover = DhcpMessage(
            op=OpCode.BOOTREQUEST,
            htype=HardwareAddressType.ETHERNET,
            hlen=6,
            hops=0,
            xid=0x12345678,
            secs=timedelta(seconds=0),
            flags=Flags.UNICAST,
            ciaddr=IPv4('0.0.0.0'),
            yiaddr=IPv4('0.0.0.0'),
            siaddr=IPv4('0.0.0.0'),
            giaddr=IPv4('0.0.0.0'),
            chaddr=b'\x11\x22\x33\x44\x55\x66',
            sname='',
            file='',
            options=opts
        )
        client.sendto(discover.encode(), ("127.0.0.1", server_port))
        
        # 2. Recv OFFER
        data, addr = client.recvfrom(2048)
        offer = DhcpMessage.decode(data)
        assert offer.op == OpCode.BOOTREPLY
        assert offer.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPOFFER
        assert offer.yiaddr == IPv4("127.0.0.1")
        
        # 3. Send REQUEST
        req_opts = DhcpOptions()
        req_opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPREQUEST
        req_opts[DhcpOptionCode.REQUESTED_IP] = IPv4("127.0.0.1")
        req_opts[DhcpOptionCode.SERVER_IDENTIFIER] = offer.options.get(DhcpOptionCode.SERVER_IDENTIFIER)
        
        request = DhcpMessage(
            op=OpCode.BOOTREQUEST,
            htype=HardwareAddressType.ETHERNET,
            hlen=6,
            hops=0,
            xid=0x12345678,
            secs=timedelta(seconds=0),
            flags=Flags.UNICAST,
            ciaddr=IPv4('0.0.0.0'),
            yiaddr=IPv4('0.0.0.0'),
            siaddr=IPv4('0.0.0.0'),
            giaddr=IPv4('0.0.0.0'),
            chaddr=b'\x11\x22\x33\x44\x55\x66',
            sname='',
            file='',
            options=req_opts
        )
        client.sendto(request.encode(), ("127.0.0.1", server_port))
        
        # 4. Recv ACK
        data, addr = client.recvfrom(2048)
        ack = DhcpMessage.decode(data)
        assert ack.op == OpCode.BOOTREPLY
        assert ack.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
        assert ack.yiaddr == IPv4("127.0.0.1")

        assert run_dora_server.metrics.packets_received > 0
        assert run_dora_server.metrics.packets_sent > 0
    finally:
        client.close()

def test_routing_rfc2131():
    server = MockDhcpServer()
    transport_mock = Mock()
    interface = NetworkInterface("eth0", ipaddress.IPv4Interface(("127.0.0.1", 24)), None)
    context = RequestContext(
        transport=transport_mock,
        interface=interface,
        client=SocketAddress("127.0.0.1", 68),
        client_mac=b'\x11\x22\x33\x44\x55\x66'
    )
    
    # Test case 1: giaddr set (should send to giaddr on port 67)
    opts = DhcpOptions()
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    msg = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x12345678,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4('0.0.0.0'),
        yiaddr=IPv4('0.0.0.0'),
        siaddr=IPv4('0.0.0.0'),
        giaddr=IPv4('192.168.1.1'),
        chaddr=b'\x11\x22\x33\x44\x55\x66',
        sname='',
        file='',
        options=opts
    )
    
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
    msg.flags = Flags.BROADCAST
    server.handle(msg, context)
    args, kwargs = transport_mock.send.call_args
    assert args[1] == IPv4("255.255.255.255")
    assert args[2] == 68


def test_relay_agent_information_echoed_in_reply():
    from pydhcp.packet.message import DhcpMessage as _DhcpMessage
    from pydhcp.options.type import RelayAgentInformation, TlvOption

    server = MockDhcpServer()
    transport_mock = Mock()
    interface = NetworkInterface("eth0", ipaddress.IPv4Interface(("127.0.0.1", 24)), None)
    context = RequestContext(
        transport=transport_mock,
        interface=interface,
        client=SocketAddress("127.0.0.1", 68),
        client_mac=b'\x11\x22\x33\x44\x55\x66'
    )

    opts = DhcpOptions()
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    relay_info = RelayAgentInformation([TlvOption(1, b"circuit-id")])
    opts[DhcpOptionCode.RELAY_AGENT_INFORMATION] = relay_info
    msg = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x12345678,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4('0.0.0.0'),
        yiaddr=IPv4('0.0.0.0'),
        siaddr=IPv4('0.0.0.0'),
        giaddr=IPv4('192.168.1.1'),
        chaddr=b'\x11\x22\x33\x44\x55\x66',
        sname='',
        file='',
        options=opts
    )

    server.handle(msg, context)
    args, kwargs = transport_mock.send.call_args
    assert args[1] == IPv4("192.168.1.1")
    assert args[2] == 67

    reply = _DhcpMessage.decode(memoryview(args[0]))
    replied_relay_info = reply.options.get(
        DhcpOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation
    )
    assert replied_relay_info == relay_info


class MockDhcpServerWithBackend(DhcpServer):
    DEFAULT_PORTS = (6767,)

    def acquire_lease(self, client_id, server_id, msg):
        from pydhcp.options.type import IPv4Address, U32
        existing = self.lease_backend.lookup(client_id)
        if existing:
            requested_ttl = msg.options.get(DhcpOptionCode.IP_ADDRESS_LEASE_TIME, decode=U32)
            ttl = int(requested_ttl) if requested_ttl is not None else 3600
            renewed = self.lease_backend.renew(client_id, ttl)
            if renewed:
                return renewed
            return existing

        requested_ip = msg.options.get(DhcpOptionCode.REQUESTED_IP, decode=IPv4Address)
        requested_ttl = msg.options.get(DhcpOptionCode.IP_ADDRESS_LEASE_TIME, decode=U32)
        ttl = int(requested_ttl) if requested_ttl is not None else 3600
        
        ip = requested_ip if requested_ip else IPv4("127.0.0.1")
        options = DhcpOptions()
        options[DhcpOptionCode.SUBNET_MASK] = IPv4("255.255.255.0")
        options[DhcpOptionCode.ROUTER] = [server_id]
        options[DhcpOptionCode.DNS] = [server_id]
        
        return self.lease_backend.allocate(client_id, ip, ttl, options)


def test_dora_with_lease_persistence(tmp_path):
    from pydhcp import FileLeaseBackend
    filepath = str(tmp_path / "dora_leases.json")
    backend = FileLeaseBackend(filepath=filepath)
    server = MockDhcpServerWithBackend(listen=[("127.0.0.1", 0)], lease_backend=backend)
    
    thread = server.start()
    
    import time
    start_t = time.time()
    while not server._sockets and time.time() - start_t < 2.0:
        time.sleep(0.01)
        
    server_port = server._sockets[0].getsockname()[1]
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(2.0)
    
    try:
        # 1. Send DISCOVER
        opts = DhcpOptions()
        opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
        opts[DhcpOptionCode.REQUESTED_IP] = IPv4("127.0.0.1")
        discover = DhcpMessage(
            op=OpCode.BOOTREQUEST,
            htype=HardwareAddressType.ETHERNET,
            hlen=6,
            hops=0,
            xid=0x12345678,
            secs=timedelta(seconds=0),
            flags=Flags.UNICAST,
            ciaddr=IPv4('0.0.0.0'),
            yiaddr=IPv4('0.0.0.0'),
            siaddr=IPv4('0.0.0.0'),
            giaddr=IPv4('0.0.0.0'),
            chaddr=b'\x11\x22\x33\x44\x55\x66',
            sname='',
            file='',
            options=opts
        )
        client.sendto(discover.encode(), ("127.0.0.1", server_port))
        
        # 2. Recv OFFER
        data, addr = client.recvfrom(2048)
        offer = DhcpMessage.decode(data)
        assert offer.op == OpCode.BOOTREPLY
        assert offer.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPOFFER
        assert offer.yiaddr == IPv4("127.0.0.1")
        
        # Check backend has a lease allocated
        client_id = discover.client_id()
        lease = backend.lookup(client_id)
        assert lease is not None
        assert lease.ip == IPv4("127.0.0.1")
        
        # 3. Send REQUEST
        req_opts = DhcpOptions()
        req_opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPREQUEST
        req_opts[DhcpOptionCode.REQUESTED_IP] = IPv4("127.0.0.1")
        req_opts[DhcpOptionCode.SERVER_IDENTIFIER] = offer.options.get(DhcpOptionCode.SERVER_IDENTIFIER)
        
        request = DhcpMessage(
            op=OpCode.BOOTREQUEST,
            htype=HardwareAddressType.ETHERNET,
            hlen=6,
            hops=0,
            xid=0x12345678,
            secs=timedelta(seconds=0),
            flags=Flags.UNICAST,
            ciaddr=IPv4('0.0.0.0'),
            yiaddr=IPv4('0.0.0.0'),
            siaddr=IPv4('0.0.0.0'),
            giaddr=IPv4('0.0.0.0'),
            chaddr=b'\x11\x22\x33\x44\x55\x66',
            sname='',
            file='',
            options=req_opts
        )
        client.sendto(request.encode(), ("127.0.0.1", server_port))
        
        # 4. Recv ACK
        data, addr = client.recvfrom(2048)
        ack = DhcpMessage.decode(data)
        assert ack.op == OpCode.BOOTREPLY
        assert ack.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
        assert ack.yiaddr == IPv4("127.0.0.1")
        
        # Verify persistence: load a new backend from the same file
        new_backend = FileLeaseBackend(filepath=filepath)
        persisted = new_backend.lookup(client_id)
        assert persisted is not None
        assert persisted.ip == IPv4("127.0.0.1")
        
    finally:
        client.close()
        server.stop()
        if thread:
            thread.join(timeout=1.0)
