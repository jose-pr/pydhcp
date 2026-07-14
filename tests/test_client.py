import ipaddress
import time
from datetime import datetime, timedelta
from unittest.mock import Mock

from pydhcp import DhcpClient, DhcpLease, DhcpMessage, DhcpOptions, DhcpServer, NetworkInterface, RequestContext
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4, SocketAddress


CHADDR = b"\x00\x11\x22\x33\x44\x55"


def _context() -> RequestContext:
    return RequestContext(
        transport=Mock(),
        interface=NetworkInterface("lo", ipaddress.IPv4Interface("127.0.0.1/24")),
        client=SocketAddress("127.0.0.1", 67),
        client_mac=CHADDR,
    )


def _reply(xid: int, message_type: DhcpMessageType = DhcpMessageType.DHCPOFFER) -> DhcpMessage:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = message_type
    return DhcpMessage(
        op=OpCode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=xid,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("192.0.2.10"),
        siaddr=IPv4("192.0.2.1"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=CHADDR,
        sname="",
        file="",
        options=options,
    )


def _assert_round_trips(message: DhcpMessage, message_type: DhcpMessageType) -> None:
    restored = DhcpMessage.decode(message.encode())
    assert restored.op == OpCode.BOOTREQUEST
    assert restored.chaddr == CHADDR
    assert restored.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == message_type


def test_client_builds_standard_request_messages() -> None:
    client = DhcpClient(listen=("127.0.0.1", 6768))

    discover = client.build_discover(
        CHADDR,
        xid=0x12345678,
        client_identifier=b"\x01" + CHADDR,
        parameter_request_list=[DhcpOptionCode.SUBNET_MASK, DhcpOptionCode.ROUTER],
    )
    assert discover.flags == Flags.BROADCAST
    assert discover.options.get(DhcpOptionCode.CLIENT_IDENTIFIER, decode=False) == bytearray(b"\x01" + CHADDR)
    _assert_round_trips(discover, DhcpMessageType.DHCPDISCOVER)

    request = client.build_request(
        CHADDR,
        xid=0x12345679,
        requested_ip=IPv4("192.0.2.10"),
        server_identifier="192.0.2.1",
    )
    assert request.options.get(DhcpOptionCode.REQUESTED_IP) == IPv4("192.0.2.10")
    assert request.options.get(DhcpOptionCode.SERVER_IDENTIFIER) == IPv4("192.0.2.1")
    _assert_round_trips(request, DhcpMessageType.DHCPREQUEST)

    inform = client.build_inform(CHADDR, ciaddr="192.0.2.20", xid=0x1234567A)
    assert inform.ciaddr == IPv4("192.0.2.20")
    assert DhcpOptionCode.REQUESTED_IP not in inform.options
    _assert_round_trips(inform, DhcpMessageType.DHCPINFORM)

    release = client.build_release(CHADDR, ciaddr="192.0.2.20", server_identifier="192.0.2.1")
    assert release.flags == Flags.UNICAST
    _assert_round_trips(release, DhcpMessageType.DHCPRELEASE)

    decline = client.build_decline(CHADDR, requested_ip="192.0.2.30", server_identifier="192.0.2.1")
    assert decline.options.get(DhcpOptionCode.REQUESTED_IP) == IPv4("192.0.2.30")
    _assert_round_trips(decline, DhcpMessageType.DHCPDECLINE)


def test_client_queues_matching_bootreply() -> None:
    seen = []

    class RecordingClient(DhcpClient):
        def on_reply(self, msg, context):
            seen.append((msg, context))

    client = RecordingClient(listen=("127.0.0.1", 6768))
    client._pending_xids.add(0xAABBCCDD)
    context = _context()

    client.handle(_reply(0x11111111), context)
    assert client.next_reply(timeout=0) is None

    accepted = _reply(0xAABBCCDD)
    client.handle(accepted, context)

    assert seen == [(accepted, context)]
    assert client.next_reply(timeout=0) == (accepted, context)
    assert client.drain_replies() == []


def test_client_send_uses_bound_udp_transport(monkeypatch) -> None:
    client = DhcpClient(listen=("127.0.0.1", 6768))
    socket = object()
    client._sockets.append(socket)  # type: ignore[arg-type]
    transport = Mock()
    transport.send.return_value = 300
    monkeypatch.setattr("pydhcp.client.UdpTransport", lambda sock: transport)

    message = client.build_discover(CHADDR, xid=0xCAFEBABE)

    assert client.send(message, destination="192.0.2.1", port=6767) == 300
    data, dest, port, mac = transport.send.call_args.args
    assert DhcpMessage.decode(data).xid == 0xCAFEBABE
    assert dest == IPv4("192.0.2.1")
    assert port == 6767
    assert mac == CHADDR
    assert 0xCAFEBABE in client._pending_xids


class _FixedLeaseServer(DhcpServer):
    DEFAULT_PORTS = (6767,)

    def acquire_lease(self, client_id, server_id, msg):
        options = DhcpOptions()
        options[DhcpOptionCode.ROUTER] = IPv4("127.0.0.1")
        return DhcpLease(IPv4("127.0.0.1"), datetime.now() + timedelta(seconds=60), options)


def _wait_bound(listener, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while not listener._sockets and time.time() < deadline:
        time.sleep(0.01)


def test_client_dora_against_real_server() -> None:
    server = _FixedLeaseServer(listen=[("127.0.0.1", 0)])
    thread = server.start()
    _wait_bound(server)
    server_port = server._sockets[0].getsockname()[1]

    client = DhcpClient(listen=("127.0.0.1", 0))
    client_thread = client.start()
    _wait_bound(client)
    try:
        ack = client.dora(CHADDR, timeout=2.0, retries=1, destination="127.0.0.1", port=server_port)
        assert ack is not None
        assert ack.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
        assert ack.yiaddr == IPv4("127.0.0.1")
    finally:
        client.stop()
        if client_thread:
            client_thread.join(timeout=1.0)
        server.stop()
        if thread:
            thread.join(timeout=1.0)


def test_client_discover_offer_returns_none_without_server() -> None:
    client = DhcpClient(listen=("127.0.0.1", 0))
    offer = client.discover_offer(CHADDR, timeout=0.2, retries=0, destination="127.0.0.1", port=6767)
    assert offer is None
