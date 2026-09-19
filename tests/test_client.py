import ipaddress
import time
from datetime import datetime, timedelta
from unittest.mock import Mock

from pydhcp import (
    DhcpClient,
    DhcpLease,
    DhcpMessage,
    DhcpOptions,
    DhcpServer,
    NetworkInterface,
    RequestContext,
)
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


def _reply(
    xid: int, message_type: DhcpMessageType = DhcpMessageType.DHCPOFFER
) -> DhcpMessage:
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
    assert discover.options.get(
        DhcpOptionCode.CLIENT_IDENTIFIER, decode=False
    ) == bytearray(b"\x01" + CHADDR)
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

    release = client.build_release(
        CHADDR, ciaddr="192.0.2.20", server_identifier="192.0.2.1"
    )
    assert release.flags == Flags.UNICAST
    _assert_round_trips(release, DhcpMessageType.DHCPRELEASE)

    decline = client.build_decline(
        CHADDR, requested_ip="192.0.2.30", server_identifier="192.0.2.1"
    )
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
        return DhcpLease(
            IPv4("127.0.0.1"), datetime.now() + timedelta(seconds=60), options
        )


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
        ack = client.dora(
            CHADDR,
            timeout=2.0,
            retries=1,
            destination="127.0.0.1",
            port=server_port,
            broadcast=False,
        )
        assert ack is not None
        assert (
            ack.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
        )
        assert ack.yiaddr == IPv4("127.0.0.1")
    finally:
        client.stop()
        if client_thread:
            client_thread.join(timeout=1.0)
        server.stop()
        if thread:
            thread.join(timeout=1.0)


def test_client_discover_offer_returns_none_without_server() -> None:
    # `with` so the client's socket is closed: this test leaked a bound socket
    # on every run, which is what made the suite fail under
    # `-W error::ResourceWarning`.
    with DhcpClient(listen=("127.0.0.1", 0)) as client:
        offer = client.discover_offer(
            CHADDR, timeout=0.2, retries=0, destination="127.0.0.1", port=6767
        )
    assert offer is None


# --- the client must stay the same client across a DORA ---


def _canned_offer(xid, chaddr=CHADDR):
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPOFFER
    options[DhcpOptionCode.SERVER_IDENTIFIER] = IPv4("10.0.0.1")
    return DhcpMessage(
        op=OpCode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=xid,
        secs=timedelta(0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("10.0.0.50"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=chaddr,
        sname="",
        file="",
        options=options,
    )


class _RecordingClient(DhcpClient):
    """Captures what would go on the wire; answers a DISCOVER with an OFFER."""

    def __init__(self, *args, offer_has_server_id=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.sent = []
        self.offer_has_server_id = offer_has_server_id

    def send(self, message, destination=IPv4("255.255.255.255"), port=67):
        self.sent.append(message)
        self._pending_xids.add(message.xid)
        if message.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) is (
            DhcpMessageType.DHCPDISCOVER
        ):
            offer = _canned_offer(message.xid)
            if not self.offer_has_server_id:
                del offer.options[int(DhcpOptionCode.SERVER_IDENTIFIER)]
            self._replies.put((offer, None))
        return 0


def test_dora_repeats_the_client_id_and_parameter_list_in_the_request():
    """RFC 2131 §4.2 and §4.4.1 are both MUSTs.

    The identifier is what the server keys the lease on: sending the DISCOVER
    under a supplied client id and the REQUEST under htype+chaddr made pydhcp's
    own server see two different clients, so the OFFER and the REQUEST were
    allocated separately.
    """
    cid = b"\xff\xde\xad\xbe\xef"
    prl = [DhcpOptionCode.SUBNET_MASK, DhcpOptionCode.ROUTER]

    client = _RecordingClient(listen=("127.0.0.1", 0))
    client.dora(
        CHADDR,
        timeout=0.2,
        retries=0,
        client_identifier=cid,
        parameter_request_list=prl,
    )

    assert len(client.sent) == 2, [
        str(m.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)) for m in client.sent
    ]
    discover, request = client.sent
    assert request.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) is (
        DhcpMessageType.DHCPREQUEST
    )
    assert request.options.get(DhcpOptionCode.CLIENT_IDENTIFIER, decode=False) == cid
    assert request.options.get(DhcpOptionCode.PARAMETER_REQUEST_LIST, decode=False)
    # and the two messages are the same client as far as a server is concerned
    assert request.client_id() == discover.client_id()


def test_dora_refuses_an_offer_without_a_server_identifier():
    """RFC 2131 §4.3.2: a SELECTING REQUEST carries option 54.

    Without it the REQUEST asks every server on the segment to answer, and
    pydhcp sent one anyway with the option silently absent.
    """
    client = _RecordingClient(listen=("127.0.0.1", 0), offer_has_server_id=False)

    assert client.dora(CHADDR, timeout=0.2, retries=0) is None
    types = [m.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) for m in client.sent]
    assert DhcpMessageType.DHCPREQUEST not in types


def test_client_reply_queue_is_bounded_and_counts_what_it_drops():
    """An idle client accepts every BOOTREPLY so `on_reply` works as an observer.

    That is deliberate, but it used to be an unbounded queue: on a busy segment
    with nobody calling drain_replies(), memory grew without limit.
    """
    client = DhcpClient(listen=("127.0.0.1", 0))
    context = Mock()

    for index in range(client.MAX_QUEUED_REPLIES + 50):
        client.handle(_canned_offer(index), context)

    assert client._replies.qsize() == client.MAX_QUEUED_REPLIES
    assert client.metrics.replies_dropped_overflow == 50
    # the newest replies are the ones kept
    kept = {msg.xid for msg, _ in client.drain_replies()}
    assert max(kept) == client.MAX_QUEUED_REPLIES + 49


def test_pending_xids_do_not_accumulate_across_exchanges():
    """A spent xid stayed acceptable forever, and the set only ever grew.

    These go out as broadcasts, so the xid is visible to anyone on the segment.
    """
    client = _RecordingClient(listen=("127.0.0.1", 0))

    for _ in range(5):
        client.dora(CHADDR, timeout=0.05, retries=0)

    assert client._pending_xids == set(), client._pending_xids
