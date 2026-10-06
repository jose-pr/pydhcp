import ipaddress
import queue
import socket
import threading
import time
from datetime import timedelta
from unittest.mock import Mock

import pytest

from pydhcp import (
    DHCPClient,
    DHCPError,
    DHCPRefusedError,
    DHCPTimeoutError,
    DHCPMessage,
    DHCPOptions,
    NetworkInterface,
    DHCPRequestContext,
)
from pydhcp.packet import DHCPMessageType, DHCPFlags, HardwareAddressType, DHCPOpcode
from pydhcp.options import DHCPOptionCode
from ipaddress import IPv4Address as IPv4
from pydhcp import SocketAddress
from conftest import FixedLeaseServer, running

CHADDR = b"\x00\x11\x22\x33\x44\x55"


def _context() -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(),
        interface=NetworkInterface("lo", ipaddress.IPv4Interface("127.0.0.1/24")),
        client=SocketAddress("127.0.0.1", 67),
        client_mac=CHADDR,
    )


def _reply(
    xid: int, message_type: DHCPMessageType = DHCPMessageType.DHCPOFFER
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = message_type
    return DHCPMessage(
        op=DHCPOpcode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=xid,
        secs=timedelta(seconds=0),
        flags=DHCPFlags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("192.0.2.10"),
        siaddr=IPv4("192.0.2.1"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=CHADDR,
        sname="",
        file="",
        options=options,
    )


def _assert_round_trips(message: DHCPMessage, message_type: DHCPMessageType) -> None:
    """Assert the *whole* message survives the wire, not three fields of it.

    Comparing only `op`, `chaddr` and the message type left everything else
    unguarded: `flags`, `secs`, `ciaddr`/`yiaddr`/`siaddr`/`giaddr`, `sname`,
    `file` and every option but one could come back different and each of these
    five builder tests would still pass. `to_mapping()` is the full, decoded
    form of both header and options, so one comparison covers all of it.
    """
    restored = DHCPMessage.decode(message.encode())
    assert restored.op == DHCPOpcode.BOOTREQUEST
    assert restored.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == message_type
    assert restored.to_mapping() == message.to_mapping()


def test_client_builds_standard_request_messages() -> None:
    client = DHCPClient(listen=("127.0.0.1", 6768))

    discover = client.build_discover(
        CHADDR,
        xid=0x12345678,
        client_identifier=b"\x01" + CHADDR,
        parameter_request_list=[DHCPOptionCode.SUBNET_MASK, DHCPOptionCode.ROUTER],
    )
    assert discover.flags == DHCPFlags.BROADCAST
    assert discover.options.get(
        DHCPOptionCode.CLIENT_IDENTIFIER, decode=False
    ) == bytearray(b"\x01" + CHADDR)
    _assert_round_trips(discover, DHCPMessageType.DHCPDISCOVER)

    request = client.build_request(
        CHADDR,
        xid=0x12345679,
        requested_ip=IPv4("192.0.2.10"),
        server_identifier="192.0.2.1",
    )
    assert request.options.get(DHCPOptionCode.REQUESTED_IP) == IPv4("192.0.2.10")
    assert request.options.get(DHCPOptionCode.SERVER_IDENTIFIER) == IPv4("192.0.2.1")
    _assert_round_trips(request, DHCPMessageType.DHCPREQUEST)

    inform = client.build_inform(CHADDR, ciaddr="192.0.2.20", xid=0x1234567A)
    assert inform.ciaddr == IPv4("192.0.2.20")
    assert DHCPOptionCode.REQUESTED_IP not in inform.options
    _assert_round_trips(inform, DHCPMessageType.DHCPINFORM)

    release = client.build_release(
        CHADDR, ciaddr="192.0.2.20", server_identifier="192.0.2.1"
    )
    assert release.flags == DHCPFlags.UNICAST
    _assert_round_trips(release, DHCPMessageType.DHCPRELEASE)

    decline = client.build_decline(
        CHADDR, requested_ip="192.0.2.30", server_identifier="192.0.2.1"
    )
    assert decline.options.get(DHCPOptionCode.REQUESTED_IP) == IPv4("192.0.2.30")
    _assert_round_trips(decline, DHCPMessageType.DHCPDECLINE)


def test_client_queues_matching_bootreply() -> None:
    seen = []

    class RecordingClient(DHCPClient):
        def on_reply(self, msg, context):
            seen.append((msg, context))

    client = RecordingClient(listen=("127.0.0.1", 6768))
    client._pending_keys.add((0xAABBCCDD, CHADDR))
    context = _context()

    client.handle(_reply(0x11111111), context)
    assert client.next_reply(timeout=0) is None

    accepted = _reply(0xAABBCCDD)
    client.handle(accepted, context)

    assert seen == [(accepted, context)]
    assert client.next_reply(timeout=0) == (accepted, context)
    assert client.drain_replies() == []


def test_client_send_uses_bound_udp_transport(monkeypatch) -> None:
    client = DHCPClient(listen=("127.0.0.1", 6768))
    socket = object()
    client._sockets.append(socket)  # type: ignore[arg-type]
    transport = Mock()
    transport.send.return_value = 300
    monkeypatch.setattr("pydhcp.client._sync.UDPTransport", lambda sock: transport)

    message = client.build_discover(CHADDR, xid=0xCAFEBABE)

    assert client.send(message, dst="192.0.2.1", port=6767) == 300
    data, dest = transport.send.call_args.args
    port = transport.send.call_args.kwargs["port"]
    mac = transport.send.call_args.kwargs["client_mac"]
    assert DHCPMessage.decode(data).xid == 0xCAFEBABE
    assert dest == IPv4("192.0.2.1")
    assert port == 6767
    assert mac == CHADDR
    # `send` does not register the transaction: an exchange does.
    assert (0xCAFEBABE, CHADDR) not in client._pending_keys


def test_client_dora_against_real_server() -> None:
    server = FixedLeaseServer(listen=[("127.0.0.1", 0)])
    with running(server):
        server_port = server.bound_addresses[0].port

        with running(DHCPClient(listen=("127.0.0.1", 0))) as client:
            # The client is on an ephemeral port, not 68.
            server.REPLY_TO_CLIENT_PORT = client.bound_addresses[0].port
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
                ack.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
                == DHCPMessageType.DHCPACK
            )
            assert ack.yiaddr == IPv4("127.0.0.1")


def test_client_discover_offer_receives_a_real_offer() -> None:
    """`discover_offer` against a live server, with the receive loop running.

    This replaces a test that asserted `discover_offer(...) is None` on a
    client that was never `start()`ed. Without the receive thread nothing ever
    reads the socket, so the call could only ever return None -- measured
    against a live `FixedLeaseServer`: the server logged one packet received
    and one sent, and `discover_offer` still returned None. The assertion could
    not fail, so it proved nothing about the client.
    """
    server = FixedLeaseServer(listen=[("127.0.0.1", 0)])
    with running(server):
        server_port = server.bound_addresses[0].port

        with running(DHCPClient(listen=("127.0.0.1", 0))) as client:
            server.REPLY_TO_CLIENT_PORT = client.bound_addresses[0].port
            offer = client.discover_offer(
                CHADDR,
                timeout=2.0,
                retries=1,
                destination="127.0.0.1",
                port=server_port,
                broadcast=False,
            )

    assert offer is not None
    assert (
        offer.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == DHCPMessageType.DHCPOFFER
    )
    assert offer.op == DHCPOpcode.BOOTREPLY
    assert offer.chaddr == CHADDR
    assert offer.yiaddr == IPv4("127.0.0.1")
    assert offer.options.get(DHCPOptionCode.SERVER_IDENTIFIER) is not None
    # Exchanges are cleaned up even on the success path.
    assert client._pending_keys == set()


def test_client_discover_offer_times_out_when_nothing_answers() -> None:
    """A started client, a real listener that never replies: a genuine timeout.

    The destination is a UDP socket bound here rather than a fixed port: the
    old version fired a datagram at whatever happened to be on 127.0.0.1:6767,
    and a host running pydhcp's own default-port server would have been
    answering it.
    """
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        silent.bind(("127.0.0.1", 0))
        silent_port = silent.getsockname()[1]

        with running(DHCPClient(listen=("127.0.0.1", 0))) as client:
            with pytest.raises(DHCPTimeoutError):
                client.discover_offer(
                    CHADDR,
                    timeout=0.2,
                    retries=0,
                    destination="127.0.0.1",
                    port=silent_port,
                    broadcast=False,
                )

        # The datagram really was sent and really did arrive -- otherwise the
        # timeout above would be the old tautology in a new costume.
        silent.settimeout(1.0)
        received = DHCPMessage.decode(bytearray(silent.recv(2048)))
        assert (
            received.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
            == DHCPMessageType.DHCPDISCOVER
        )
    finally:
        silent.close()

    assert client._pending_keys == set()


# --- the client must stay the same client across a DORA ---


def _canned_offer(xid, chaddr=CHADDR):
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPOFFER
    options[DHCPOptionCode.SERVER_IDENTIFIER] = IPv4("10.0.0.1")
    return DHCPMessage(
        op=DHCPOpcode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=xid,
        secs=timedelta(0),
        flags=DHCPFlags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("10.0.0.50"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=chaddr,
        sname="",
        file="",
        options=options,
    )


class _RecordingClient(DHCPClient):
    """Captures what would go on the wire; answers a DISCOVER with an OFFER."""

    def __init__(self, *args, offer_has_server_id=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.sent = []
        self.offer_has_server_id = offer_has_server_id

    def send(self, message, dst=IPv4("255.255.255.255"), port=67):
        self.sent.append(message)
        self._pending_keys.add(self._pending_key(message))
        if message.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) is (
            DHCPMessageType.DHCPDISCOVER
        ):
            offer = _canned_offer(message.xid)
            if not self.offer_has_server_id:
                del offer.options[int(DHCPOptionCode.SERVER_IDENTIFIER)]
            self.handle(offer, None)
        return 0


def test_dora_repeats_the_client_id_and_parameter_list_in_the_request():
    """RFC 2131 §4.2 and §4.4.1 are both MUSTs.

    The identifier is what the server keys the lease on: sending the DISCOVER
    under a supplied client id and the REQUEST under htype+chaddr made pydhcp's
    own server see two different clients, so the OFFER and the REQUEST were
    allocated separately.
    """
    cid = b"\xff\xde\xad\xbe\xef"
    prl = [DHCPOptionCode.SUBNET_MASK, DHCPOptionCode.ROUTER]

    client = _RecordingClient(listen=("127.0.0.1", 0))
    with pytest.raises(DHCPTimeoutError):  # nobody answers the REQUEST
        client.dora(
            CHADDR,
            timeout=0.2,
            retries=0,
            client_identifier=cid,
            parameter_request_list=prl,
        )

    assert len(client.sent) == 2, [
        str(m.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)) for m in client.sent
    ]
    discover, request = client.sent
    assert request.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) is (
        DHCPMessageType.DHCPREQUEST
    )
    assert request.options.get(DHCPOptionCode.CLIENT_IDENTIFIER, decode=False) == cid
    assert request.options.get(DHCPOptionCode.PARAMETER_REQUEST_LIST, decode=False)
    # and the two messages are the same client as far as a server is concerned
    assert request.get_client_id() == discover.get_client_id()


def test_dora_refuses_an_offer_without_a_server_identifier():
    """RFC 2131 §4.3.2: a SELECTING REQUEST carries option 54.

    Without it the REQUEST asks every server on the segment to answer, and
    pydhcp sent one anyway with the option silently absent.
    """
    client = _RecordingClient(listen=("127.0.0.1", 0), offer_has_server_id=False)

    with pytest.raises(DHCPTimeoutError):
        client.dora(CHADDR, timeout=0.2, retries=0)
    types = [m.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) for m in client.sent]
    assert DHCPMessageType.DHCPREQUEST not in types


def test_client_reply_queue_is_bounded_and_counts_what_it_drops():
    """An idle client accepts every BOOTREPLY so `on_reply` works as an observer.

    That is deliberate, but it used to be an unbounded queue: on a busy segment
    with nobody calling drain_replies(), memory grew without limit.
    """
    client = DHCPClient(listen=("127.0.0.1", 0))
    context = Mock()

    for index in range(client.MAX_QUEUED_REPLIES + 50):
        client.handle(_canned_offer(index), context)

    assert client._replies.qsize() == client.MAX_QUEUED_REPLIES
    assert client.metrics.replies_dropped_overflow == 50
    # the newest replies are the ones kept
    kept = {msg.xid for msg, _ in client.drain_replies()}
    assert max(kept) == client.MAX_QUEUED_REPLIES + 49


def test_pending_keys_do_not_accumulate_across_exchanges():
    """A spent xid stayed acceptable forever, and the set only ever grew.

    These go out as broadcasts, so the xid is visible to anyone on the segment.
    """
    client = _RecordingClient(listen=("127.0.0.1", 0))

    for _ in range(5):
        with pytest.raises(DHCPTimeoutError):
            client.dora(CHADDR, timeout=0.05, retries=0)

    assert client._pending_keys == set(), client._pending_keys


# --- retransmission: RFC 2131 §4.1 backoff and a real `secs` ---


def _canned_ack(xid, chaddr=CHADDR):
    ack = _canned_offer(xid, chaddr)
    ack.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPACK
    return ack


class _StubbedClockClient(DHCPClient):
    """A client whose clock only moves when the exchange waits.

    Nothing here sleeps. Backoff measured by living through it would cost the
    suite the full 2+4+8 seconds of one default schedule, and the intervals are
    jittered, so a wall-clock assertion would be flaky on top of slow.
    """

    #: How much time each wait is taken to consume. Smaller than any interval
    #: the tests use, so the wait still has time left when it returns.
    WAIT_COST = 3.0

    def __init__(self, *args, answer=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.now = 1000.0
        self.answer = answer
        self.intervals = []
        self.secs_sent = []

    def _monotonic(self):
        return self.now

    def send(self, message, dst=IPv4("255.255.255.255"), port=67):
        self.secs_sent.append(int(message.secs.total_seconds()))
        self._pending_keys.add(self._pending_key(message))
        message_type = message.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
        if self.answer and message_type is DHCPMessageType.DHCPDISCOVER:
            self.handle(_canned_offer(message.xid), None)
        elif self.answer and message_type is DHCPMessageType.DHCPREQUEST:
            self.handle(_canned_ack(message.xid), None)
        return 0

    def _wait_for(self, waiter, msg_type, timeout, server=None):
        """Record the interval the exchange chose, then spend it instantly.

        Only the *waiting* is stubbed. Delegating to the real `_wait_for` with
        this timeout is what a sleeping test looks like: it blocked on the
        queue for the whole 8+16+32 seconds of one schedule, 56 s in one test.
        """
        self.intervals.append(timeout)
        self.now += self.WAIT_COST
        while True:
            try:
                msg, _context = waiter.get_nowait()
            except queue.Empty:
                return None
            taken = self._take(msg, msg_type, server, self.now)
            if taken is not None:
                return taken


def test_retransmissions_back_off_instead_of_repeating_one_interval():
    """RFC 2131 §4.1: the delay doubles with each retransmission, randomized.

    Measured before this: four DISCOVERs at 0.216 / 0.201 / 0.214 s apart for a
    `timeout` of 0.2 — a fixed interval, so a fleet of clients retransmits in
    lock-step forever.
    """
    client = _StubbedClockClient(listen=("127.0.0.1", 0), answer=False)

    with pytest.raises(DHCPTimeoutError):
        client.discover_offer(
            CHADDR, timeout=2.0, retries=3, destination="127.0.0.1", port=6767
        )

    assert len(client.intervals) == 4
    assert client.intervals == sorted(client.intervals)
    assert len(set(client.intervals)) == 4, client.intervals
    for attempt, interval in enumerate(client.intervals):
        base = 2.0 * 2**attempt
        # +/-1 s around the doubled base (RFC 2131 s4.1), the amplitude capped
        # at the base itself so a short interval cannot go negative.
        assert abs(interval - base) <= min(1.0, base) + 1e-9


def test_retransmission_interval_is_jittered_within_the_rfc_band():
    """§4.1 randomizes "by ... a uniform random number ... from the range -1 to +1".

    The randomization is the point, not the doubling: without it every client
    that started together retransmits together, which is the collision it
    exists to break up. Both directions: a mode that only ever shortens the
    delay is not the RFC's.
    """
    client = DHCPClient(listen=("127.0.0.1", 0))

    draws = [next(client._retransmit_intervals(4.0, 0)) for _ in range(64)]

    assert len(set(draws)) > 1
    assert all(3.0 <= draw <= 5.0 for draw in draws), draws
    assert min(draws) < 4.0 < max(draws), "the jitter is one-sided"


def test_retransmission_interval_is_capped_at_the_rfc_maximum():
    """§4.1: doubling continues "up to a maximum of 64 seconds", randomized
    around that maximum -- not clamped one-sidedly below it, which would
    re-synchronise backed-off clients exactly where they spend their time."""
    client = DHCPClient(listen=("127.0.0.1", 0))

    late = list(client._retransmit_intervals(2.0, 20))[6:]

    assert late, "the schedule ended early"
    for interval in late:
        assert 63.0 <= interval <= 65.0, interval


def test_a_first_interval_above_the_cap_is_held_at_the_cap():
    """`timeout` is the initial interval, and a caller may give more than 64 s.

    The schedule is capped, so the first wait is the cap (randomized around it)
    rather than an error raised before anything is sent.
    """
    client = DHCPClient(listen=("127.0.0.1", 0))

    for timeout, retries in ((65.0, 1), (120.0, 0), (1000.0, 2)):
        waits = list(client._retransmit_intervals(timeout, retries))

        assert len(waits) == retries + 1
        assert all(63.0 <= wait <= 65.0 for wait in waits), (timeout, waits)


def test_a_subclass_cap_below_the_timeout_is_honoured():
    class Impatient(DHCPClient):
        RETRANSMIT_MAX_INTERVAL = 10.0

    waits = list(Impatient(listen=("127.0.0.1", 0))._retransmit_intervals(30.0, 1))

    assert all(9.0 <= wait <= 11.0 for wait in waits), waits


def test_secs_counts_up_across_retransmissions():
    """RFC 2131 §2: seconds since the client began acquisition, not always 0.

    Hardcoded to 0, every retransmission looked brand new to a server or relay
    that prioritises a client which has been trying for a while.
    """
    client = _StubbedClockClient(listen=("127.0.0.1", 0), answer=False)

    with pytest.raises(DHCPTimeoutError):
        client.discover_offer(
            CHADDR, timeout=8.0, retries=2, destination="127.0.0.1", port=6767
        )

    assert client.secs_sent[0] == 0
    assert client.secs_sent == [0, 3, 6], client.secs_sent


def test_dora_secs_continues_from_the_discover():
    """§2 says acquisition, not message: the REQUEST does not restart the clock."""
    client = _StubbedClockClient(listen=("127.0.0.1", 0))

    ack = client.dora(CHADDR, timeout=8.0, retries=0)

    assert ack is not None
    discover_secs, request_secs = client.secs_sent
    assert discover_secs == 0
    assert request_secs == _StubbedClockClient.WAIT_COST


# --- what an exchange reports: RFC 2131 s3.1 step 5 and s4.4.1 ---


class _ScriptedClient(_StubbedClockClient):
    """Answers each message type with the datagrams a test chooses.

    `answers` maps a message type to a function of the request that returns
    the replies to hand to `handle()`, as the receive thread would.
    """

    def __init__(self, *args, answers, **kwargs):
        super().__init__(*args, **kwargs)
        self.answers = answers
        self.requests = []

    def send(self, message, dst=IPv4("255.255.255.255"), port=67):
        kind = message.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
        self.requests.append(kind)
        self.secs_sent.append(int(message.secs.total_seconds()))
        for reply in self.answers.get(kind, lambda m: [])(message):
            self.handle(reply, None)
        return 0

    def kinds(self):
        return [kind.name for kind in self.requests]


def _from_server(reply, server):
    reply.options[DHCPOptionCode.SERVER_IDENTIFIER] = IPv4(server)
    return reply


def _offer_then(other):
    return {
        DHCPMessageType.DHCPDISCOVER: lambda m: [_canned_offer(m.xid)],
        DHCPMessageType.DHCPREQUEST: other,
    }


def test_a_dhcpnak_ends_the_exchange_at_once_and_is_raised():
    """RFC 2131 s3.1 step 5: on a DHCPNAK "the client restarts the configuration
    process"; retransmission is for when it "receives neither a DHCPACK or a
    DHCPNAK". The refusal carries the NAK, and one REQUEST was sent."""

    def nak(message):
        reply = _canned_offer(message.xid)
        reply.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPNAK
        reply.yiaddr = IPv4("0.0.0.0")
        return [reply]

    client = _ScriptedClient(listen=("127.0.0.1", 0), answers=_offer_then(nak))

    with pytest.raises(DHCPRefusedError) as refused:
        client.dora(CHADDR, timeout=2.0, retries=2)

    assert client.kinds() == ["DHCPDISCOVER", "DHCPREQUEST"]
    assert refused.value.nak.message_type is DHCPMessageType.DHCPNAK
    assert refused.value.nak.chaddr == CHADDR
    assert client._pending_keys == set()


def test_a_dhcpnak_from_a_server_other_than_the_selected_one_is_ignored():
    """The REQUEST names the selected server (RFC 2131 s4.3.2); a NAK naming
    another one is not an answer to it."""

    def foreign_nak(message):
        reply = _from_server(_canned_offer(message.xid), "10.0.0.66")
        reply.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPNAK
        return [reply]

    client = _ScriptedClient(listen=("127.0.0.1", 0), answers=_offer_then(foreign_nak))

    with pytest.raises(DHCPTimeoutError):
        client.dora(CHADDR, timeout=2.0, retries=0)


def test_an_offer_without_yiaddr_is_ignored():
    """An OFFER of 0.0.0.0 offers nothing: no REQUEST is built from it."""

    def empty(message):
        offer = _canned_offer(message.xid)
        offer.yiaddr = IPv4("0.0.0.0")
        return [offer]

    client = _ScriptedClient(
        listen=("127.0.0.1", 0), answers={DHCPMessageType.DHCPDISCOVER: empty}
    )

    with pytest.raises(DHCPTimeoutError):
        client.dora(CHADDR, timeout=2.0, retries=0)

    assert client.kinds() == ["DHCPDISCOVER"]


def test_an_ack_from_a_server_other_than_the_selected_one_is_ignored():
    """RFC 2131 s4.4.1: the client "records the address of the server that
    supplied the parameters from the 'server identifier' field". An ACK from
    another server, ahead of the real one, does not end the exchange."""

    def acks(message):
        foreign = _from_server(_canned_ack(message.xid), "10.0.0.66")
        foreign.yiaddr = IPv4("172.16.9.9")
        return [foreign, _canned_ack(message.xid)]

    client = _ScriptedClient(listen=("127.0.0.1", 0), answers=_offer_then(acks))

    ack = client.dora(CHADDR, timeout=2.0, retries=0)

    assert ack.yiaddr == IPv4("10.0.0.50")
    assert ack.options.get(DHCPOptionCode.SERVER_IDENTIFIER) == IPv4("10.0.0.1")


def test_a_foreign_ack_alone_is_a_timeout_not_an_answer():
    def foreign(message):
        return [_from_server(_canned_ack(message.xid), "10.0.0.66")]

    client = _ScriptedClient(listen=("127.0.0.1", 0), answers=_offer_then(foreign))

    with pytest.raises(DHCPTimeoutError):
        client.dora(CHADDR, timeout=2.0, retries=0)


def test_a_timeout_is_a_timeout_error_and_a_package_error():
    """API "Exceptions": a timeout is `(Base, TimeoutError)`."""
    client = _ScriptedClient(listen=("127.0.0.1", 0), answers={})

    with pytest.raises(TimeoutError) as raised:
        client.discover_offer(CHADDR, timeout=2.0, retries=1)

    assert isinstance(raised.value, DHCPTimeoutError)
    assert isinstance(raised.value, DHCPError)
    assert client._pending_keys == set()


# --- time: bounded from above by a second of margin, from below by the schedule ---


def _real_clock_client(schedule):
    """A client on the real clock with a fixed retransmission schedule."""
    client = _ScriptedClient(listen=("127.0.0.1", 0), answers={})
    client._monotonic = time.monotonic
    client._wait_for = lambda waiter, msg_type, timeout, server=None: (
        DHCPClient._wait_for(client, waiter, msg_type, timeout, server)
    )
    client._retransmit_intervals = lambda timeout, retries: iter(schedule)
    return client


def test_an_exchange_gives_up_after_its_schedule_and_not_before():
    schedule = [0.2, 0.3]
    client = _real_clock_client(schedule)

    began = time.monotonic()
    with pytest.raises(DHCPTimeoutError):
        client.discover_offer(CHADDR)
    elapsed = time.monotonic() - began

    assert sum(schedule) - 0.05 <= elapsed <= sum(schedule) + 1.0, elapsed
    assert client.kinds() == ["DHCPDISCOVER"] * 2


def test_a_deadline_bounds_the_whole_call_and_timeout_keeps_its_meaning():
    client = _real_clock_client([0.5, 1.0, 2.0])

    began = time.monotonic()
    with pytest.raises(DHCPTimeoutError):
        client.discover_offer(CHADDR, deadline=0.7)
    elapsed = time.monotonic() - began

    assert 0.7 - 0.05 <= elapsed <= 0.7 + 1.0, elapsed
    # Sent at 0 and at 0.5; the second wait was cut to what the deadline left.
    assert client.kinds() == ["DHCPDISCOVER"] * 2


def test_a_deadline_counts_across_both_halves_of_a_dora():
    client = _real_clock_client([0.4, 0.4, 0.4])
    client.answers = {
        DHCPMessageType.DHCPDISCOVER: lambda m: [_canned_offer(m.xid)],
    }

    began = time.monotonic()
    with pytest.raises(DHCPTimeoutError):
        client.dora(CHADDR, deadline=0.6)
    elapsed = time.monotonic() - began

    assert 0.6 - 0.05 <= elapsed <= 0.6 + 1.0, elapsed
    assert client.kinds()[0] == "DHCPDISCOVER" and "DHCPREQUEST" in client.kinds()


@pytest.mark.parametrize("deadline", [0, -1.0])
def test_a_deadline_that_is_not_positive_is_refused(deadline):
    client = _ScriptedClient(listen=("127.0.0.1", 0), answers={})

    with pytest.raises(ValueError, match="deadline"):
        client.dora(CHADDR, deadline=deadline)

    assert client.requests == []


# --- send() alone remembers nothing; an exchange registers its own key ---


def test_send_used_on_its_own_leaves_no_transaction_behind(monkeypatch):
    client = DHCPClient(listen=("127.0.0.1", 0))
    client._sockets.append(object())
    transport = Mock()
    transport.send.return_value = 300
    monkeypatch.setattr("pydhcp.client._sync.UDPTransport", lambda sock: transport)

    for xid in range(5000):
        client.send(client.build_release(CHADDR, ciaddr="10.0.0.50", xid=xid))

    assert client._pending_keys == set()
    # Still an observer: an unrelated reply is queued, not dropped.
    client.handle(_canned_offer(0x99), _context())
    assert client.next_reply(timeout=0) is not None


def test_an_exchange_registers_its_key_before_the_first_send():
    """A reply handled while the datagram is still being sent is accepted."""
    seen = []

    class Watching(_ScriptedClient):
        def send(self, message, dst=IPv4("255.255.255.255"), port=67):
            seen.append(self._pending_key(message) in self._pending_keys)
            return super().send(message, dst, port)

    client = Watching(listen=("127.0.0.1", 0), answers={})

    with pytest.raises(DHCPTimeoutError):
        client.discover_offer(CHADDR, timeout=2.0, retries=0)

    assert seen == [True]
    assert client._pending_keys == set()


def test_handle_ignores_a_bootrequest():
    """Only a BOOTREPLY is a reply; `client.py` checks `op` first for a reason.

    A DHCP client sits on a broadcast segment, so every other host's DISCOVER
    arrives here too. Queued as replies they would be handed to `on_reply` and
    to any waiting exchange whose (xid, chaddr) they happened to match.
    """
    client = DHCPClient(listen=("127.0.0.1", 0))
    seen: list[DHCPMessage] = []
    client.on_reply = lambda msg, context: seen.append(msg)  # type: ignore[method-assign]

    request = _canned_offer(0xAABBCCDD)
    request.op = DHCPOpcode.BOOTREQUEST
    client.handle(request, _context())

    assert client.next_reply(timeout=0) is None
    assert client.drain_replies() == []
    assert seen == []

    # The very same message as a reply is accepted, so the rejection above is
    # the `op` check and not some other mismatch.
    request.op = DHCPOpcode.BOOTREPLY
    client.handle(request, _context())
    assert seen == [request]


# --- reply matching: an exchange is (xid, chaddr), as it is on the relay ---

OTHER_CHADDR = b"\x00\xaa\xbb\xcc\xdd\xee"


def test_reply_with_a_foreign_chaddr_is_ignored():
    """Matched on the xid alone, a foreign reply carrying it was accepted.

    Measured: 'foreign-chaddr reply queued: True'. The xid is in cleartext in a
    broadcast DISCOVER, so any host on the segment can read one and answer it —
    the same reasoning as `DHCPRelay._pending_key`.
    """
    client = DHCPClient(listen=("127.0.0.1", 0))
    client._pending_keys.add((0xAABBCCDD, CHADDR))
    context = _context()

    client.handle(_canned_offer(0xAABBCCDD, chaddr=OTHER_CHADDR), context)
    assert client.next_reply(timeout=0) is None

    mine = _canned_offer(0xAABBCCDD)
    client.handle(mine, context)
    assert client.next_reply(timeout=0) == (mine, context)


def test_concurrent_exchanges_each_receive_their_own_reply():
    """Two exchanges on one client used to consume each other's replies.

    Measured on the xid-only matcher, with one exchange's OFFER queued first:
    the other exchange's `_wait_for` popped it, discarded it as a wrong-xid
    reply, and the exchange it belonged to then timed out having never seen it.
    """
    sent = {}
    started = {CHADDR: threading.Event(), OTHER_CHADDR: threading.Event()}
    results = {}

    class _TwoExchangeClient(DHCPClient):
        def send(self, message, dst=IPv4("255.255.255.255"), port=67):
            self._pending_keys.add(self._pending_key(message))
            sent[message.chaddr] = message
            started[message.chaddr].set()
            return 0

    client = _TwoExchangeClient(listen=("127.0.0.1", 0))

    def run(chaddr):
        results[chaddr] = client.discover_offer(
            chaddr, timeout=5.0, retries=0, destination="127.0.0.1", port=6767
        )

    threads = [threading.Thread(target=run, args=(c,)) for c in started]
    for thread in threads:
        thread.start()
    for chaddr, event in started.items():
        assert event.wait(5.0), f"exchange for {chaddr!r} never sent"

    # The foreign exchange's reply first: that is the order under which the
    # xid-only matcher lost one of the two.
    for chaddr in (OTHER_CHADDR, CHADDR):
        client.handle(_canned_offer(sent[chaddr].xid, chaddr), _context())
    for thread in threads:
        thread.join(timeout=5.0)
        assert not thread.is_alive()

    assert set(results) == set(started)
    for chaddr, offer in results.items():
        assert offer is not None, f"exchange for {chaddr!r} lost its reply"
        assert offer.chaddr == chaddr
        assert offer.xid == sent[chaddr].xid
