import ipaddress
from datetime import timedelta
from unittest.mock import Mock

import pytest

from pydhcp import DhcpMessage, DhcpOptions, DhcpRelay, NetworkInterface, RequestContext
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.options import DhcpOptionCode
from pydhcp.options.type import RelayAgentInformation, TlvOption
from pydhcp.network import IPv4, SocketAddress


CHADDR = b"\x11\x22\x33\x44\x55\x66"


def _context(client_port: int = 68) -> RequestContext:
    return RequestContext(
        transport=Mock(),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24"), None),
        client=SocketAddress("10.0.0.50", client_port),
        client_mac=CHADDR,
    )


def _server_context(client_port: int = 68, server_ip: str = "192.0.2.1") -> RequestContext:
    """A context whose source is a configured upstream server.

    Replies reach a relay *from* a server; the relay now drops a BOOTREPLY from
    anywhere else, so reply-path tests must look like the real thing.
    """
    return RequestContext(
        transport=Mock(),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24"), None),
        client=SocketAddress(server_ip, client_port),
        client_mac=CHADDR,
    )


def _discover(giaddr: str = "0.0.0.0", hops: int = 0, with_relay_info: bool = False) -> DhcpMessage:
    opts = DhcpOptions()
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    if with_relay_info:
        opts[DhcpOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation([TlvOption(1, b"existing")])
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=hops,
        xid=0x12345678,
        secs=timedelta(seconds=0),
        flags=Flags.BROADCAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4(giaddr),
        chaddr=CHADDR,
        sname="",
        file="",
        options=opts,
    )


def _reply(giaddr: str, ciaddr: str = "0.0.0.0", yiaddr: str = "0.0.0.0", broadcast: bool = False) -> DhcpMessage:
    opts = DhcpOptions()
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPOFFER
    return DhcpMessage(
        op=OpCode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=1,
        xid=0x12345678,
        secs=timedelta(seconds=0),
        flags=Flags.BROADCAST if broadcast else Flags.UNICAST,
        ciaddr=IPv4(ciaddr),
        yiaddr=IPv4(yiaddr),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4(giaddr),
        chaddr=CHADDR,
        sname="",
        file="",
        options=opts,
    )


def test_relay_requires_at_least_one_server_address():
    with pytest.raises(ValueError):
        DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=[])


def test_forward_to_servers_stamps_giaddr_and_increments_hops():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _context()
    msg = _discover()

    relay.handle(msg, context)

    assert context.transport.send.call_count == 1
    data, dest, port, mac = context.transport.send.call_args.args
    assert dest == IPv4("192.0.2.1")
    assert port == 67
    assert mac == CHADDR

    forwarded = DhcpMessage.decode(data)
    assert forwarded.giaddr == IPv4("10.0.0.1")
    assert forwarded.hops == 1
    assert relay.metrics.packets_sent == 1


def test_forward_to_servers_sends_to_every_configured_server():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1", ("192.0.2.2", 6767)])
    context = _context()
    msg = _discover()

    relay.handle(msg, context)

    assert context.transport.send.call_count == 2
    destinations = {call.args[1:3] for call in context.transport.send.call_args_list}
    assert destinations == {(IPv4("192.0.2.1"), 67), (IPv4("192.0.2.2"), 6767)}
    assert relay.metrics.packets_sent == 2


def test_forward_to_servers_is_idempotent_when_giaddr_already_set():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _context()
    msg = _discover(giaddr="10.0.0.1")

    relay.handle(msg, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DhcpMessage.decode(data)
    assert forwarded.giaddr == IPv4("10.0.0.1")


def test_forward_to_servers_drops_packet_over_hop_limit():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], max_hops=2)
    context = _context()
    msg = _discover(hops=2)

    relay.handle(msg, context)

    context.transport.send.assert_not_called()
    assert relay.metrics.packets_dropped_hop_limit == 1
    assert relay.metrics.packets_sent == 0


def test_relay_agent_info_inserted_when_enabled():
    relay = DhcpRelay(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"circuit-1",
        remote_id=b"remote-1",
    )
    context = _context()
    msg = _discover()

    relay.handle(msg, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DhcpMessage.decode(data)
    relay_info = forwarded.options.get(DhcpOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation)
    assert relay_info == RelayAgentInformation([TlvOption(1, b"circuit-1"), TlvOption(2, b"remote-1")])


def test_relay_agent_info_not_inserted_when_disabled():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _context()
    msg = _discover()

    relay.handle(msg, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DhcpMessage.decode(data)
    assert DhcpOptionCode.RELAY_AGENT_INFORMATION not in forwarded.options


def test_request_with_relay_info_and_giaddr_zero_is_dropped():
    """RFC 3046 s2.1/s5: giaddr 0 means this came straight from a client, so the
    option is forged -- a client that sets its own circuit id picks its own
    policy on any server that trusts option 82."""
    relay = DhcpRelay(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"circuit-1",
    )
    context = _context()

    relay.handle(_discover(with_relay_info=True), context)

    context.transport.send.assert_not_called()
    assert relay.metrics.packets_dropped_untrusted == 1


def test_relay_agent_info_passthrough_when_already_present():
    """A downstream relay's option is passed through unmodified.

    giaddr is set, so this came from another relay rather than a client. The
    same holds for a client-sourced request when the access layer below is
    trusted and trust_client_relay_agent_info=True.
    """
    relay = DhcpRelay(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"circuit-1",
    )
    context = _context()
    msg = _discover(giaddr="10.0.0.1", with_relay_info=True)

    relay.handle(msg, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DhcpMessage.decode(data)
    relay_info = forwarded.options.get(DhcpOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation)
    assert relay_info == RelayAgentInformation([TlvOption(1, b"existing")])


def test_client_relay_info_passes_through_when_explicitly_trusted():
    relay = DhcpRelay(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        trust_client_relay_agent_info=True,
    )
    context = _context()

    relay.handle(_discover(with_relay_info=True), context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DhcpMessage.decode(data)
    assert forwarded.options.get(
        DhcpOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation
    ) == RelayAgentInformation([TlvOption(1, b"existing")])


def test_forward_to_client_broadcast_flag():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _server_context()
    reply = _reply(giaddr="10.0.0.1", broadcast=True)

    relay.handle(reply, context)

    data, dest, port, mac = context.transport.send.call_args.args
    assert dest == IPv4("255.255.255.255")
    assert port == 68


def test_forward_to_client_ciaddr():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _server_context()
    reply = _reply(giaddr="10.0.0.1", ciaddr="10.0.0.50")

    relay.handle(reply, context)

    data, dest, port, mac = context.transport.send.call_args.args
    assert dest == IPv4("10.0.0.50")
    assert port == 68


def test_forward_to_client_without_ciaddr_is_broadcast():
    """A client with no address cannot answer ARP for yiaddr.

    The relay used to unicast there, which the kernel drops with no error -- the
    same trap DhcpServer.UNICAST_TO_UNCONFIGURED_CLIENT documents. Confirmed with
    ISC dhclient through this relay, which never saw an OFFER.
    """
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _server_context()
    reply = _reply(giaddr="10.0.0.1", yiaddr="10.0.0.60")

    relay.handle(reply, context)

    data, dest, port, mac = context.transport.send.call_args.args
    assert dest == IPv4("255.255.255.255")
    assert port == 68


def test_forward_to_client_uses_original_client_port_when_known():
    # A client that isn't listening on the well-known port 68 (e.g. an
    # ephemeral port in tests) must still get replies routed back to the
    # port its original request actually came from, not a hardcoded 68.
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    request_context = _server_context(client_port=54321)
    discover = _discover()

    relay.handle(discover, request_context)

    reply_context = _server_context(client_port=67)  # server's own source port
    reply = _reply(giaddr="10.0.0.1", ciaddr="10.0.0.50")
    relay.handle(reply, reply_context)

    data, dest, port, mac = reply_context.transport.send.call_args.args
    assert dest == IPv4("10.0.0.50")
    assert port == 54321


def test_pending_clients_map_is_bounded_and_evicts_oldest_first():
    relay = DhcpRelay(server_addresses=["10.0.0.2"])
    relay.MAX_PENDING_CLIENTS = 4

    for xid in range(10):
        msg = _discover()
        msg.xid = xid
        relay.handle(msg, _context(client_port=40000 + xid))

    assert len(relay._pending_clients) == 4
    # Oldest evicted, most recent four kept, insertion order preserved.
    assert list(relay._pending_clients) == [6, 7, 8, 9]
    assert relay._pending_clients[9].client.port == 40009


def test_reply_for_an_evicted_xid_falls_back_to_the_well_known_client_port():
    relay = DhcpRelay(server_addresses=["10.0.0.2"])
    relay.MAX_PENDING_CLIENTS = 1

    first = _discover()
    first.xid = 1
    relay.handle(first, _context(client_port=45000))
    second = _discover()
    second.xid = 2
    relay.handle(second, _context(client_port=45001))
    assert 1 not in relay._pending_clients

    reply = _reply("10.0.0.1", yiaddr="10.0.0.50")
    reply.xid = 1
    context = _server_context(server_ip="10.0.0.2")
    relay.handle(reply, context)

    _data, _dest, port, _mac = context.transport.send.call_args.args
    assert port == 68


# --- Relay trust and the RFC 3046 reply path ---


def test_bootreply_from_an_unconfigured_source_is_dropped():
    """Anything that can reach the relay's port 67 could otherwise have a forged
    ACK broadcast onto the client segment from the relay's own address, naming
    the attacker as router and DNS."""
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _server_context(server_ip="198.51.100.66")

    relay.handle(_reply("10.0.0.1", yiaddr="10.0.0.50"), context)

    context.transport.send.assert_not_called()
    assert relay.metrics.packets_dropped_untrusted == 1


def test_relay_strips_relay_agent_information_from_replies():
    """RFC 3046 s2.2: the option is relay-to-server bookkeeping and is removed
    before the reply reaches the client."""
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    reply = _reply("10.0.0.1", yiaddr="10.0.0.50")
    reply.options[DhcpOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation(
        [TlvOption(1, b"circuit-1")]
    )
    context = _server_context()

    relay.handle(reply, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DhcpMessage.decode(data)
    assert DhcpOptionCode.RELAY_AGENT_INFORMATION not in forwarded.options
    # The caller's message is untouched: the relay works on a copy.
    assert DhcpOptionCode.RELAY_AGENT_INFORMATION in reply.options


def test_relay_forwards_a_reply_larger_than_the_576_byte_default():
    """A server reply legitimately exceeds 576 octets when the client advertised
    a larger maximum. Encoding at the default raised OverflowError, and the
    receive loop logged it, so the client never got its reply."""
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    reply = _reply("10.0.0.1", yiaddr="10.0.0.50")
    for index in range(4):
        reply.options[200 + index] = bytearray(b"P" * 200)
    context = _server_context()

    relay.handle(reply, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DhcpMessage.decode(bytearray(data))
    assert len(data) > 576
    for index in range(4):
        assert len(forwarded.options.get(200 + index, decode=False)) == 200


def test_forwarding_a_request_does_not_mutate_the_callers_message():
    relay = DhcpRelay(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"circuit-1",
    )
    msg = _discover()

    relay.handle(msg, _context())

    assert msg.giaddr == IPv4("0.0.0.0")
    assert msg.hops == 0
    assert DhcpOptionCode.RELAY_AGENT_INFORMATION not in msg.options


# --- Which interface a relayed datagram leaves by ---
#
# A relay forwards across interfaces, the one case the IP_PKTINFO source pin
# gets wrong: it is set from the packet that just arrived. Reusing it to reach
# the upstream server pins the client-facing interface for a destination that is
# not on that link, and the datagram is dropped with no error. Reusing it for
# the reply pins the server-facing interface, so a broadcast leaves by the
# default route and never reaches the client's segment. Both were measured with
# ISC dhclient through this relay.


def test_upstream_forward_drops_the_pktinfo_pin():
    from pydhcp.listener import PktInfoUdpTransport, UdpTransport

    pinned = PktInfoUdpTransport(Mock())
    pinned.ifindex, pinned.local_ip = 7, IPv4("10.99.0.1")

    routed = DhcpRelay._routed_transport(pinned)

    assert type(routed) is UdpTransport
    assert routed.socket is pinned.socket


def test_reply_is_pinned_to_the_interface_the_request_arrived_on():
    from pydhcp.listener import PktInfoUdpTransport
    from pydhcp.relay import PendingClient

    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    arrived_on_server_side = PktInfoUdpTransport(Mock())
    arrived_on_server_side.ifindex, arrived_on_server_side.local_ip = 9, IPv4("10.98.0.1")
    pending = PendingClient(SocketAddress("10.99.0.50", 68), 3, IPv4("10.99.0.1"))

    out = relay._client_transport(arrived_on_server_side, pending)

    assert isinstance(out, PktInfoUdpTransport)
    assert out.ifindex == 3
    assert out.local_ip == IPv4("10.99.0.1")


def test_reply_without_a_recorded_ingress_falls_back_to_plain_routing():
    from pydhcp.listener import PktInfoUdpTransport, UdpTransport

    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    transport = PktInfoUdpTransport(Mock())
    transport.ifindex, transport.local_ip = 9, IPv4("10.98.0.1")

    out = relay._client_transport(transport, None)

    assert type(out) is UdpTransport


def test_pending_map_records_the_ingress_interface():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = RequestContext(
        transport=Mock(),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24"), None),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
        ifindex=4,
        local_ip=IPv4("10.0.0.1"),
    )

    relay.handle(_discover(), context)

    pending = relay._pending_clients[0x12345678]
    assert pending.ifindex == 4
    assert pending.local_ip == IPv4("10.0.0.1")
