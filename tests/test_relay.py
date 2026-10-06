import ipaddress
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import netimps
import pytest

from pydhcp import (
    AsyncDHCPRelay,
    DHCPMessage,
    DHCPOptions,
    DHCPRelay,
    NetworkInterface,
    DHCPRequestContext,
)
from pydhcp.packet import DHCPMessageType, DHCPFlags, HardwareAddressType, DHCPOpcode
from pydhcp.options import DHCPOptionCode
from pydhcp.options import RelayAgentInformation, TLVOption
from ipaddress import IPv4Address as IPv4
from pydhcp import SocketAddress
from pydhcp.relay import _core as relay_core

CHADDR = b"\x11\x22\x33\x44\x55\x66"


@pytest.fixture(params=[DHCPRelay, AsyncDHCPRelay], ids=["sync", "async"])
def relay_class(request):
    """Every forwarding test runs against both relays.

    Parametrized rather than duplicated on purpose: a second copy of these
    assertions is exactly how the async half of this project drifted from the
    sync half last time. `AsyncDHCPRelay` takes the same arguments minus
    `poll_interval`, which none of these tests passes, and `handle()` is
    ordinary synchronous code on both, so it needs no event loop here.
    """
    return request.param


def _context(client_port: int = 68) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(),
        interface=NetworkInterface(
            "eth0", ipaddress.IPv4Interface("10.0.0.1/24"), None
        ),
        client=SocketAddress("10.0.0.50", client_port),
        client_mac=CHADDR,
    )


def _server_context(
    client_port: int = 68, server_ip: str = "192.0.2.1"
) -> DHCPRequestContext:
    """A context whose source is a configured upstream server.

    Replies reach a relay *from* a server; the relay now drops a BOOTREPLY from
    anywhere else, so reply-path tests must look like the real thing.
    """
    return DHCPRequestContext(
        transport=Mock(),
        interface=NetworkInterface(
            "eth0", ipaddress.IPv4Interface("10.0.0.1/24"), None
        ),
        client=SocketAddress(server_ip, client_port),
        client_mac=CHADDR,
    )


def _discover(
    giaddr: str = "0.0.0.0", hops: int = 0, with_relay_info: bool = False
) -> DHCPMessage:
    opts = DHCPOptions()
    opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    if with_relay_info:
        opts[DHCPOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation(
            [TLVOption(1, b"existing")]
        )
    return DHCPMessage(
        op=DHCPOpcode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=hops,
        xid=0x12345678,
        secs=timedelta(seconds=0),
        flags=DHCPFlags.BROADCAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4(giaddr),
        chaddr=CHADDR,
        sname="",
        file="",
        options=opts,
    )


def _reply(
    giaddr: str,
    ciaddr: str = "0.0.0.0",
    yiaddr: str = "0.0.0.0",
    broadcast: bool = False,
) -> DHCPMessage:
    opts = DHCPOptions()
    opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPOFFER
    return DHCPMessage(
        op=DHCPOpcode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=1,
        xid=0x12345678,
        secs=timedelta(seconds=0),
        flags=DHCPFlags.BROADCAST if broadcast else DHCPFlags.UNICAST,
        ciaddr=IPv4(ciaddr),
        yiaddr=IPv4(yiaddr),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4(giaddr),
        chaddr=CHADDR,
        sname="",
        file="",
        options=opts,
    )


def test_relay_requires_at_least_one_server_address(relay_class):
    with pytest.raises(ValueError):
        relay_class(listen=("127.0.0.1", 6767), server_addresses=[])


def test_forward_to_servers_stamps_giaddr_and_increments_hops(relay_class):
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _context()
    msg = _discover()

    relay.handle(msg, context)

    assert context.transport.send.call_count == 1
    data, dest = context.transport.send.call_args.args
    port = context.transport.send.call_args.kwargs["port"]
    mac = context.transport.send.call_args.kwargs["client_mac"]
    assert dest == IPv4("192.0.2.1")
    assert port == 67
    assert mac == CHADDR

    forwarded = DHCPMessage.decode(data)
    assert forwarded.giaddr == IPv4("10.0.0.1")
    assert forwarded.hops == 1
    assert relay.metrics.packets_sent == 1


def test_forward_to_servers_sends_to_every_configured_server(relay_class):
    relay = relay_class(
        listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1", ("192.0.2.2", 6767)]
    )
    context = _context()
    msg = _discover()

    relay.handle(msg, context)

    assert context.transport.send.call_count == 2
    destinations = {
        (call.args[1], call.kwargs["port"])
        for call in context.transport.send.call_args_list
    }
    assert destinations == {(IPv4("192.0.2.1"), 67), (IPv4("192.0.2.2"), 6767)}
    assert relay.metrics.packets_sent == 2


def test_forward_to_servers_is_idempotent_when_giaddr_already_set(relay_class):
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _context()
    msg = _discover(giaddr="10.5.5.1")

    relay.handle(msg, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DHCPMessage.decode(data)
    assert forwarded.giaddr == IPv4("10.5.5.1")


def test_forward_to_servers_drops_packet_over_hop_limit(relay_class):
    """RFC 1542 4.1.1 discards a request whose hops field *exceeds* the threshold.

    This test used to assert that max_hops=2 dropped hops=2, which pinned the
    off-by-one rather than catching it: a request at hops=2 has crossed two
    relays and this one is entitled to forward it. Rewritten to the RFC, not
    adjusted to keep passing.
    """
    relay = relay_class(
        listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], max_hops=2
    )
    context = _context()

    relay.handle(_discover(hops=3), context)

    context.transport.send.assert_not_called()
    assert relay.metrics.packets_dropped_hop_limit == 1
    assert relay.metrics.packets_sent == 0


def test_a_request_at_exactly_the_hop_limit_is_still_forwarded(relay_class):
    """The boundary the old assertion had on the wrong side."""
    relay = relay_class(
        listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], max_hops=2
    )
    context = _context()

    relay.handle(_discover(hops=2), context)

    assert relay.metrics.packets_dropped_hop_limit == 0
    assert context.transport.send.call_count == 1
    forwarded = DHCPMessage.decode(context.transport.send.call_args.args[0])
    assert forwarded.hops == 3, "the relay must still count itself"


def test_the_default_threshold_is_the_rfc_default_not_the_ceiling(relay_class):
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    assert relay.max_hops == 4


@pytest.mark.parametrize("bad", [-1, 17, 255, 1000])
def test_a_threshold_outside_the_rfc_range_is_refused(relay_class, bad):
    """Above 254 the incremented value also overflows the one-octet field."""
    with pytest.raises(ValueError, match="RFC 1542"):
        relay_class(
            listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], max_hops=bad
        )


def test_relay_agent_info_inserted_when_enabled(relay_class):
    relay = relay_class(
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
    forwarded = DHCPMessage.decode(data)
    relay_info = forwarded.options.get(
        DHCPOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation
    )
    assert relay_info == RelayAgentInformation(
        [TLVOption(1, b"circuit-1"), TLVOption(2, b"remote-1")]
    )


def test_relay_agent_info_not_inserted_when_disabled(relay_class):
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _context()
    msg = _discover()

    relay.handle(msg, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DHCPMessage.decode(data)
    assert DHCPOptionCode.RELAY_AGENT_INFORMATION not in forwarded.options


def test_request_with_relay_info_and_giaddr_zero_is_dropped(relay_class):
    """RFC 3046 s2.1/s5: giaddr 0 means this came straight from a client, so the
    option is forged -- a client that sets its own circuit id picks its own
    policy on any server that trusts option 82."""
    relay = relay_class(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"circuit-1",
    )
    context = _context()

    relay.handle(_discover(with_relay_info=True), context)

    context.transport.send.assert_not_called()
    assert relay.metrics.packets_dropped_untrusted == 1


def test_relay_agent_info_passthrough_when_already_present(relay_class):
    """RFC 3046 s2.1.1: a request another relay already stamped is forwarded as is.

    Its `giaddr` is set and not ours, so it came from a downstream relay rather
    than a client: "SHALL forward any received DHCP packet with a valid non-zero
    giaddr WITHOUT adding any relay agent options", and the downstream relay's
    own option passes through unmodified. The same holds for a client-sourced
    request when the access layer below is trusted
    (trust_client_relay_agent_info=True).
    """
    relay = relay_class(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"circuit-1",
    )
    context = _context()
    msg = _discover(giaddr="10.5.5.1", with_relay_info=True)

    relay.handle(msg, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DHCPMessage.decode(data)
    relay_info = forwarded.options.get(
        DHCPOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation
    )
    assert relay_info == RelayAgentInformation([TLVOption(1, b"existing")])


def test_client_relay_info_passes_through_when_explicitly_trusted(relay_class):
    relay = relay_class(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        trust_client_relay_agent_info=True,
    )
    context = _context()

    relay.handle(_discover(with_relay_info=True), context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DHCPMessage.decode(data)
    assert forwarded.options.get(
        DHCPOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation
    ) == RelayAgentInformation([TLVOption(1, b"existing")])


def test_forward_to_client_broadcast_flag(relay_class):
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _server_context()
    reply = _reply(giaddr="10.0.0.1", broadcast=True)

    relay.handle(reply, context)

    data, dest = context.transport.send.call_args.args
    port = context.transport.send.call_args.kwargs["port"]
    mac = context.transport.send.call_args.kwargs["client_mac"]
    assert dest == IPv4("255.255.255.255")
    assert port == 68


def test_forward_to_client_ciaddr(relay_class):
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _server_context()
    reply = _reply(giaddr="10.0.0.1", ciaddr="10.0.0.50")

    relay.handle(reply, context)

    data, dest = context.transport.send.call_args.args
    port = context.transport.send.call_args.kwargs["port"]
    mac = context.transport.send.call_args.kwargs["client_mac"]
    assert dest == IPv4("10.0.0.50")
    assert port == 68


def test_forward_to_client_without_ciaddr_is_broadcast(relay_class):
    """A client with no address cannot answer ARP for yiaddr.

    The relay used to unicast there, which the kernel drops with no error -- the
    same trap DHCPServer.UNICAST_TO_UNCONFIGURED_CLIENT documents. Confirmed with
    ISC dhclient through this relay, which never saw an OFFER.
    """
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _server_context()
    reply = _reply(giaddr="10.0.0.1", yiaddr="10.0.0.60")

    relay.handle(reply, context)

    data, dest = context.transport.send.call_args.args
    port = context.transport.send.call_args.kwargs["port"]
    mac = context.transport.send.call_args.kwargs["client_mac"]
    assert dest == IPv4("255.255.255.255")
    assert port == 68


def test_forward_to_client_uses_original_client_port_when_known(relay_class):
    # A client that isn't listening on the well-known port 68 (e.g. an
    # ephemeral port in tests) must still get replies routed back to the
    # port its original request actually came from, not a hardcoded 68.
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    request_context = _server_context(client_port=54321)
    discover = _discover()

    relay.handle(discover, request_context)

    reply_context = _server_context(client_port=67)  # server's own source port
    reply = _reply(giaddr="10.0.0.1", ciaddr="10.0.0.50")
    relay.handle(reply, reply_context)

    data, dest = reply_context.transport.send.call_args.args
    port = reply_context.transport.send.call_args.kwargs["port"]
    mac = reply_context.transport.send.call_args.kwargs["client_mac"]
    assert dest == IPv4("10.0.0.50")
    assert port == 54321


def test_pending_clients_map_is_bounded_and_evicts_oldest_first(relay_class):
    relay = relay_class(server_addresses=["10.0.0.2"])
    relay.MAX_PENDING_CLIENTS = 4

    for xid in range(10):
        msg = _discover()
        msg.xid = xid
        relay.handle(msg, _context(client_port=40000 + xid))

    assert len(relay._pending_clients) == 4
    # Oldest evicted, most recent four kept, insertion order preserved. The key
    # is (xid, chaddr): an xid alone is not an identity, since it is readable
    # from any broadcast DISCOVER on the segment.
    assert [xid for xid, _chaddr in relay._pending_clients] == [6, 7, 8, 9]
    assert relay._pending_clients[(9, CHADDR)].client.port == 40009


def test_reply_for_an_evicted_xid_falls_back_to_the_well_known_client_port(relay_class):
    relay = relay_class(server_addresses=["10.0.0.2"])
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

    _data, _dest = context.transport.send.call_args.args
    port = context.transport.send.call_args.kwargs["port"]
    _mac = context.transport.send.call_args.kwargs["client_mac"]
    assert port == 68


# --- Relay trust and the RFC 3046 reply path ---


def test_bootreply_from_an_unconfigured_source_is_dropped(relay_class):
    """Anything that can reach the relay's port 67 could otherwise have a forged
    ACK broadcast onto the client segment from the relay's own address, naming
    the attacker as router and DNS."""
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _server_context(server_ip="198.51.100.66")

    relay.handle(_reply("10.0.0.1", yiaddr="10.0.0.50"), context)

    context.transport.send.assert_not_called()
    assert relay.metrics.packets_dropped_untrusted == 1


def test_relay_strips_relay_agent_information_from_replies(relay_class):
    """RFC 3046 s2.2: the option this relay added is relay-to-server bookkeeping
    and is removed before the reply reaches the client."""
    relay = relay_class(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"circuit-1",
    )
    reply = _reply("10.0.0.1", yiaddr="10.0.0.50")
    reply.options[DHCPOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation(
        [TLVOption(1, b"circuit-1")]
    )
    context = _server_context()

    relay.handle(reply, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DHCPMessage.decode(data)
    assert DHCPOptionCode.RELAY_AGENT_INFORMATION not in forwarded.options
    # The caller's message is untouched: the relay works on a copy.
    assert DHCPOptionCode.RELAY_AGENT_INFORMATION in reply.options


def test_relay_forwards_a_reply_larger_than_the_576_byte_default(relay_class):
    """A server reply legitimately exceeds 576 octets when the client advertised
    a larger maximum. Encoding at the default raised OverflowError, and the
    receive loop logged it, so the client never got its reply."""
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    reply = _reply("10.0.0.1", yiaddr="10.0.0.50")
    for index in range(4):
        reply.options[200 + index] = bytearray(b"P" * 200)
    context = _server_context()

    relay.handle(reply, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DHCPMessage.decode(bytearray(data))
    assert len(data) > 576
    for index in range(4):
        assert len(forwarded.options.get(200 + index, decode=False)) == 200


def test_forwarding_a_request_does_not_mutate_the_callers_message(relay_class):
    relay = relay_class(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"circuit-1",
    )
    msg = _discover()

    relay.handle(msg, _context())

    assert msg.giaddr == IPv4("0.0.0.0")
    assert msg.hops == 0
    assert DHCPOptionCode.RELAY_AGENT_INFORMATION not in msg.options


# --- Which interface a relayed datagram leaves by ---
#
# A relay forwards across interfaces, the one case the IP_PKTINFO source pin
# gets wrong: it is set from the packet that just arrived. Reusing it to reach
# the upstream server pins the client-facing interface for a destination that is
# not on that link, and the datagram is dropped with no error. Reusing it for
# the reply pins the server-facing interface, so a broadcast leaves by the
# default route and never reaches the client's segment. Both were measured with
# ISC dhclient through this relay.


def test_upstream_forward_drops_the_pktinfo_pin(relay_class):
    from pydhcp.listener import PktInfoUDPTransport, UDPTransport

    pinned = PktInfoUDPTransport(Mock())
    pinned.ifindex, pinned.local_ip = 7, IPv4("10.99.0.1")

    routed = relay_class._routed_transport(pinned)

    assert type(routed) is UDPTransport
    assert routed.socket is pinned.socket


def _pinned_reply_setup(relay_class, giaddr="10.99.0.1"):
    """A relay whose reply arrives on a pinned transport made of mocks.

    Returns the relay, the context and the endpoint mock a pinned send goes
    through, so a test can read which source (address and interface index) the
    reply was sent from.
    """
    from pydhcp.listener import PktInfoUDPTransport

    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    endpoint = Mock()
    endpoint.send.return_value = 1
    transport = PktInfoUDPTransport(Mock(), endpoint)
    # What the receive path set from the datagram that arrived from the server:
    # the server-facing interface, which is the wrong one for the reply.
    transport.ifindex, transport.local_ip = 9, IPv4("10.98.0.1")
    context = DHCPRequestContext(
        transport=transport,
        interface=NetworkInterface(
            "sv0", ipaddress.IPv4Interface("10.98.0.1/24"), None
        ),
        client=SocketAddress("192.0.2.1", 67),
        client_mac=CHADDR,
        ifindex=9,
        local_ip=IPv4("10.98.0.1"),
    )
    return relay, context, endpoint


CLIENT_SIDE = netimps.Interface(
    name="cv0", index=3, ips=[ipaddress.IPv4Interface("10.99.0.1/24")]
)


@pytest.fixture(autouse=True)
def host(monkeypatch):
    """The interfaces this host holds, as the relay's lookups see them.

    Empty by default, so the suite does not depend on the addresses of the
    machine it runs on; a test adds an interface to the dict.
    """
    held: "dict[str, netimps.Interface]" = {}
    monkeypatch.setattr(
        relay_core._netimps,
        "get_interface",
        lambda address, **_kw: held.get(str(address)),
    )
    monkeypatch.setattr(
        relay_core._netimps,
        "is_local_address",
        lambda address, **_kw: str(address) in held,
    )
    return held


def test_a_reply_leaves_by_the_interface_that_holds_its_giaddr(relay_class, host):
    """RFC 1542 s4.1.2: "The 'giaddr' field can be used to identify the logical
    interface from which the reply must be sent". The relay has seen no request
    of this exchange, so nothing it remembers can be what chooses the interface."""
    host["10.99.0.1"] = CLIENT_SIDE
    relay, context, endpoint = _pinned_reply_setup(relay_class)

    relay.handle(_reply(giaddr="10.99.0.1", yiaddr="10.99.0.50"), context)

    (_data, dest, port), kwargs = endpoint.send.call_args
    source = kwargs["src"]
    assert (dest, port) == ("255.255.255.255", 68)
    assert source.index == 3
    assert [str(ip.ip) for ip in source.ips] == ["10.99.0.1"]


def test_a_reply_whose_giaddr_no_interface_holds_is_dropped_and_counted(
    relay_class, host
):
    """RFC 1542 s4.1.2: "If the content of the 'giaddr' field does not match one
    of the relay agent's directly-connected logical interfaces, the BOOTREPLY
    messsage MUST be silently discarded"."""
    host["10.99.0.1"] = CLIENT_SIDE
    relay, context, endpoint = _pinned_reply_setup(relay_class)

    relay.handle(_reply(giaddr="10.77.77.1", yiaddr="10.99.0.50"), context)

    endpoint.send.assert_not_called()
    assert relay.metrics.packets_dropped_unknown_giaddr == 1
    assert relay.metrics.packets_sent == 0


def test_a_reply_with_giaddr_zero_is_dropped_and_counted(relay_class):
    """No interface holds 0.0.0.0, so the same clause discards it."""
    relay, context, endpoint = _pinned_reply_setup(relay_class)

    relay.handle(_reply(giaddr="0.0.0.0", yiaddr="10.99.0.50"), context)

    endpoint.send.assert_not_called()
    assert relay.metrics.packets_dropped_unknown_giaddr == 1


# --- the pending table: what it keeps and what it does at its cap ---
#
# It holds only the port of a client that is not on port 68, so that an entry
# lost costs that client's reply the port and nothing else. At the cap the
# oldest entry is evicted. The tests set the cap to 2 and pass the time in.


def _stamped(
    port: int, at: float, ip: str = "10.0.0.50", transport=None
) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=transport or Mock(),
        interface=NetworkInterface(
            "eth0", ipaddress.IPv4Interface("10.0.0.1/24"), None
        ),
        client=SocketAddress(ip, port),
        client_mac=CHADDR,
        received_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        received_monotonic=at,
    )


def _request(xid: int, chaddr: bytes = CHADDR) -> DHCPMessage:
    request = _discover()
    request.xid = xid
    request.chaddr = chaddr
    return request


def _reply_goes(relay, xid: int, at: float) -> "tuple[int, int]":
    """The (port, interface index) a reply for `xid` leaves by."""
    from pydhcp.listener import PktInfoUDPTransport

    endpoint = Mock()
    endpoint.send.return_value = 1
    transport = PktInfoUDPTransport(Mock(), endpoint)
    transport.ifindex, transport.local_ip = 9, IPv4("10.98.0.1")
    reply = _reply(giaddr="10.0.0.1", yiaddr="10.0.0.50")
    reply.xid = xid
    relay.handle(reply, _stamped(67, at, ip="192.0.2.1", transport=transport))
    (_data, _dest, port), kwargs = endpoint.send.call_args
    return port, kwargs["src"].index


def test_a_forged_flood_evicts_the_oldest_entry_and_costs_that_reply_only_its_port(
    relay_class, host
):
    """A bound, stated: at the cap the oldest entry goes. The real client's reply
    then goes to port 68 and, with its interface chosen from `giaddr`, still
    leaves by the right one."""
    host["10.0.0.1"] = netimps.Interface(
        name="eth0", index=4, ips=[ipaddress.IPv4Interface("10.0.0.1/24")]
    )
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    relay.MAX_PENDING_CLIENTS = 2
    relay.handle(_request(1), _stamped(40001, 100.0))
    assert _reply_goes(relay, 1, 101.0) == (40001, 4)

    for forged in (2, 3):
        relay.handle(
            _request(forged, bytes([0xAA, 0, 0, 0, 0, forged])),
            _stamped(40000 + forged, 102.0, ip="10.0.0.66"),
        )

    assert len(relay._pending_clients) == 2
    assert _reply_goes(relay, 1, 103.0) == (68, 4)


def test_a_flood_from_the_standard_port_occupies_nothing(relay_class):
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    relay.MAX_PENDING_CLIENTS = 2
    relay.handle(_request(1), _stamped(40001, 100.0))

    for forged in range(2, 12):
        relay.handle(
            _request(forged, bytes([0xAA, 0, 0, 0, 0, forged])),
            _stamped(68, 101.0, ip="10.0.0.66"),
        )

    assert list(relay._pending_clients) == [(1, CHADDR)]


def test_an_entry_expires_after_its_ttl(relay_class, host):
    host["10.0.0.1"] = netimps.Interface(
        name="eth0", index=4, ips=[ipaddress.IPv4Interface("10.0.0.1/24")]
    )
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    relay.handle(_request(1), _stamped(40001, 100.0))

    held = relay.PENDING_TTL_SECONDS
    assert _reply_goes(relay, 1, 100.0 + held - 1)[0] == 40001
    assert _reply_goes(relay, 1, 100.0 + held)[0] == 68
    assert len(relay._pending_clients) == 0


def test_expiring_does_not_walk_the_table(relay_class):
    """The cost of a request or a reply must not grow with the entries a flood
    left: the table is in the order its entries were written, so expiry looks at
    the oldest only."""

    class Counting(OrderedDict):
        looked_at = 0

        def values(self):
            for value in super().values():
                Counting.looked_at += 1
                yield value

    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    relay._pending_clients = Counting()
    for xid in range(50):
        relay.handle(_request(xid), _stamped(40000 + xid, 100.0 + xid))
    Counting.looked_at = 0

    relay._expire_pending(100.0 + 50)

    assert Counting.looked_at <= 1


def test_a_request_that_reuses_a_pending_transaction_from_another_address_is_dropped(
    relay_class,
):
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    relay.handle(_request(1), _stamped(40001, 100.0, ip="10.0.0.50"))
    attacker = _stamped(5353, 101.0, ip="10.0.0.66")

    relay.handle(_request(1), attacker)

    attacker.transport.send.assert_not_called()
    assert relay.metrics.packets_dropped_reused_transaction == 1
    assert relay._pending_clients[(1, CHADDR)].client == SocketAddress(
        "10.0.0.50", 40001
    )


def test_a_request_from_the_same_address_replaces_the_entry(relay_class):
    """Every unconfigured client has source address 0.0.0.0, so the address is
    all that can tell a client that opened a new socket from another host."""
    relay = relay_class(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    relay.handle(_request(1), _stamped(40001, 100.0))
    relay.handle(_request(1), _stamped(40002, 101.0))

    assert relay._pending_clients[(1, CHADDR)].client.port == 40002
    assert relay.metrics.packets_dropped_reused_transaction == 0


# --- reply routing must survive a client that reuses someone else's xid ---


def _client_context(client_ip: str, client_port: int) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(),
        interface=NetworkInterface(
            "eth0", ipaddress.IPv4Interface("10.0.0.1/24"), None
        ),
        client=SocketAddress(client_ip, client_port),
        client_mac=CHADDR,
    )


def test_a_reused_xid_cannot_redirect_another_clients_reply(relay_class):
    """The xid is cleartext in a broadcast DISCOVER, so it is not an identity.

    Keyed by xid alone, a second request carrying the victim's xid overwrote the
    entry and the relay then sent the victim's OFFER to the attacker's port -- a
    targeted denial of lease acquisition for any host on the segment.
    """
    relay = relay_class(server_addresses=["10.0.0.2"])

    victim = _discover()
    victim.xid = 0xAAAA
    relay.handle(victim, _client_context("10.0.0.50", 40001))

    attacker = _discover()
    attacker.xid = 0xAAAA
    attacker.chaddr = b"\xaa\xbb\xcc\xdd\xee\xff"
    relay.handle(attacker, _client_context("10.0.0.66", 5353))

    context = _server_context(server_ip="10.0.0.2")
    reply = _reply(giaddr="10.0.0.1", yiaddr="10.0.0.50")
    reply.xid = 0xAAAA
    relay.handle(reply, context)

    _data, _dest = context.transport.send.call_args.args
    port = context.transport.send.call_args.kwargs["port"]
    _mac = context.transport.send.call_args.kwargs["client_mac"]
    assert port == 40001, "the victim's reply was redirected to the attacker"


def test_every_configured_server_reply_reaches_the_tracked_port(relay_class):
    """Popping the entry on the first reply lost the port for the rest.

    With two servers configured the second reply fell back to 68, so which reply
    actually reached a client on another port depended on which server answered
    first.
    """
    relay = relay_class(server_addresses=["10.0.0.2", "10.0.0.3"])
    request = _discover()
    request.xid = 0xBBBB
    relay.handle(request, _client_context("10.0.0.50", 40002))

    ports = []
    for server in ("10.0.0.2", "10.0.0.3"):
        context = _server_context(server_ip=server)
        reply = _reply(giaddr="10.0.0.1", yiaddr="10.0.0.50")
        reply.xid = 0xBBBB
        relay.handle(reply, context)
        _data, _dest = context.transport.send.call_args.args
        port = context.transport.send.call_args.kwargs["port"]
        _mac = context.transport.send.call_args.kwargs["client_mac"]
        ports.append(port)

    assert ports == [40002, 40002], ports


def test_pending_entries_expire_rather_than_accumulate(relay_class):
    """Entries are kept for further replies, so something else must remove them."""
    import time

    relay = relay_class(server_addresses=["10.0.0.2"])
    relay.PENDING_TTL_SECONDS = 0.0  # everything is immediately stale

    request = _discover()
    request.xid = 0xCCCC
    relay.handle(request, _client_context("10.0.0.50", 40003))

    relay._expire_pending(time.monotonic())
    assert dict(relay._pending_clients) == {}


# --- RFC 3046: what the relay may add to a request, and when ---
#
# Each test reads the octets that went out, not a decoded message: the decoder
# folds an overloaded `sname` back into the options, which is how a wrong layout
# once printed a right answer.

_INSERTING = dict(
    insert_relay_agent_info=True, circuit_id=b"circuit-1", remote_id=b"remote-1"
)
_OPTIONS_OFFSET = 240  # fixed header (236) and the magic cookie
_SNAME = slice(44, 108)
_FILE = slice(108, 236)


def _wire_options(data) -> "list[tuple[int, bytes]]":
    """The (code, payload) pairs of the options field, in wire order, to END."""
    data = bytes(data)
    out = []
    index = _OPTIONS_OFFSET
    while index < len(data) and data[index] != 255:
        if data[index] == 0:
            index += 1
            continue
        length = data[index + 1]
        out.append((data[index], data[index + 2 : index + 2 + length]))
        index += 2 + length
    return out


def _sent_data(context) -> bytes:
    return bytes(context.transport.send.call_args.args[0])


def test_a_request_with_a_nonzero_giaddr_is_forwarded_without_adding_option_82(
    relay_class,
):
    """RFC 3046 s2.1.1: "SHALL forward any received DHCP packet with a valid
    non-zero giaddr WITHOUT adding any relay agent options"."""
    relay = relay_class(
        listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], **_INSERTING
    )
    context = _context()

    relay.handle(_discover(giaddr="10.5.5.1"), context)

    data = _sent_data(context)
    assert 82 not in [code for code, _ in _wire_options(data)]
    assert DHCPMessage.decode(data).giaddr == IPv4("10.5.5.1")


@pytest.mark.parametrize("inserting", [True, False])
def test_a_request_whose_giaddr_is_the_relays_own_address_is_dropped(
    relay_class, inserting
):
    """RFC 3046 s2.1.1: "SHALL discard the packet if the giaddr spoofs a giaddr
    address implemented by the local agent itself". The rule is stated for a
    relay that adds option 82; forwarding such a request with insertion off is a
    loop all the same, so it is dropped there too."""
    options = _INSERTING if inserting else {}
    relay = relay_class(
        listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], **options
    )
    context = _context()

    relay.handle(_discover(giaddr="10.0.0.1"), context)

    context.transport.send.assert_not_called()
    assert relay.metrics.packets_dropped_relay_loop == 1
    assert relay.metrics.packets_sent == 0


def test_option_82_is_added_last_before_end(relay_class):
    """RFC 3046 s2.1: "SHALL add it as the last option (but before 'End Option'
    255, if present)"."""
    relay = relay_class(
        listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], **_INSERTING
    )
    context = _context()
    request = _discover()
    request.options[DHCPOptionCode.HOSTNAME] = "client-host"

    relay.handle(request, context)

    options = _wire_options(_sent_data(context))
    assert options[-1] == (82, b"\x01\x09circuit-1\x02\x08remote-1")
    assert [code for code, _ in options] == [53, 12, 82]


def test_option_82_is_not_added_through_option_overload_and_is_counted(relay_class):
    """RFC 3046 s2.1: the agent "SHALL NOT add an 'Option Overload' option to the
    packet or use the 'file' or 'sname' fields for adding Relay Agent Information
    option", and a packet that "would exceed this configured maximum size shall
    be forwarded WITHOUT adding the Agent Information option"."""
    relay = relay_class(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        max_packet_size=576,
        insert_relay_agent_info=True,
        circuit_id=b"c" * 20,
        remote_id=b"r" * 20,
    )
    context = _context()
    request = _discover()
    request.options[DHCPOptionCode.VENDOR_CLASS_IDENTIFIER] = "x" * 200
    request.options[DHCPOptionCode.HOSTNAME] = "h" * 60

    relay.handle(request, context)

    data = _sent_data(context)
    codes = [code for code, _ in _wire_options(data)]
    assert 82 not in codes
    assert 52 not in codes
    assert data[_SNAME] == bytes(64) and data[_FILE] == bytes(128)
    assert relay.metrics.relay_info_omitted == 1
    assert relay.metrics.packets_sent == 1


def test_the_encode_limit_of_a_request_is_the_relays_not_the_clients(relay_class):
    """Option 57 is what the client can *receive*. The same request, advertising
    576, that overloaded `sname` when the relay used it as its own limit keeps
    option 82 in the options field of a 598-octet datagram."""
    relay = relay_class(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"c" * 40,
        remote_id=b"r" * 40,
    )
    context = _context()
    request = _discover()
    request.options[DHCPOptionCode.VENDOR_CLASS_IDENTIFIER] = "x" * 200
    request.options[DHCPOptionCode.HOSTNAME] = "h" * 60
    request.options[DHCPOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE] = 576

    relay.handle(request, context)

    data = _sent_data(context)
    codes = [code for code, _ in _wire_options(data)]
    assert codes[-1] == 82 and 52 not in codes
    assert data[_SNAME] == bytes(64) and data[_FILE] == bytes(128)
    assert relay.metrics.relay_info_omitted == 0


# --- RFC 3046 s2.2: which replies lose option 82 ---


def _reply_with(option) -> DHCPMessage:
    reply = _reply(giaddr="10.0.0.1", yiaddr="10.0.0.50")
    reply.options[DHCPOptionCode.RELAY_AGENT_INFORMATION] = option
    return reply


def test_a_reply_loses_the_option_82_this_relay_added(relay_class):
    """RFC 3046 s2.1: the echoed option "MUST be removed by either the relay
    agent or the trusted downstream network element which added it"."""
    relay = relay_class(
        listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], **_INSERTING
    )
    context = _server_context()

    relay.handle(
        _reply_with(
            RelayAgentInformation(
                [TLVOption(1, b"circuit-1"), TLVOption(2, b"remote-1")]
            )
        ),
        context,
    )

    assert 82 not in [code for code, _ in _wire_options(_sent_data(context))]


def test_a_reply_keeps_the_option_82_a_trusted_downstream_element_added(relay_class):
    """The same sentence names the downstream element as the one that removes
    its own option: this relay inserted nothing, so it removes nothing."""
    relay = relay_class(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        trust_client_relay_agent_info=True,
    )
    context = _server_context()

    relay.handle(
        _reply_with(RelayAgentInformation([TLVOption(1, b"switch-port-7")])), context
    )

    options = dict(_wire_options(_sent_data(context)))
    assert options[82] == b"\x01\x0dswitch-port-7"


def test_a_reply_keeps_an_option_82_that_is_not_the_one_this_relay_added(relay_class):
    relay = relay_class(
        listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], **_INSERTING
    )
    context = _server_context()

    relay.handle(
        _reply_with(RelayAgentInformation([TLVOption(1, b"switch-port-7")])), context
    )

    assert 82 in [code for code, _ in _wire_options(_sent_data(context))]


# --- the constructor refuses what cannot work ---


def test_insert_relay_agent_info_without_an_id_is_refused(relay_class):
    with pytest.raises(ValueError, match="circuit_id or remote_id"):
        relay_class(
            listen=("127.0.0.1", 6767),
            server_addresses=["192.0.2.1"],
            insert_relay_agent_info=True,
        )


@pytest.mark.parametrize("name", ["circuit_id", "remote_id"])
def test_an_id_without_insert_relay_agent_info_is_refused(relay_class, name):
    with pytest.raises(ValueError, match="insert_relay_agent_info"):
        relay_class(
            listen=("127.0.0.1", 6767),
            server_addresses=["192.0.2.1"],
            **{name: b"id"},
        )
