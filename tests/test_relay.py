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


def test_relay_agent_info_passthrough_when_already_present():
    relay = DhcpRelay(
        listen=("127.0.0.1", 6767),
        server_addresses=["192.0.2.1"],
        insert_relay_agent_info=True,
        circuit_id=b"circuit-1",
    )
    context = _context()
    msg = _discover(with_relay_info=True)

    relay.handle(msg, context)

    data, *_rest = context.transport.send.call_args.args
    forwarded = DhcpMessage.decode(data)
    relay_info = forwarded.options.get(DhcpOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation)
    assert relay_info == RelayAgentInformation([TlvOption(1, b"existing")])


def test_forward_to_client_broadcast_flag():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _context()
    reply = _reply(giaddr="10.0.0.1", broadcast=True)

    relay.handle(reply, context)

    data, dest, port, mac = context.transport.send.call_args.args
    assert dest == IPv4("255.255.255.255")
    assert port == 68


def test_forward_to_client_ciaddr():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _context()
    reply = _reply(giaddr="10.0.0.1", ciaddr="10.0.0.50")

    relay.handle(reply, context)

    data, dest, port, mac = context.transport.send.call_args.args
    assert dest == IPv4("10.0.0.50")
    assert port == 68


def test_forward_to_client_yiaddr_fallback():
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    context = _context()
    reply = _reply(giaddr="10.0.0.1", yiaddr="10.0.0.60")

    relay.handle(reply, context)

    data, dest, port, mac = context.transport.send.call_args.args
    assert dest == IPv4("10.0.0.60")
    assert port == 68


def test_forward_to_client_uses_original_client_port_when_known():
    # A client that isn't listening on the well-known port 68 (e.g. an
    # ephemeral port in tests) must still get replies routed back to the
    # port its original request actually came from, not a hardcoded 68.
    relay = DhcpRelay(listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"])
    request_context = _context(client_port=54321)
    discover = _discover()

    relay.handle(discover, request_context)

    reply_context = _context(client_port=67)  # server's own source port
    reply = _reply(giaddr="10.0.0.1", ciaddr="10.0.0.50")
    relay.handle(reply, reply_context)

    data, dest, port, mac = reply_context.transport.send.call_args.args
    assert dest == IPv4("10.0.0.50")
    assert port == 54321
