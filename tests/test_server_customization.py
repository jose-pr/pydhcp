import ipaddress
from datetime import datetime, timedelta
from unittest.mock import Mock

from pydhcp import DhcpLease, DhcpMessage, DhcpOptions, NetworkInterface, RequestContext
from pydhcp.enum import DhcpMessageType, DhcpOptionCode, Flags, HardwareAddressType, OpCode
from pydhcp.netutils import IPv4, SocketAddress
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
