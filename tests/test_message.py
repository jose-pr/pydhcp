import pytest
from datetime import timedelta
from pydhcp.message import DhcpMessage
from pydhcp.enum import OpCode, HardwareAddressType, Flags, DhcpOptionCode, DhcpMessageType
from pydhcp.netutils import IPv4
from pydhcp.options import DhcpOptions

def test_message_encode_decode():
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray([DhcpMessageType.DHCPDISCOVER.value])
    options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray([1, 0, 17, 34, 51, 68, 85])
    options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = bytearray([1, 3, 6, 15])

    msg = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x3903F326,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4('0.0.0.0'),
        yiaddr=IPv4('0.0.0.0'),
        siaddr=IPv4('0.0.0.0'),
        giaddr=IPv4('0.0.0.0'),
        chaddr=b'\x00\x11\x22\x33\x44\x55',
        sname='',
        file='',
        options=options
    )

    encoded = msg.encode()
    assert len(encoded) >= 240
    
    decoded = DhcpMessage.decode(encoded)
    assert decoded.op == OpCode.BOOTREQUEST
    assert decoded.xid == 0x3903F326
    assert decoded.chaddr.startswith(b'\x00\x11\x22\x33\x44\x55')
    assert decoded.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPDISCOVER


def test_message_edge_cases():
    # Message with sname and file populated
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray([DhcpMessageType.DHCPOFFER.value])
    msg = DhcpMessage(
        op=OpCode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=1,
        xid=0x11112222,
        secs=timedelta(seconds=5),
        flags=Flags.BROADCAST,
        ciaddr=IPv4('192.168.1.5'),
        yiaddr=IPv4('192.168.1.10'),
        siaddr=IPv4('192.168.1.1'),
        giaddr=IPv4('0.0.0.0'),
        chaddr=b'\x00\x11\x22\x33\x44\x55',
        sname='my-server-name',
        file='boot-file-path',
        options=options
    )
    encoded = msg.encode()
    decoded = DhcpMessage.decode(encoded)
    assert decoded.sname.startswith('my-server-name')
    assert decoded.file.startswith('boot-file-path')
    assert decoded.hops == 1
    assert decoded.secs == timedelta(seconds=5)
    assert decoded.flags == Flags.BROADCAST
    assert decoded.ciaddr == IPv4('192.168.1.5')
    assert decoded.yiaddr == IPv4('192.168.1.10')
    assert decoded.siaddr == IPv4('192.168.1.1')

    # String representations
    log_str = msg.log_str(IPv4('192.168.1.1'), IPv4('192.168.1.10'))
    assert "XID=11112222" in log_str

