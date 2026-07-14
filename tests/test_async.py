import asyncio
import socket
import pytest
from pydhcp import AsyncDhcpServer, DhcpMessage, DhcpLease, DhcpOptions
from pydhcp.packet import DhcpMessageType, OpCode
from pydhcp.options import DhcpOptionCode
from pydhcp.network import SocketAddress, IPv4

class MockAsyncDhcpServer(AsyncDhcpServer):
    def acquire_lease(self, client_id, server_id, msg):
        from datetime import datetime, timedelta
        options = DhcpOptions()
        return DhcpLease(IPv4("127.0.0.1"), datetime.now() + timedelta(seconds=10), options)

def test_async_server_lifecycle():
    async def run_test():
        # Bind to a high port on localhost for testing
        server = MockAsyncDhcpServer(listen=[("127.0.0.1", 10067)])
        await server.start()
        
        # We want to send a UDP packet and get a response
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.bind(("127.0.0.1", 0))
        
        # Construct a DHCP DISCOVER message
        from datetime import timedelta
        from pydhcp.packet import HardwareAddressType, Flags
        
        options = DhcpOptions()
        options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
        
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
        
        data = msg.encode()
        
        loop = asyncio.get_running_loop()
        # Send the packet to the server
        client_sock.sendto(data, ("127.0.0.1", 10067))
        
        # Wait for the response
        try:
            resp_data, addr = await asyncio.wait_for(
                loop.run_in_executor(None, client_sock.recvfrom, 2048),
                timeout=2.0
            )
                
            resp_msg = DhcpMessage.decode(resp_data)
            assert resp_msg.op == OpCode.BOOTREPLY
            assert resp_msg.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPOFFER
        finally:
            await server.stop()
            client_sock.close()
            
    asyncio.run(run_test())
