from __future__ import annotations

import asyncio
import socket
import pytest
import time
from datetime import timedelta
from pydhcp import AsyncDhcpServer, DhcpMessage, DhcpLease, DhcpOptions, IPv4Address
from pydhcp.enum import OpCode, DhcpMessageType, DhcpOptionCode, HardwareAddressType, Flags
from pydhcp.netutils import IPv4

class MockAsyncServerForConcurrency(AsyncDhcpServer):
    def acquire_lease(self, client_id, server_id, msg):
        requested_ip = msg.options.get(DhcpOptionCode.REQUESTED_IP, decode=IPv4Address)
        ip = requested_ip if requested_ip else IPv4("127.0.0.1")
        options = DhcpOptions()
        return self.lease_backend.allocate(client_id, ip, 3600, options)


class ClientProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.queue.put_nowait((data, addr))


async def run_client(client_id_int: int, server_port: int):
    mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, client_id_int])
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ClientProtocol(),
        local_addr=("127.0.0.1", 0),
        family=socket.AF_INET,
    )
    assert protocol.transport is not None

    # 1. Send DISCOVER
    opts = DhcpOptions()
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    opts[DhcpOptionCode.CLIENT_IDENTIFIER] = mac
    
    discover = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=1000 + client_id_int,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4('0.0.0.0'),
        yiaddr=IPv4('0.0.0.0'),
        siaddr=IPv4('0.0.0.0'),
        giaddr=IPv4('0.0.0.0'),
        chaddr=mac,
        sname='',
        file='',
        options=opts
    )

    start_time = time.perf_counter()
    protocol.transport.sendto(discover.encode(), ("127.0.0.1", server_port))

    # Recv OFFER
    data, addr = await asyncio.wait_for(protocol.queue.get(), timeout=10.0)
    offer = DhcpMessage.decode(data)
    assert offer.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPOFFER

    # 2. Send REQUEST
    req_opts = DhcpOptions()
    req_opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPREQUEST
    req_opts[DhcpOptionCode.REQUESTED_IP] = offer.yiaddr
    req_opts[DhcpOptionCode.CLIENT_IDENTIFIER] = mac
    
    request = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=2000 + client_id_int,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4('0.0.0.0'),
        yiaddr=IPv4('0.0.0.0'),
        siaddr=IPv4('0.0.0.0'),
        giaddr=IPv4('0.0.0.0'),
        chaddr=mac,
        sname='',
        file='',
        options=req_opts
    )
    protocol.transport.sendto(request.encode(), ("127.0.0.1", server_port))

    # Recv ACK
    data, addr = await asyncio.wait_for(protocol.queue.get(), timeout=10.0)
    ack = DhcpMessage.decode(data)
    assert ack.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
    latency = time.perf_counter() - start_time

    transport.close()
    return latency


def test_async_concurrency():
    server_port = 10069
    server = MockAsyncServerForConcurrency(listen=[("127.0.0.1", server_port)])
    
    async def main():
        await server.start()
        try:
            tasks = [run_client(i, server_port) for i in range(5)]
            latencies = await asyncio.gather(*tasks)
            assert len(latencies) == 5

            latencies.sort()
            p50 = latencies[len(latencies) // 2]
            p95 = latencies[int(len(latencies) * 0.95)]
            p99 = latencies[int(len(latencies) * 0.99)]
            print(f"\nLatency: p50={p50:.4f}s, p95={p95:.4f}s, p99={p99:.4f}s")
        finally:
            await server.stop()

    asyncio.run(main())
