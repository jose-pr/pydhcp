from __future__ import annotations

import asyncio
import socket
import time
from pydhcp import AsyncDhcpServer, DhcpMessage, DhcpOptions
from pydhcp.options.type import IPv4Address
from pydhcp.packet import DhcpMessageType
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4
from conftest import build_request


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

    discover = build_request(options=opts, xid=1000 + client_id_int, chaddr=mac)

    start_time = time.perf_counter()
    protocol.transport.sendto(discover.encode(), ("127.0.0.1", server_port))

    # Recv OFFER
    data, addr = await asyncio.wait_for(protocol.queue.get(), timeout=10.0)
    offer = DhcpMessage.decode(data)
    assert (
        offer.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPOFFER
    )

    # 2. Send REQUEST
    req_opts = DhcpOptions()
    req_opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPREQUEST
    req_opts[DhcpOptionCode.REQUESTED_IP] = offer.yiaddr
    req_opts[DhcpOptionCode.CLIENT_IDENTIFIER] = mac

    request = build_request(options=req_opts, xid=2000 + client_id_int, chaddr=mac)
    protocol.transport.sendto(request.encode(), ("127.0.0.1", server_port))

    # Recv ACK
    data, addr = await asyncio.wait_for(protocol.queue.get(), timeout=10.0)
    ack = DhcpMessage.decode(data)
    assert ack.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
    latency = time.perf_counter() - start_time

    transport.close()
    return latency


def test_async_concurrency():
    # Port 0, then read the port back: a fixed test port collides with whatever
    # else holds it, and on Windows the collision surfaces as WSAEACCES rather
    # than "address in use".
    server = MockAsyncServerForConcurrency(listen=[("127.0.0.1", 0)])

    async def main():
        await server.start()
        server_port = server.bound_addresses[0].port
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
