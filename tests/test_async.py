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
        return DhcpLease(
            IPv4("127.0.0.1"), datetime.now() + timedelta(seconds=10), options
        )


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
            ciaddr=IPv4("0.0.0.0"),
            yiaddr=IPv4("0.0.0.0"),
            siaddr=IPv4("0.0.0.0"),
            giaddr=IPv4("0.0.0.0"),
            chaddr=b"\x00\x11\x22\x33\x44\x55",
            sname="",
            file="",
            options=options,
        )

        data = msg.encode()

        loop = asyncio.get_running_loop()
        # Send the packet to the server
        client_sock.sendto(data, ("127.0.0.1", 10067))

        # Wait for the response
        try:
            resp_data, addr = await asyncio.wait_for(
                loop.run_in_executor(None, client_sock.recvfrom, 2048), timeout=2.0
            )

            resp_msg = DhcpMessage.decode(resp_data)
            assert resp_msg.op == OpCode.BOOTREPLY
            assert (
                resp_msg.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
                == DhcpMessageType.DHCPOFFER
            )
        finally:
            await server.stop()
            client_sock.close()

    asyncio.run(run_test())


# --- AsyncDhcpServer must honour the contract it inherits ---


def test_async_server_has_the_same_state_as_the_sync_one():
    """AsyncDhcpServer cannot call DhcpServer.__init__, so it re-implemented the
    body and drifted: _declined was added to one and not the other, making every
    DHCPDECLINE an AttributeError on the async server."""
    from pydhcp.network import IPv4
    from pydhcp.server import AsyncDhcpServer, DhcpServer

    sync = DhcpServer(listen=("127.0.0.1", 0))
    server = AsyncDhcpServer(listen=("127.0.0.1", 0))
    try:
        missing = [
            name for name in ("lease_backend", "_declined") if not hasattr(server, name)
        ]
        assert not missing, f"async server is missing {missing}"
        # and the state actually works, not just exists
        server.quarantine_address(IPv4("10.0.0.5"))
        assert IPv4("10.0.0.5") in server._declined
        # Every attribute DhcpServer._init_server_state owns must be on both.
        # Listener internals legitimately differ (the async half has transports
        # instead of a select loop, a cancellation token and a SIGINT handler),
        # so this compares the server layer only.
        server_state = set(vars(DhcpServer(listen=("127.0.0.1", 0)))) - set(
            vars(AsyncDhcpServer(listen=("127.0.0.1", 0)))
        )
        assert server_state <= {
            "_cancellation_token",
            "_previous_sigint",
            "_select_timeout",
            "_sigint_handler",
        }
    finally:
        server.stop()
        sync.close()


def test_async_stop_works_without_await():
    """stop() is reached through the inherited DhcpListener contract, where
    nobody awaits it. As a coroutine it silently did nothing and left the ports
    bound, and mypy accepted the call."""
    import asyncio

    from pydhcp.server import AsyncDhcpServer

    async def main():
        server = AsyncDhcpServer(listen=("127.0.0.1", 0))
        server.bind()
        assert server._sockets
        server.stop()  # no await
        assert server._sockets == []

    asyncio.run(main())


def test_async_stop_still_supports_await():
    """The documented form in README and docs/index.md."""
    import asyncio

    from pydhcp.server import AsyncDhcpServer

    async def main():
        server = AsyncDhcpServer(listen=("127.0.0.1", 0))
        server.bind()
        assert server._sockets
        await server.stop()
        assert server._sockets == []

    asyncio.run(main())
