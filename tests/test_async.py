import asyncio
import socket
import pytest
from pydhcp import AsyncDHCPServer, DHCPMessage, DHCPLease, DHCPOptions
from pydhcp.packet import DHCPMessageType, DHCPOpcode
from pydhcp.options import DHCPOptionCode
from ipaddress import IPv4Address as IPv4
from pydhcp import SocketAddress
from helpers import LOOPBACK_ALIAS_BINDABLE, build_request


class MockAsyncDHCPServer(AsyncDHCPServer):
    def acquire_lease(self, client_id, server_id, msg, *, commit=True):
        from datetime import datetime, timedelta, timezone

        options = DHCPOptions()
        return DHCPLease(
            IPv4("127.0.0.1"),
            datetime.now(timezone.utc) + timedelta(seconds=10),
            options,
        )


def test_async_server_lifecycle():
    async def run_test():
        # Port 0, then read the port back: a fixed test port collides with
        # whatever else holds it, and on Windows the collision surfaces as
        # WSAEACCES rather than "address in use".
        server = MockAsyncDHCPServer(listen=[("127.0.0.1", 0)])
        await server.start()
        server_port = server.bound_addresses[0].port

        # We want to send a UDP packet and get a response
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.bind(("127.0.0.1", 0))
        # The client is on an ephemeral port, not 68.
        server.REPLY_TO_CLIENT_PORT = client_sock.getsockname()[1]

        # Construct a DHCP DISCOVER message
        from datetime import timedelta

        data = build_request(DHCPMessageType.DHCPDISCOVER, xid=0x3903F326).encode()

        loop = asyncio.get_running_loop()
        # Send the packet to the server
        client_sock.sendto(data, ("127.0.0.1", server_port))

        # Wait for the response
        try:
            resp_data, addr = await asyncio.wait_for(
                loop.run_in_executor(None, client_sock.recvfrom, 2048), timeout=20.0
            )

            resp_msg = DHCPMessage.decode(resp_data)
            assert resp_msg.op == DHCPOpcode.BOOTREPLY
            assert (
                resp_msg.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
                == DHCPMessageType.DHCPOFFER
            )
        finally:
            await server.aclose()
            client_sock.close()

    asyncio.run(run_test())


# --- AsyncDHCPServer must honour the contract it inherits ---


def test_async_server_has_the_same_state_as_the_sync_one():
    """AsyncDHCPServer cannot call DHCPServer.__init__, so it re-implemented the
    body and drifted: _declined was added to one and not the other, making every
    DHCPDECLINE an AttributeError on the async server."""
    from ipaddress import IPv4Address as IPv4
    from pydhcp.listener import AsyncDHCPListener, DHCPListener
    from pydhcp.server import AsyncDHCPServer, DHCPServer

    sync = DHCPServer(listen=("127.0.0.1", 0))
    server = AsyncDHCPServer(listen=("127.0.0.1", 0))
    try:
        missing = [
            name for name in ("lease_backend", "_declined") if not hasattr(server, name)
        ]
        assert not missing, f"async server is missing {missing}"
        # and the state actually works, not just exists
        server.quarantine_address(IPv4("10.0.0.5"))
        assert IPv4("10.0.0.5") in server._declined
        # Every attribute DHCPServer._init_server_state owns must be on both.
        # Listener internals legitimately differ (the async half has a worker
        # and receive tasks, the sync half a wake socket and a select loop), so
        # this compares the server layer only.
        server_state = set(vars(DHCPServer(listen=("127.0.0.1", 0)))) - set(
            vars(AsyncDHCPServer(listen=("127.0.0.1", 0)))
        )
        sync_listener_only = set(vars(DHCPListener(listen=("127.0.0.1", 0)))) - set(
            vars(AsyncDHCPListener(listen=("127.0.0.1", 0)))
        )
        assert server_state <= sync_listener_only, server_state - sync_listener_only
    finally:
        sync.close()


def test_async_handler_does_not_run_on_the_event_loop() -> None:
    """The handler is ordinary synchronous code -- lease lookups, a whole-file
    rewrite in FileLeaseBackend, interface work -- so running it inline blocked
    every other coroutine in the host application. Measured with a 10 ms ticker
    alongside a 30 ms handler: worst gap 98 ms before, 27 ms after (Windows,
    where an idle loop already measures 25 ms).
    """
    import asyncio
    import threading

    from pydhcp.server import AsyncDHCPServer

    seen: dict = {}

    class ThreadRecordingServer(AsyncDHCPServer):
        def handle(self, msg, context):
            seen["handler"] = threading.current_thread()

    async def main():
        server = ThreadRecordingServer(listen=("127.0.0.1", 0))
        await server.start()
        seen["loop"] = threading.current_thread()
        port = server.bound_addresses[0].port
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.sendto(_discover_bytes(), ("127.0.0.1", port))
            sender.close()
            for _ in range(100):
                if "handler" in seen:
                    break
                await asyncio.sleep(0.02)
        finally:
            await server.aclose()

    asyncio.run(main())

    assert "handler" in seen, "the datagram was never handled"
    assert seen["handler"] is not seen["loop"], "handler ran on the event loop"


def test_async_handlers_stay_serialised() -> None:
    """One worker, deliberately: the lease backends are not thread-safe, so a
    pool would trade a blocked event loop for a data race."""
    import asyncio
    import threading
    import time

    from pydhcp.server import AsyncDHCPServer

    overlaps = []
    active = []
    lock = threading.Lock()

    class OverlapDetectingServer(AsyncDHCPServer):
        def handle(self, msg, context):
            with lock:
                active.append(1)
                overlaps.append(len(active))
            time.sleep(0.02)
            with lock:
                active.pop()

    async def main():
        server = OverlapDetectingServer(listen=("127.0.0.1", 0))
        await server.start()
        port = server.bound_addresses[0].port
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for _ in range(5):
                sender.sendto(_discover_bytes(), ("127.0.0.1", port))
            sender.close()
            for _ in range(100):
                if len(overlaps) >= 5:
                    break
                await asyncio.sleep(0.02)
        finally:
            await server.aclose()

    asyncio.run(main())

    assert overlaps, "no datagrams were handled"
    assert max(overlaps) == 1, f"handlers overlapped: {overlaps}"


def _discover_bytes() -> bytes:
    return bytes(build_request(DHCPMessageType.DHCPDISCOVER, xid=0x5A5A5A5A).encode())


def test_async_listener_uses_the_same_receive_path_as_the_sync_one():
    """A wildcard async listen must take the packet-info path where it exists.

    It used to hardcode `_pktinfo = False` and expand the wildcard into one
    socket per address. On Linux an address-bound socket receives no broadcasts,
    so a real dhclient's DISCOVER -- which goes to 255.255.255.255 -- reached the
    async server never, while the identical sync server answered it. Verified
    against ISC dhclient 4.4.3 over a veth pair: nothing before, full DORA after.
    """
    from pydhcp.listener import AsyncDHCPListener, DHCPListener

    for spec in ("*", ("*", 10067), None):
        sync = DHCPListener(listen=spec)
        expected = sync._pktinfo
        assert (
            AsyncDHCPListener(listen=spec)._pktinfo == expected
        ), f"listeners disagree about the receive path for {spec!r}"
        # And so the wildcard stays unexpanded in the same cases: expanding it is
        # precisely what loses the broadcasts on Linux.
        assert (len(AsyncDHCPListener(listen=spec)._listen) == len(sync._listen)) or (
            not expected
        )


def test_async_listener_builds_a_packet_info_context():
    """The received interface must reach the handler, not just the socket.

    _context_for is shared with the sync listener for this reason: the async
    half previously built its own DHCPRequestContext and dropped ifindex/local_ip,
    so replies went out with whatever SERVER_IDENTIFIER the wildcard implied.
    """
    from pydhcp.listener import PktInfoUDPTransport, UDPTransport

    # the receive path is not public
    from pydhcp.listener._receive import _context_for

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    try:
        plain = _context_for(sock, SocketAddress(IPv4("127.0.0.1"), 68), b"\x00" * 6)
        assert type(plain.transport) is UDPTransport
        assert plain.ifindex is None and plain.local_ip is None

        routed = _context_for(
            sock,
            SocketAddress(IPv4("127.0.0.1"), 68),
            b"\x00" * 6,
            ifindex=7,
            local_ip=IPv4("127.0.0.1"),
        )
        assert isinstance(routed.transport, PktInfoUDPTransport)
        assert routed.transport.ifindex == 7
        assert routed.transport.local_ip == IPv4("127.0.0.1")
        assert routed.ifindex == 7 and routed.local_ip == IPv4("127.0.0.1")
    finally:
        sock.close()


@pytest.mark.skipif(
    not LOOPBACK_ALIAS_BINDABLE,
    reason="needs a second loopback address; macOS aliases only 127.0.0.1",
)
@pytest.mark.parametrize("already_waiting", [False, True])
def test_dropping_a_socket_under_a_waiting_receive_ends_its_task_quietly(
    already_waiting: bool,
) -> None:
    """Re-binding a started listener whose listen list shrank closes the sockets
    no longer wanted. Their receive tasks are waiting in `arecv`, which a close
    wakes with `RuntimeError`; that is the endpoint saying it is closed, and must
    not reach the loop as a task exception nobody retrieved."""

    async def run_test() -> "list[dict[str, object]]":
        reports: "list[dict[str, object]]" = []
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda _loop, context: reports.append(context))
        server = MockAsyncDHCPServer(listen=[("127.0.0.1", 0), ("127.0.0.2", 0)])
        await server.start()
        try:
            keep, drop = server._tasks
            if already_waiting:
                await asyncio.sleep(0)  # both receive tasks run to their `arecv`
            server._listen = server._listen[:1]
            server.bind()
            await asyncio.wait_for(drop, timeout=10.0)
            assert drop.exception() is None
            assert not keep.done()
        finally:
            await server.aclose()
        return reports

    assert asyncio.run(run_test()) == []


def test_async_oversized_datagram_is_dropped_rather_than_half_decoded() -> None:
    """The cut is reported by netimps as `truncated` on every platform, so the
    async receive loop counts it without a platform-specific error branch."""

    async def run_test() -> "tuple[int, int, int]":
        handled: "list[DHCPMessage]" = []

        class Recording(MockAsyncDHCPServer):
            def handle(self, msg, context) -> None:
                handled.append(msg)

        server = Recording(listen=[("127.0.0.1", 0)], max_packet_size=576)
        await server.start()
        try:
            port = server.bound_addresses[0].port
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.sendto(
                build_request().encode() + b"\x00" * 1102, ("127.0.0.1", port)
            )
            sender.close()
            for _ in range(100):
                if server.metrics.packets_dropped_truncated:
                    break
                await asyncio.sleep(0.05)
        finally:
            await server.aclose()
        return (
            len(handled),
            server.metrics.packets_dropped_truncated,
            server.metrics.packets_received,
        )

    assert asyncio.run(run_test()) == (0, 1, 0)
