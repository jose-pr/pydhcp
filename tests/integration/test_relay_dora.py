import time
from datetime import datetime, timedelta

from pydhcp import DhcpClient, DhcpLease, DhcpOptions, DhcpRelay, DhcpServer
from pydhcp.packet import DhcpMessageType
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4


CHADDR = b"\x11\x22\x33\x44\x55\x66"


class _FixedLeaseServer(DhcpServer):
    DEFAULT_PORTS = (6767,)

    def acquire_lease(self, client_id, server_id, msg):
        options = DhcpOptions()
        options[DhcpOptionCode.ROUTER] = IPv4("127.0.0.1")
        return DhcpLease(IPv4("127.0.0.1"), datetime.now() + timedelta(seconds=60), options)


def _wait_bound(listener, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while not listener._sockets and time.time() < deadline:
        time.sleep(0.01)


def test_full_dora_through_relay() -> None:
    server = _FixedLeaseServer(listen=[("127.0.0.1", 0)])
    server_thread = server.start()
    _wait_bound(server)
    server_port = server._sockets[0].getsockname()[1]

    relay = DhcpRelay(listen=[("127.0.0.1", 0)], server_addresses=[("127.0.0.1", server_port)])
    relay_thread = relay.start()
    _wait_bound(relay)
    relay_port = relay._sockets[0].getsockname()[1]

    client = DhcpClient(listen=("127.0.0.1", 0))
    client_thread = client.start()
    _wait_bound(client)

    try:
        ack = client.dora(CHADDR, timeout=2.0, retries=1, destination="127.0.0.1", port=relay_port)
        assert ack is not None
        assert ack.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPACK
        assert ack.yiaddr == IPv4("127.0.0.1")

        assert relay.metrics.packets_received >= 2
        assert relay.metrics.packets_sent >= 2
        assert relay.metrics.packets_dropped_hop_limit == 0
    finally:
        client.stop()
        if client_thread:
            client_thread.join(timeout=1.0)
        relay.stop()
        if relay_thread:
            relay_thread.join(timeout=1.0)
        server.stop()
        if server_thread:
            server_thread.join(timeout=1.0)
