from pydhcp import DHCPClient, DHCPRelay
from pydhcp.packet import DHCPMessageType
from pydhcp.options import DHCPOptionCode
from ipaddress import IPv4Address as IPv4
from conftest import FixedLeaseServer, running

CHADDR = b"\x11\x22\x33\x44\x55\x66"


def test_full_dora_through_relay() -> None:
    server = FixedLeaseServer(listen=[("127.0.0.1", 0)])
    with running(server):
        server_port = server.bound_addresses[0].port

        relay = DHCPRelay(
            listen=[("127.0.0.1", 0)], server_addresses=[("127.0.0.1", server_port)]
        )
        with running(relay):
            relay_port = relay.bound_addresses[0].port
            # The relay is on an ephemeral port, not 67; the relay itself
            # answers the client on the port the client sent from.
            server.REPLY_TO_RELAY_PORT = relay_port

            with running(DHCPClient(listen=("127.0.0.1", 0))) as client:
                ack = client.dora(
                    CHADDR,
                    timeout=2.0,
                    retries=1,
                    destination="127.0.0.1",
                    port=relay_port,
                    broadcast=False,
                )
                assert ack is not None
                assert (
                    ack.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
                    == DHCPMessageType.DHCPACK
                )
                assert ack.yiaddr == IPv4("127.0.0.1")

                assert relay.metrics.packets_received >= 2
                assert relay.metrics.packets_sent >= 2
                assert relay.metrics.packets_dropped_hop_limit == 0
