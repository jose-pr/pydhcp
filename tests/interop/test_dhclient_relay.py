"""ISC dhclient through the relay to the server.

RFC 1542 s4.1.1 and RFC 2131 s4.1: the relay stamps giaddr with its address on
the client's segment and forwards the request to the server by unicast; the
server answers to giaddr; the relay hands the reply to the client on the
client's segment. RFC 3046: option 82 is added toward the server and removed
from what the client receives.
"""

from __future__ import annotations

import pytest

from pydhcp.options import DHCPOptionCode

from ._peers import dhclient
from ._topo import RELAY_CLIENT_SIDE_MAC, ROLES_RELAYED, relayed
from .conftest import need, peer_version, record_case


@pytest.mark.parametrize("kind", ["sync", "async"])
def test_dhclient_completes_dora_through_the_relay(lab, kind):
    need("dhclient")
    net = relayed(lab)
    client_tap = lab.tap(net.cli, "cv0", "client-segment")
    server_tap = lab.tap(net.srv, "sv0", "server-segment")
    server = lab.python(
        net.srv, "pool_server.py", "--relay-network", "10.99.0.0/24", name="server"
    )
    assert server.wait_for_text("serving"), server.text()
    relay = lab.python(
        net.rly,
        "relay.py",
        net.server_ip,
        *(["--async"] if kind == "async" else []),
        name=f"relay-{kind}",
    )
    assert relay.wait_for_text("relaying"), relay.text()

    client = dhclient(lab, net.cli, "cv0")
    lease = client.wait_bound(30)

    assert lease is not None, (client.proc.text(), relay.text(), server.text())
    assert lease.fields["ip_address"].startswith("10.99.0.1")
    assert lease.fields["routers"] == net.relay_client_ip

    # Toward the server: unicast from the relay, giaddr stamped, option 82 added.
    forwarded = [f for f in server_tap.frames() if f.src_ip == "10.98.0.1"]
    assert {f.type_name() for f in forwarded} >= {"DHCPDISCOVER", "DHCPREQUEST"}
    for frame in forwarded:
        message = frame.message()
        assert frame.dst_ip == net.server_ip
        assert str(message.giaddr) == net.relay_client_ip
        assert DHCPOptionCode.RELAY_AGENT_INFORMATION in message.options

    # Toward the client: out by the client's interface, from the relay's address
    # there, with option 82 gone.
    delivered = [f for f in client_tap.frames() if f.sport == 67]
    assert [f.type_name() for f in delivered][:2] == ["DHCPOFFER", "DHCPACK"]
    for frame in delivered:
        assert frame.src_mac == RELAY_CLIENT_SIDE_MAC
        assert frame.src_ip == net.relay_client_ip
        assert DHCPOptionCode.RELAY_AGENT_INFORMATION not in frame.message().options

    record_case(
        f"dhclient_{kind}_relay_dora",
        f"dhclient obtains a lease through a {kind} pydhcp relay from a "
        "pydhcp server on another segment",
        peer_version("dhclient", "--version"),
        {"client-segment": client_tap, "server-segment": server_tap},
        {
            **ROLES_RELAYED,
            RELAY_CLIENT_SIDE_MAC: "pydhcp-relay",
            "02:00:00:98:00:01": "pydhcp-relay",
            "02:00:00:98:00:02": "pydhcp-server",
        },
    )
