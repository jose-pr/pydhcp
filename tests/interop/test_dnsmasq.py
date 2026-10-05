"""dnsmasq as the other end: a stock server behind the relay, a stock server in
front of pydhcp's own client.

The server side of the relay and the client library are only ever exercised
against pydhcp otherwise, so a misreading shared by both halves would pass.
"""

from __future__ import annotations

import json

from pydhcp.options import DhcpOptionCode

from ._peers import dhclient, dnsmasq
from ._topo import RELAY_CLIENT_SIDE_MAC, ROLES_RELAYED, ROLES_SINGLE, relayed, single
from .conftest import need, peer_version, record_case

RANGE = "10.99.0.100,10.99.0.150,255.255.255.0,5m"


def test_dhclient_completes_dora_through_the_relay_from_dnsmasq(lab):
    need("dhclient", "dnsmasq")
    net = relayed(lab)
    client_tap = lab.tap(net.cli, "cv0", "client-segment")
    server_tap = lab.tap(net.srv, "sv0", "server-segment")
    dnsmasq(lab, net.srv, "sv0", RANGE)
    relay = lab.python(net.rly, "relay.py", net.server_ip, name="relay")
    assert relay.wait_for_text("relaying"), relay.text()

    client = dhclient(lab, net.cli, "cv0")
    lease = client.wait_bound(30)

    assert lease is not None, (client.proc.text(), relay.text())
    assert lease.fields["ip_address"].startswith("10.99.0.1")
    delivered = [f for f in client_tap.frames() if f.sport == 67]
    assert [f.type_name() for f in delivered][:2] == ["DHCPOFFER", "DHCPACK"]
    assert {f.src_mac for f in delivered} == {RELAY_CLIENT_SIDE_MAC}
    forwarded = [f for f in server_tap.frames() if f.src_ip == "10.98.0.1"]
    assert {str(f.message().giaddr) for f in forwarded} == {net.relay_client_ip}

    record_case(
        "dnsmasq_behind_relay_dora",
        "dhclient obtains a lease through a pydhcp relay from dnsmasq on "
        "another segment",
        peer_version("dnsmasq", "--version")
        + "; "
        + peer_version("dhclient", "--version"),
        {"client-segment": client_tap, "server-segment": server_tap},
        {
            **ROLES_RELAYED,
            RELAY_CLIENT_SIDE_MAC: "pydhcp-relay",
            "02:00:00:98:00:01": "pydhcp-relay",
            "02:00:00:98:00:02": "dnsmasq",
        },
    )


def test_pydhcp_client_completes_dora_against_dnsmasq(lab):
    need("dnsmasq")
    # DhcpClient sends from an address the interface already holds.
    net = single(lab, client_addr="10.99.0.50/24")
    lab.route(net.cli, "default", "via", net.server_ip)
    tap = lab.tap(net.cli, "cv0", "client-segment")
    dnsmasq(lab, net.srv, "sv0", RANGE)

    out = lab.python_wait(net.cli, "client_dora.py", timeout=60)
    result = json.loads(out.strip().splitlines()[-1])

    assert result is not None, out
    assert result["yiaddr"].startswith("10.99.0.1")
    types = [f.type_name() for f in tap.frames()]
    assert types[:4] == ["DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST", "DHCPACK"], types
    assert DhcpOptionCode.SUBNET_MASK.name in result["options"]
    assert result["options"]["SUBNET_MASK"] == "255.255.255.0"

    record_case(
        "dnsmasq_pydhcp_client_dora",
        "pydhcp's DhcpClient completes DISCOVER, OFFER, REQUEST, ACK against dnsmasq",
        peer_version("dnsmasq", "--version"),
        {"client-segment": tap},
        ROLES_SINGLE
        | {"02:00:00:99:00:01": "dnsmasq", "02:00:00:99:00:02": "pydhcp-client"},
    )
