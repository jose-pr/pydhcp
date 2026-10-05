"""ISC dhclient against the server, on one segment.

RFC 2131 s4.3.1 and s4.1: a client with no address broadcasts DHCPDISCOVER; the
server answers where the client can hear it. A client that cannot yet answer
ARP for the address it is offered has the reply broadcast to it (or sent to its
hardware address), and the server's own address is the source and the server
identifier. The client completes the exchange and configures what it was given.
"""

from __future__ import annotations

import pytest

from ._peers import dhclient
from ._topo import ROLES_SINGLE, single
from .conftest import need, peer_version, record_case


@pytest.mark.parametrize("kind", ["sync", "async"])
def test_dhclient_completes_dora_from_a_wildcard_server(lab, kind):
    need("dhclient")
    net = single(lab)
    tap = lab.tap(net.cli, "cv0", "client-segment")
    server = lab.python(
        net.srv,
        "pool_server.py",
        *(["--async"] if kind == "async" else []),
        name=f"server-{kind}",
    )
    assert server.wait_for_text("serving"), server.text()

    client = dhclient(lab, net.cli, "cv0")
    lease = client.wait_bound(30)

    assert lease is not None, (client.proc.text(), server.text())
    assert lease.fields["ip_address"].startswith("10.99.0.1")
    assert lease.fields["subnet_mask"] == "255.255.255.0"
    assert lease.fields["routers"] == "10.99.0.1"
    assert lease.fields["domain_name"] == "lab.test"
    assert lease.fields["interface_mtu"] == "1400"

    replies = [f for f in tap.frames() if f.sport == 67]
    names = [f.type_name() for f in replies]
    assert names[:2] == ["DHCPOFFER", "DHCPACK"], names
    for frame in replies:
        assert frame.src_ip == net.server_ip
        assert frame.dst_ip == "255.255.255.255"
        assert frame.dst_mac == "ff:ff:ff:ff:ff:ff"
        assert frame.dport == 68

    record_case(
        f"dhclient_{kind}_server_dora",
        "dhclient with no address obtains a lease from a wildcard-bound "
        f"{kind} pydhcp server on one segment",
        peer_version("dhclient", "--version"),
        {"client-segment": tap},
        ROLES_SINGLE | {"02:00:00:99:00:01": "pydhcp-server"},
    )
