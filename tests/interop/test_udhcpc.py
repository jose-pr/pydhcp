"""BusyBox udhcpc, a second implementation of the client side.

One client implementation is one reading of the RFC. udhcpc builds its requests
differently (no host-name by default, a vendor class, its own retransmission
timing) and configures through its own script interface.
"""

from __future__ import annotations

from pydhcp.options import DhcpOptionCode

from ._peers import udhcpc
from ._topo import (
    RELAY_CLIENT_SIDE_MAC,
    ROLES_RELAYED,
    ROLES_SINGLE,
    relayed,
    single,
)
from .conftest import _cannot, need, peer_version, record_case


def _need_udhcpc() -> None:
    need("busybox")
    import subprocess

    from ._lab import which

    listed = subprocess.run(
        [which("busybox") or "busybox", "--list"], capture_output=True, text=True
    ).stdout.split()
    if "udhcpc" not in listed:
        _cannot("this busybox has no udhcpc applet")


def _version() -> str:
    return peer_version("busybox") + " (udhcpc)"


def test_udhcpc_completes_dora_from_the_server(lab):
    _need_udhcpc()
    net = single(lab)
    tap = lab.tap(net.cli, "cv0", "client-segment")
    server = lab.python(net.srv, "pool_server.py", name="server")
    assert server.wait_for_text("serving"), server.text()

    client = udhcpc(lab, net.cli, "cv0", extra=["-O", "mtu"])
    lease = client.wait_bound(30)

    assert lease is not None, (client.proc.text(), server.text())
    assert lease.fields["ip"].startswith("10.99.0.1")
    assert lease.fields["router"] == "10.99.0.1"
    assert lease.fields["domain"] == "lab.test"
    assert lease.fields["mtu"] == "1400"
    replies = [f for f in tap.frames() if f.sport == 67]
    assert [f.type_name() for f in replies][:2] == ["DHCPOFFER", "DHCPACK"]
    assert {f.src_ip for f in replies} == {net.server_ip}

    record_case(
        "udhcpc_server_dora",
        "udhcpc with no address obtains a lease from a wildcard-bound pydhcp "
        "server on one segment",
        _version(),
        {"client-segment": tap},
        ROLES_SINGLE | {"02:00:00:99:00:01": "pydhcp-server"},
    )


def test_udhcpc_completes_dora_through_the_relay(lab):
    _need_udhcpc()
    net = relayed(lab)
    client_tap = lab.tap(net.cli, "cv0", "client-segment")
    server_tap = lab.tap(net.srv, "sv0", "server-segment")
    server = lab.python(
        net.srv, "pool_server.py", "--relay-network", "10.99.0.0/24", name="server"
    )
    assert server.wait_for_text("serving"), server.text()
    relay = lab.python(net.rly, "relay.py", net.server_ip, name="relay")
    assert relay.wait_for_text("relaying"), relay.text()

    client = udhcpc(lab, net.cli, "cv0")
    lease = client.wait_bound(30)

    assert lease is not None, (client.proc.text(), relay.text(), server.text())
    assert lease.fields["ip"].startswith("10.99.0.1")
    assert lease.fields["router"] == net.relay_client_ip
    delivered = [f for f in client_tap.frames() if f.sport == 67]
    assert [f.type_name() for f in delivered][:2] == ["DHCPOFFER", "DHCPACK"]
    assert {f.src_mac for f in delivered} == {RELAY_CLIENT_SIDE_MAC}
    for frame in delivered:
        assert DhcpOptionCode.RELAY_AGENT_INFORMATION not in frame.message().options

    record_case(
        "udhcpc_relay_dora",
        "udhcpc obtains a lease through a pydhcp relay from a pydhcp server on "
        "another segment",
        _version(),
        {"client-segment": client_tap, "server-segment": server_tap},
        {
            **ROLES_RELAYED,
            RELAY_CLIENT_SIDE_MAC: "pydhcp-relay",
            "02:00:00:98:00:01": "pydhcp-relay",
            "02:00:00:98:00:02": "pydhcp-server",
        },
    )
