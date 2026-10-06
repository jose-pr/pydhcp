"""Replies on a host with more than one interface, judged by what each segment saw.

On a wildcard socket a reply is pinned to the interface the request arrived on.
That is right for a broadcast and for a destination on that segment. RFC 2131
s4.1 makes every other reply an ordinary unicast ("the server unicasts
DHCPOFFER and DHCPACK messages to the address in 'giaddr'") that the routing
table delivers, and the BROADCAST hint is "to broadcast any messages to the
client on the client's subnet": a reply must not reach a segment the client is
not on, and a relay must hand a reply to the client's segment whatever else is
going on.

Sinks are `tap`s on every segment, so each assertion is about frames on a
wire, not about what the library says it did.
"""

from __future__ import annotations

import pytest

from pydhcp import DHCPRelay

from ._topo import RELAY_CLIENT_SIDE_MAC, relayed, two_homed

CHADDR = "020000000099"


def _offers(tap):
    return [f for f in tap.frames() if f.sport == 67 and f.type_name() == "DHCPOFFER"]


def test_a_unicast_reply_routed_through_another_interface_arrives(lab):
    net = two_homed(lab)
    tap_a = lab.tap(net.a, "a0", "segment-a")
    tap_b = lab.tap(net.b, "b0", "segment-b")
    server = lab.python(
        net.srv, "pool_server.py", "--relay-network", "10.205.0.0/24", name="server"
    )
    assert server.wait_for_text("serving"), server.text()

    # A relay on segment A forwards a request for a client behind 10.205.0.9,
    # an address the server reaches through its default route on segment B.
    lab.python_wait(
        net.a,
        "emit.py",
        "relayed",
        "--src",
        "10.203.0.2",
        "--src-port",
        "67",
        "--dst",
        "10.203.0.1",
        "--giaddr",
        "10.205.0.9",
        "--chaddr",
        CHADDR,
    )
    arrived = tap_b.wait_for(lambda frames: any(f.sport == 67 for f in frames), 4)

    assert _offers(tap_a) == []
    assert arrived, "the reply was lost: nothing reached segment B"
    reply = _offers(tap_b)[0]
    assert reply.dst_ip == "10.205.0.9"
    # From the address the request was sent to, as the client's relay expects.
    assert reply.src_ip == "10.203.0.1"


def _broadcast_discover_held_in_the_server(lab, net):
    """A DISCOVER on segment A, held inside the server while the test acts."""
    ready = lab.work / "ready"
    gate = lab.work / "gate"
    server = lab.python(
        net.srv,
        "pool_server.py",
        "--gate-chaddr",
        CHADDR,
        "--gate-file",
        str(gate),
        "--ready-file",
        str(ready),
        "--status",
        str(lab.work / "server.json"),
        name="server",
    )
    assert server.wait_for_text("serving"), server.text()
    lab.python_wait(net.a, "emit.py", "discover", "--chaddr", CHADDR)
    assert lab.wait_file(ready), server.text()
    return server, gate


def test_a_broadcast_reply_stays_on_the_arrival_segment(lab):
    net = two_homed(lab)
    tap_a = lab.tap(net.a, "a0", "segment-a")
    tap_b = lab.tap(net.b, "b0", "segment-b")
    _server, gate = _broadcast_discover_held_in_the_server(lab, net)

    gate.touch()
    assert tap_a.wait_for(lambda frames: any(f.sport == 67 for f in frames), 5)

    assert len(_offers(tap_a)) == 1
    assert _offers(tap_a)[0].src_ip == "10.203.0.1"
    assert _offers(tap_b) == []


def test_a_broadcast_reply_whose_pin_fails_never_reaches_another_segment(lab):
    net = two_homed(lab)
    tap_a = lab.tap(net.a, "a0", "segment-a")
    tap_b = lab.tap(net.b, "b0", "segment-b")
    _server, gate = _broadcast_discover_held_in_the_server(lab, net)

    # The address the reply is pinned to leaves the host while the reply is
    # being decided, so the pinned send fails.
    lab.run(net.srv, [lab.ip, "addr", "del", "10.203.0.1/24", "dev", "sa"])
    gate.touch()
    tap_b.wait_for(lambda frames: any(f.sport == 67 for f in frames), 4)

    assert _offers(tap_b) == [], "the reply appeared on the other segment"
    # Where it must not be is the one claim; it may stay on A or be dropped.
    assert len(_offers(tap_a)) <= 1


def _relayed_exchange(lab, forged: int):
    """A client's DISCOVER through the relay, with `forged` requests from another
    segment arriving while the server holds the real one. Returns the taps on the
    client's segment and the server's."""
    net = relayed(lab, with_forger=True, client_addr="10.99.0.50/24")
    tap_client = lab.tap(net.cli, "cv0", "client-segment")
    tap_server = lab.tap(net.srv, "sv0", "server-segment")
    ready = lab.work / "ready"
    gate = lab.work / "gate"
    server = lab.python(
        net.srv,
        "pool_server.py",
        "--relay-network",
        "10.99.0.0/24",
        "--gate-chaddr",
        CHADDR,
        "--gate-file",
        str(gate),
        "--ready-file",
        str(ready),
        name="server",
    )
    assert server.wait_for_text("serving"), server.text()
    relay = lab.python(net.rly, "relay.py", net.server_ip, name="relay")
    assert relay.wait_for_text("relaying"), relay.text()

    # The client's request is forwarded and held in the server...
    lab.python_wait(
        net.cli, "emit.py", "discover", "--chaddr", CHADDR, "--device", "cv0"
    )
    assert lab.wait_file(ready), server.text()
    # ...while a host on another segment sends requests, each from a different client.
    if forged:
        lab.python_wait(
            net.forger,
            "emit.py",
            "flood",
            "--src",
            "10.97.0.2",
            "--count",
            str(forged),
            "--device",
            "fb0",
        )
        forwarded = tap_server.wait_for(
            lambda frames: sum(
                1 for f in frames if f.src_ip == "10.98.0.1" and f.sport == 67
            )
            >= forged,
            30,
        )
        assert forwarded, "the relay did not forward the flood"

    gate.touch()
    tap_client.wait_for(lambda frames: any(f.sport == 67 for f in frames), 5)
    return tap_client, tap_server


def test_a_reply_leaves_by_the_clients_interface(lab):
    tap_client, tap_server = _relayed_exchange(lab, forged=0)

    assert [f.src_mac for f in _offers(tap_client)] == [RELAY_CLIENT_SIDE_MAC]
    assert [f for f in _offers(tap_server) if f.src_ip == "10.98.0.1"] == []


@pytest.mark.xfail(
    strict=True,
    reason="a flood of forged requests evicts the real client's entry and its "
    "reply stops leaving by the client's interface",
)
def test_a_reply_still_leaves_by_the_clients_interface_after_a_forged_flood(lab):
    # One request more than the relay remembers (the real client's is the
    # oldest entry), each from a different client.
    tap_client, tap_server = _relayed_exchange(lab, DHCPRelay.MAX_PENDING_CLIENTS + 1)

    assert [f.src_mac for f in _offers(tap_client)] == [RELAY_CLIENT_SIDE_MAC]
    assert [f for f in _offers(tap_server) if f.src_ip == "10.98.0.1"] == []
