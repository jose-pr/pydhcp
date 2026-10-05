"""The network shapes the scenarios run on.

Addresses are private ranges and hardware addresses are locally administered
(`02:...`), all chosen here: nothing on a recorded wire belongs to the host.
"""

from __future__ import annotations

import typing as _ty

from ._lab import Lab

CLIENT_MAC = "02:00:00:99:00:02"
SERVER_MAC = "02:00:00:99:00:01"

#: Who sent a frame, by hardware address, for the recorded cases.
ROLES_SINGLE = {SERVER_MAC: "server", CLIENT_MAC: "client"}


class Single(_ty.NamedTuple):
    """One segment, 10.99.0.0/24: the server at .1, a client with no address."""

    srv: str
    cli: str
    server_ip: str


def single(lab: Lab, client_addr: _ty.Optional[str] = None) -> Single:
    srv, cli = lab.netns("srv"), lab.netns("cli")
    lab.veth(
        srv,
        "sv0",
        cli,
        "cv0",
        mac1=SERVER_MAC,
        mac2=CLIENT_MAC,
        addr1="10.99.0.1/24",
        addr2=client_addr,
    )
    return Single(srv, cli, "10.99.0.1")


RELAY_CLIENT_SIDE_MAC = "02:00:00:99:00:01"
RELAY_SERVER_SIDE_MAC = "02:00:00:98:00:01"
SERVER_SEGMENT_MAC = "02:00:00:98:00:02"
ROLES_RELAYED = {
    CLIENT_MAC: "client",
    RELAY_CLIENT_SIDE_MAC: "relay",
    RELAY_SERVER_SIDE_MAC: "relay",
    SERVER_SEGMENT_MAC: "server",
}


class Relayed(_ty.NamedTuple):
    """client -- 10.99.0.0/24 -- relay -- 10.98.0.0/24 -- server.

    The relay holds 10.99.0.1 and 10.98.0.1, the server 10.98.0.2 with its
    default route through the relay. `forger` is a second client segment,
    10.97.0.0/24, when it was asked for.
    """

    cli: str
    rly: str
    srv: str
    forger: _ty.Optional[str]
    relay_client_ip: str
    server_ip: str


def relayed(
    lab: Lab, with_forger: bool = False, client_addr: _ty.Optional[str] = None
) -> Relayed:
    cli, rly, srv = lab.netns("cli"), lab.netns("rly"), lab.netns("srv")
    lab.veth(
        cli,
        "cv0",
        rly,
        "ra0",
        mac1=CLIENT_MAC,
        mac2=RELAY_CLIENT_SIDE_MAC,
        addr2="10.99.0.1/24",
    )
    lab.veth(
        rly,
        "rs0",
        srv,
        "sv0",
        mac1=RELAY_SERVER_SIDE_MAC,
        mac2=SERVER_SEGMENT_MAC,
        addr1="10.98.0.1/24",
        addr2="10.98.0.2/24",
    )
    lab.route(srv, "default", "via", "10.98.0.1")
    forger = None
    if with_forger:
        forger = lab.netns("forger")
        lab.veth(
            forger,
            "fb0",
            rly,
            "rb0",
            mac1="02:00:00:97:00:02",
            mac2="02:00:00:97:00:01",
            addr1="10.97.0.2/24",
            addr2="10.97.0.1/24",
        )
        lab.route(rly, "default", "via", "10.98.0.2")
    return Relayed(cli, rly, srv, forger, "10.99.0.1", "10.98.0.2")


class TwoHomed(_ty.NamedTuple):
    """A server holding two interfaces, the default route on the second.

    segment A, 10.203.0.0/24, is where requests arrive (server `sa`, host `a`);
    segment B, 10.204.0.0/24, holds the default route (server `sb`, host `b`).
    10.205.0.9 is an address on `b` reached through the default route.
    """

    srv: str
    a: str
    b: str


A_SERVER_MAC = "02:00:00:03:00:01"
A_HOST_MAC = "02:00:00:03:00:02"
B_SERVER_MAC = "02:00:00:04:00:01"
B_HOST_MAC = "02:00:00:04:00:02"


def two_homed(lab: Lab) -> TwoHomed:
    srv, a, b = lab.netns("srv"), lab.netns("a"), lab.netns("b")
    lab.veth(
        srv,
        "sa",
        a,
        "a0",
        mac1=A_SERVER_MAC,
        mac2=A_HOST_MAC,
        addr1="10.203.0.1/24",
        addr2="10.203.0.2/24",
    )
    lab.veth(
        srv,
        "sb",
        b,
        "b0",
        mac1=B_SERVER_MAC,
        mac2=B_HOST_MAC,
        addr1="10.204.0.1/24",
        addr2="10.204.0.2/24",
    )
    lab.run(b, [lab.ip, "addr", "add", "10.205.0.9/32", "dev", "lo"])
    lab.route(srv, "default", "via", "10.204.0.2", "dev", "sb")
    lab.route(a, "default", "via", "10.203.0.1", "dev", "a0")
    lab.route(b, "default", "via", "10.204.0.1", "dev", "b0")
    return TwoHomed(srv, a, b)
