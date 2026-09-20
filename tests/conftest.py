"""Helpers shared by more than one test module.

Deliberately small. A helper only one module uses stays in that module: a
reader should be able to follow a test without opening this file. What lives
here was copy-pasted verbatim across files -- the 14-line BOOTREQUEST skeleton
in sixteen of them, and the bind-wait loop and fixed-lease server stub in three
each -- so a change to any of them had to be made everywhere or not at all.
"""

from __future__ import annotations

import time
import typing as _ty
from datetime import datetime, timedelta

from pydhcp import DhcpLease, DhcpMessage, DhcpOptions, DhcpServer
from pydhcp.network import IPv4
from pydhcp.options import DhcpOptionCode
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode

#: The client hardware address most tests use; only tests that care about
#: telling two clients apart pass their own.
CHADDR = b"\x00\x11\x22\x33\x44\x55"


def build_request(
    message_type: _ty.Optional[DhcpMessageType] = DhcpMessageType.DHCPDISCOVER,
    *,
    options: _ty.Optional[DhcpOptions] = None,
    **fields: _ty.Any,
) -> DhcpMessage:
    """A BOOTREQUEST with every field a test does not care about filled in.

    Any header field can be overridden by keyword (`xid=...`, `chaddr=...`,
    `flags=...`, `sname=...`); everything else takes the neutral value the
    hand-written copies all used.

    `options` is the option bag to carry. Omit it and a fresh bag is built
    holding just `message_type`; supply it and it is used exactly as given and
    `message_type` is ignored. The split matters because option order is
    wire-visible, so a test needing more than the message type builds the bag
    itself rather than having this function append to it.
    """
    if options is None:
        options = DhcpOptions()
        if message_type is not None:
            options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = message_type
    header: dict[str, _ty.Any] = dict(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x12345678,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=CHADDR,
        sname="",
        file="",
    )
    header.update(fields)
    return DhcpMessage(options=options, **header)


def wait_bound(listener: _ty.Any, timeout: float = 2.0) -> None:
    """Block until a started listener reports a bound address.

    `start()` returns before the receive thread has bound, so reading
    `bound_addresses[0].port` straight afterwards races. Polling the public
    property is what replaced reaching into `._sockets`.
    """
    deadline = time.time() + timeout
    while not listener.bound_addresses and time.time() < deadline:
        time.sleep(0.01)


class FixedLeaseServer(DhcpServer):
    """A server that hands every client the same loopback lease.

    No host configuration and no address pool: the tests that use it are
    exercising the socket path, not allocation. `LEASE_SECONDS` is the only
    thing subclasses vary.

    It sets no `DEFAULT_PORTS`: every caller binds `("127.0.0.1", 0)` and reads
    the port back with `wait_bound` + `bound_addresses`, because a fixed test
    port collides under WSAEACCES on Windows.
    """

    LEASE_SECONDS = 60

    def acquire_lease(
        self, client_id: _ty.Any, server_id: _ty.Any, msg: DhcpMessage
    ) -> DhcpLease:
        options = DhcpOptions()
        options[DhcpOptionCode.ROUTER] = IPv4("127.0.0.1")
        return DhcpLease(
            IPv4("127.0.0.1"),
            datetime.now() + timedelta(seconds=self.LEASE_SECONDS),
            options,
        )
