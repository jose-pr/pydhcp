"""A pool server over the documented `acquire_lease` extension point.

Run: python pool_server.py [--async] [--relay-network CIDR] [--gate-chaddr HEX
         --gate-file PATH --ready-file PATH] [--status PATH] [--lease-seconds N]

Listens on the wildcard at port 67 -- the path a real deployment uses. A stock
`DHCPServer` allocates nothing for a client that asks for no address, so the
pool is the override the documentation describes: the next free host from .100
of the network the request belongs to (the relay's network when `giaddr` is
set), on the subnet of the interface that holds the server identifier.

A request from `--gate-chaddr` is held inside `acquire_lease` until
`--gate-file` exists, and `--ready-file` is created on entry, so a test can act
while the server has a request in hand.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import pathlib
import signal
import threading
import time

import datetime

from pydhcp import AsyncDHCPServer, DHCPLease, DHCPServer
from ipaddress import IPv4Address as IPv4
from pydhcp import NetworkInterface

# the host-interface enumeration is not public
from pydhcp._network import host_ip_interfaces
from pydhcp.options import DHCPOptionCode, DHCPOptions

parser = argparse.ArgumentParser()
parser.add_argument("--async", dest="use_async", action="store_true")
parser.add_argument("--relay-network")
parser.add_argument("--gate-chaddr")
parser.add_argument("--gate-file")
parser.add_argument("--ready-file")
parser.add_argument("--status")
parser.add_argument("--lease-seconds", type=int, default=600)
parser.add_argument(
    "--private-store",
    action="store_true",
    help="keep leases in the server's own dict, not in the lease backend",
)
args = parser.parse_args()

relay_network = (
    ipaddress.IPv4Network(args.relay_network) if args.relay_network else None
)


class Pool:
    def _options(self, network, router):
        options = DHCPOptions()
        options[DHCPOptionCode.SUBNET_MASK] = network.netmask
        options[DHCPOptionCode.BROADCAST_ADDRESS] = network.broadcast_address
        options[DHCPOptionCode.ROUTER] = [router]
        options[DHCPOptionCode.DNS] = [router]
        options[DHCPOptionCode.DOMAIN_NAME] = "lab.test"
        options[DHCPOptionCode.INTERFACE_MTU] = 1400
        return options

    def _private_lease(self, client_id, network, interface, router, commit):
        """The server's own store: nothing is written to `lease_backend`."""
        store = self.__dict__.setdefault("_store", {})
        lease = store.get(client_id)
        if lease is None:
            taken = {held.ip for held in store.values()}
            for host in range(100, 150):
                candidate = IPv4(str(network.network_address + host))
                if candidate in taken:
                    continue
                if self._address_refusal(candidate, interface, client_id) is not None:
                    continue
                expires = datetime.datetime.now() + datetime.timedelta(
                    seconds=args.lease_seconds
                )
                lease = DHCPLease(candidate, expires, self._options(network, router))
                store[client_id] = lease
                break
        return lease

    def acquire_lease(self, client_id, server_id, msg, *, commit=True):
        if msg.giaddr != IPv4("0.0.0.0"):
            if relay_network is None:
                return None
            interface = NetworkInterface(
                "relayed",
                ipaddress.IPv4Interface(f"{msg.giaddr}/{relay_network.prefixlen}"),
            )
            network = relay_network
            router = IPv4(str(msg.giaddr))
        else:
            interface = next(
                iter(host_ip_interfaces(lambda i: i.ip == server_id, cache=True)), None
            )
            if interface is None:
                return None
            network = interface.network
            router = IPv4(str(server_id))

        gate_chaddr = bytes.fromhex(args.gate_chaddr) if args.gate_chaddr else None
        if gate_chaddr is not None and bytes(msg.chaddr[:6]) == gate_chaddr:
            if args.ready_file:
                pathlib.Path(args.ready_file).touch()
            end = time.monotonic() + 20
            while not pathlib.Path(args.gate_file).exists() and time.monotonic() < end:
                time.sleep(0.05)

        if args.private_store:
            return self._private_lease(client_id, network, interface, router, commit)

        existing = self.lease_backend.lookup(client_id)
        if existing is not None:
            if commit:
                return (
                    self.lease_backend.renew(client_id, args.lease_seconds) or existing
                )
            return existing

        for host in range(100, 150):
            candidate = IPv4(str(network.network_address + host))
            if self._address_refusal(candidate, interface, client_id) is not None:
                continue
            options = DHCPOptions()
            options[DHCPOptionCode.SUBNET_MASK] = network.netmask
            options[DHCPOptionCode.BROADCAST_ADDRESS] = network.broadcast_address
            options[DHCPOptionCode.ROUTER] = [router]
            options[DHCPOptionCode.DNS] = [router]
            options[DHCPOptionCode.DOMAIN_NAME] = "lab.test"
            options[DHCPOptionCode.INTERFACE_MTU] = 1400
            return self.lease_backend.allocate(
                client_id, candidate, args.lease_seconds, options
            )
        return None


class SyncPool(Pool, DHCPServer):
    pass


class AsyncPool(Pool, AsyncDHCPServer):
    pass


def report(server) -> None:
    if args.status:
        pathlib.Path(args.status).write_text(
            json.dumps(server.metrics.snapshot()), encoding="utf-8"
        )


def run_sync() -> None:
    server = SyncPool(listen=("*", 67))
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    server.start()
    print("serving", flush=True)
    done.wait()
    server.close()
    report(server)


async def run_async() -> None:
    server = AsyncPool(listen=("*", 67))
    loop = asyncio.get_running_loop()
    done = asyncio.Event()
    loop.add_signal_handler(signal.SIGTERM, done.set)
    await server.start()
    print("serving", flush=True)
    await done.wait()
    await server.aclose()
    report(server)


if args.use_async:
    asyncio.run(run_async())
else:
    run_sync()
