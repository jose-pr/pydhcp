"""Request-handling measurement primitives for the `server` suite.

`DHCPServer.handle()` on a DISCOVER and then a REQUEST of one client, with a
policy that grants one fixed lease and a transport that only records what would
have been sent: no socket, so what is measured is the server's own work -- input
checks, lease decision, reply construction and encode -- per message.

Each function here takes ONE sample per metric. Sampling, median/min/max
reduction and the comparable result file belong to the runner -- see
`benchmarks/run.py --save`.
"""

import argparse
import datetime
import ipaddress
import json
import pathlib
import sys
import timeit
from collections import OrderedDict
from typing import Any

SRC_DIR = pathlib.Path(__file__).parent.parent / "src"
sys.path.insert(0, SRC_DIR.as_posix())

from pydhcp import DHCPLease, DHCPMessage, DHCPOptions, DHCPServer, NetworkInterface
from pydhcp import SocketAddress
from pydhcp.listener import DHCPRequestContext
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType, DHCPOpcode

CLIENT_MAC = b"\x00\x11\x22\x33\x44\x55"
LEASE_ADDRESS = ipaddress.IPv4Address("127.0.0.1")


class _Recording:
    """A transport that counts what the server sends."""

    sent = 0

    def send(self, data: Any, dst: Any, *, port: int, client_mac: bytes) -> int:
        self.sent += 1
        return len(data)


class _FixedLeaseServer(DHCPServer):
    """Grants every client the same lease, so no store is measured."""

    def acquire_lease(
        self, client_id: Any, server_id: Any, msg: DHCPMessage, *, commit: bool = True
    ) -> DHCPLease:
        options = DHCPOptions()
        options[DHCPOptionCode.ROUTER] = LEASE_ADDRESS
        options[DHCPOptionCode.DNS] = [LEASE_ADDRESS]
        return DHCPLease(
            LEASE_ADDRESS,
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=3600),
            options,
        )


def build_request(message_type: DHCPMessageType) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = bytearray([message_type.value])
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray([1, 0, 17, 34, 51, 68, 85])
    options[DHCPOptionCode.PARAMETER_REQUEST_LIST] = bytearray(
        [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
    )
    if message_type is DHCPMessageType.DHCPREQUEST:
        options[DHCPOptionCode.REQUESTED_IP] = LEASE_ADDRESS
        options[DHCPOptionCode.SERVER_IDENTIFIER] = LEASE_ADDRESS
    return DHCPMessage(
        DHCPOpcode.BOOTREQUEST,
        xid=0x3903F326,
        chaddr=CLIENT_MAC,
        options=options,
    )


def _measure_benchmarks(iterations: int) -> "OrderedDict[str, dict[str, Any]]":
    server = _FixedLeaseServer(listen=("127.0.0.1", 0))
    transport = _Recording()
    context = DHCPRequestContext(
        transport=transport,  # type: ignore[arg-type]
        interface=NetworkInterface("lo", ipaddress.IPv4Interface("127.0.0.1/8")),
        client=SocketAddress("127.0.0.1", 68),
        client_mac=CLIENT_MAC,
        local_ip=LEASE_ADDRESS,
    )
    discover = build_request(DHCPMessageType.DHCPDISCOVER)
    request = build_request(DHCPMessageType.DHCPREQUEST)

    def handle_discover() -> None:
        server.handle(discover, context)

    def handle_request() -> None:
        server.handle(request, context)

    try:
        handle_discover()
        handle_request()
        if transport.sent != 2:
            raise RuntimeError(f"the server answered {transport.sent} of 2 messages")
        discover_time = timeit.timeit(handle_discover, number=iterations)
        request_time = timeit.timeit(handle_request, number=iterations)
    finally:
        server.close()
    return OrderedDict(
        [
            (
                "handle_discover",
                {
                    "seconds": discover_time,
                    "ops_per_sec": iterations / discover_time,
                    "iterations": iterations,
                },
            ),
            (
                "handle_request",
                {
                    "seconds": request_time,
                    "ops_per_sec": iterations / request_time,
                    "iterations": iterations,
                },
            ),
        ]
    )


def run_benchmarks(iterations: int = 2000) -> "OrderedDict[str, dict[str, Any]]":
    benchmarks = _measure_benchmarks(iterations)
    print(f"--- Running DHCP Server Benchmarks ({iterations:,} iterations) ---")
    for name, metric in benchmarks.items():
        print(
            f"{name}: {metric['seconds']:.4f} seconds "
            f"({metric['ops_per_sec']:.1f} ops/sec)"
        )
    return benchmarks


def write_json_report(
    json_output: pathlib.Path,
    iterations: int,
    benchmarks: "OrderedDict[str, dict[str, Any]]",
) -> None:
    """Write the raw single-sample report for one run (a debugging aid)."""
    payload = {
        "benchmark": "bench_server",
        "python": sys.version.split()[0],
        "iterations": iterations,
        "metrics": benchmarks,
    }
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run DHCP server benchmark samples.")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--json-output", type=pathlib.Path)
    args = parser.parse_args()
    benchmarks = run_benchmarks(iterations=args.iterations)
    if args.json_output is not None:
        write_json_report(args.json_output, args.iterations, benchmarks)


if __name__ == "__main__":
    main()
