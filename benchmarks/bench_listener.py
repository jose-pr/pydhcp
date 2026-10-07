"""Receive-path measurement primitives for the `listener` suite.

A `DHCPListener` on loopback port 0 with a handler that only counts, fed real
datagrams from a UDP socket: the time from sending a batch until the handler has
seen every datagram, per datagram. It covers the socket receive, the decode and
the dispatch, and none of the server's own work (see the `server` suite).

Each function here takes ONE sample per metric. Sampling, median/min/max
reduction and the comparable result file belong to the runner -- see
`benchmarks/run.py --save`.
"""

import argparse
import json
import pathlib
import socket
import sys
import threading
import time
from collections import OrderedDict
from typing import Any

SRC_DIR = pathlib.Path(__file__).parent.parent / "src"
sys.path.insert(0, SRC_DIR.as_posix())

from pydhcp.listener import DHCPListener
from pydhcp.options import DHCPOptionCode, DHCPOptions
from pydhcp.packet import DHCPMessage, DHCPMessageType, DHCPOpcode

#: Datagrams sent before the sender waits for the handler: below what the socket
#: buffer holds, so a sample measures the receive path and not a dropped packet.
BATCH = 50
WAIT_SECONDS = 30.0


def build_discover() -> bytes:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DHCPMessageType.DHCPDISCOVER.value]
    )
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray([1, 0, 17, 34, 51, 68, 85])
    options[DHCPOptionCode.PARAMETER_REQUEST_LIST] = bytearray(
        [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
    )
    message = DHCPMessage(
        DHCPOpcode.BOOTREQUEST,
        xid=0x3903F326,
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        options=options,
    )
    return bytes(message.encode())


PAYLOAD_BYTES = build_discover()


class _Counting(DHCPListener):
    """A listener whose handler does nothing but count."""

    def __init__(self) -> None:
        super().__init__(listen=("127.0.0.1", 0))
        self.seen = 0
        self.target = 0
        self.reached = threading.Event()

    def handle(self, msg: DHCPMessage, context: Any) -> None:
        self.seen += 1
        if self.seen >= self.target:
            self.reached.set()


def _measure_benchmarks(iterations: int) -> "OrderedDict[str, dict[str, Any]]":
    listener = _Counting()
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        listener.start()
        port = listener.bound_addresses[0].port
        destination = ("127.0.0.1", port)
        elapsed = 0.0
        sent = 0
        while sent < iterations:
            batch = min(BATCH, iterations - sent)
            listener.reached.clear()
            listener.target = listener.seen + batch
            began = time.perf_counter()
            for _ in range(batch):
                sender.sendto(PAYLOAD_BYTES, destination)
            if not listener.reached.wait(WAIT_SECONDS):
                raise RuntimeError(
                    f"the listener saw {listener.seen} of {listener.target} datagrams"
                )
            elapsed += time.perf_counter() - began
            sent += batch
    finally:
        sender.close()
        listener.close()
    return OrderedDict(
        [
            (
                "receive_datagram",
                {
                    "seconds": elapsed,
                    "ops_per_sec": iterations / elapsed,
                    "iterations": iterations,
                },
            )
        ]
    )


def run_benchmarks(iterations: int = 1000) -> "OrderedDict[str, dict[str, Any]]":
    benchmarks = _measure_benchmarks(iterations)
    print(f"--- Running DHCP Listener Benchmarks ({iterations:,} datagrams) ---")
    metric = benchmarks["receive_datagram"]
    print(
        f"Receive: {metric['seconds']:.4f} seconds ({metric['ops_per_sec']:.1f} ops/sec)"
    )
    return benchmarks


def write_json_report(
    json_output: pathlib.Path,
    iterations: int,
    benchmarks: "OrderedDict[str, dict[str, Any]]",
) -> None:
    """Write the raw single-sample report for one run (a debugging aid)."""
    payload = {
        "benchmark": "bench_listener",
        "python": sys.version.split()[0],
        "iterations": iterations,
        "metrics": benchmarks,
    }
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run DHCP listener benchmark samples.")
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--json-output", type=pathlib.Path)
    args = parser.parse_args()
    benchmarks = run_benchmarks(iterations=args.iterations)
    if args.json_output is not None:
        write_json_report(args.json_output, args.iterations, benchmarks)


if __name__ == "__main__":
    main()
