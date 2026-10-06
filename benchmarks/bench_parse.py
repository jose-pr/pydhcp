"""Packet encode/decode measurement primitives for the `parse` suite.

Each function here takes ONE `timeit` sample per metric. Sampling,
median/min/max reduction and the comparable result file belong to the
runner -- see `benchmarks/run.py --save`.
"""

import argparse
import json
import pathlib
import sys
import timeit
from collections import OrderedDict
from typing import Any

# Ensure src/ is in the import path
SRC_DIR = pathlib.Path(__file__).parent.parent / "src"
sys.path.insert(0, SRC_DIR.as_posix())

from pydhcp.packet import DHCPMessageType
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPOpcode
from pydhcp.packet import DHCPMessage
from pydhcp.options import DHCPOptions


def build_benchmark_payload() -> bytes:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DHCPMessageType.DHCPDISCOVER.value]
    )
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray([1, 0, 17, 34, 51, 68, 85])
    options[DHCPOptionCode.PARAMETER_REQUEST_LIST] = bytearray(
        [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
    )

    msg = DHCPMessage(
        DHCPOpcode.BOOTREQUEST,
        xid=0x3903F326,
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        options=options,
    )
    return bytes(msg.encode())


PAYLOAD_BYTES = build_benchmark_payload()


def build_reply() -> DHCPMessage:
    """A server's ACK: the twelve options a stock reply carries."""
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DHCPMessageType.DHCPACK.value]
    )
    options[DHCPOptionCode.SERVER_IDENTIFIER] = bytearray([10, 0, 0, 1])
    options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = bytearray([0, 1, 81, 128])
    options[DHCPOptionCode.SUBNET_MASK] = bytearray([255, 255, 255, 0])
    options[DHCPOptionCode.ROUTER] = bytearray([10, 0, 0, 1])
    options[DHCPOptionCode.DNS] = bytearray([10, 0, 0, 2, 10, 0, 0, 3])
    options[DHCPOptionCode.DOMAIN_NAME] = bytearray(b"example.com")
    options[DHCPOptionCode.BROADCAST_ADDRESS] = bytearray([10, 0, 0, 255])
    options[DHCPOptionCode.RENEWAL_TIME] = bytearray([0, 0, 168, 192])
    options[DHCPOptionCode.REBINDING_TIME] = bytearray([0, 1, 38, 80])
    options[DHCPOptionCode.NTP_SERVERS] = bytearray([10, 0, 0, 4])
    options[DHCPOptionCode.HOSTNAME] = bytearray(b"client-host")
    return DHCPMessage(
        DHCPOpcode.BOOTREPLY,
        xid=0x3903F326,
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        options=options,
    )


def _measure_benchmarks(iterations: int) -> OrderedDict[str, dict[str, Any]]:
    payload_mv = memoryview(PAYLOAD_BYTES)

    def test_decode() -> None:
        DHCPMessage.decode(payload_mv)

    decode_time = timeit.timeit(test_decode, number=iterations)
    decode_ops_per_sec = iterations / decode_time

    msg = DHCPMessage.decode(payload_mv)

    def test_encode() -> None:
        msg.encode()

    encode_time = timeit.timeit(test_encode, number=iterations)
    encode_ops_per_sec = iterations / encode_time

    reply = build_reply()

    def test_encode_reply() -> None:
        reply.encode()

    reply_time = timeit.timeit(test_encode_reply, number=iterations)
    reply_ops_per_sec = iterations / reply_time
    return OrderedDict(
        [
            (
                "decode_packet",
                {
                    "seconds": decode_time,
                    "ops_per_sec": decode_ops_per_sec,
                    "iterations": iterations,
                },
            ),
            (
                "encode_packet",
                {
                    "seconds": encode_time,
                    "ops_per_sec": encode_ops_per_sec,
                    "iterations": iterations,
                },
            ),
            (
                "encode_reply",
                {
                    "seconds": reply_time,
                    "ops_per_sec": reply_ops_per_sec,
                    "iterations": iterations,
                },
            ),
        ]
    )


def _print_benchmarks(
    iterations: int, benchmarks: OrderedDict[str, dict[str, Any]]
) -> None:
    print(f"--- Running DHCP Packet Parsing Benchmarks ({iterations:,} iterations) ---")
    print(
        f"Decode: {benchmarks['decode_packet']['seconds']:.4f} seconds "
        f"({benchmarks['decode_packet']['ops_per_sec']:.1f} ops/sec)"
    )
    print(
        f"Encode: {benchmarks['encode_packet']['seconds']:.4f} seconds "
        f"({benchmarks['encode_packet']['ops_per_sec']:.1f} ops/sec)"
    )
    print(
        f"Encode reply: {benchmarks['encode_reply']['seconds']:.4f} seconds "
        f"({benchmarks['encode_reply']['ops_per_sec']:.1f} ops/sec)"
    )


def run_benchmarks(iterations: int = 10000) -> OrderedDict[str, dict[str, Any]]:
    benchmarks = _measure_benchmarks(iterations)
    _print_benchmarks(iterations, benchmarks)
    return benchmarks


def write_json_report(
    json_output: pathlib.Path,
    iterations: int,
    benchmarks: OrderedDict[str, dict[str, Any]],
) -> None:
    """Write the raw single-sample report for one run.

    Debugging aid only: it carries no median, so `compare_bench.py` cannot
    read it. `run.py --save` writes the comparable result.
    """
    payload = {
        "benchmark": "bench_parse",
        "python": sys.version.split()[0],
        "iterations": iterations,
        "metrics": benchmarks,
    }
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run DHCP packet parsing benchmark samples."
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10000,
        help="Number of decode/encode iterations to run.",
    )
    parser.add_argument(
        "--json-output",
        type=pathlib.Path,
        help="Optional path to write structured benchmark results as JSON.",
    )
    args = parser.parse_args()
    benchmarks = run_benchmarks(iterations=args.iterations)
    if args.json_output is not None:
        write_json_report(args.json_output, args.iterations, benchmarks)


if __name__ == "__main__":
    main()
