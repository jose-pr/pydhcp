import argparse
import json
import pathlib
import sys
import timeit
from collections import OrderedDict
from datetime import timedelta
from typing import Any

# Ensure src/ is in the import path
SRC_DIR = pathlib.Path(__file__).parent.parent / "src"
sys.path.insert(0, SRC_DIR.as_posix())

from pydhcp.enum import DhcpMessageType
from pydhcp.enum import DhcpOptionCode
from pydhcp.enum import Flags
from pydhcp.enum import HardwareAddressType
from pydhcp.enum import OpCode
from pydhcp.message import DhcpMessage
from pydhcp.netutils import IPv4
from pydhcp.options import DhcpOptions


def build_benchmark_payload() -> bytes:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray([DhcpMessageType.DHCPDISCOVER.value])
    options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray([1, 0, 17, 34, 51, 68, 85])
    options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = bytearray(
        [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
    )

    msg = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x3903F326,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        sname="",
        file="",
        options=options,
    )
    return bytes(msg.encode())


PAYLOAD_BYTES = build_benchmark_payload()


def _measure_benchmarks(iterations: int) -> OrderedDict[str, dict[str, Any]]:
    payload_mv = memoryview(PAYLOAD_BYTES)

    def test_decode() -> None:
        DhcpMessage.decode(payload_mv)

    decode_time = timeit.timeit(test_decode, number=iterations)
    decode_ops_per_sec = iterations / decode_time

    msg = DhcpMessage.decode(payload_mv)

    def test_encode() -> None:
        msg.encode()

    encode_time = timeit.timeit(test_encode, number=iterations)
    encode_ops_per_sec = iterations / encode_time
    return OrderedDict(
        [
            (
                "decode_packet",
                {"seconds": decode_time, "ops_per_sec": decode_ops_per_sec, "iterations": iterations},
            ),
            (
                "encode_packet",
                {"seconds": encode_time, "ops_per_sec": encode_ops_per_sec, "iterations": iterations},
            ),
        ]
    )


def _print_benchmarks(iterations: int, benchmarks: OrderedDict[str, dict[str, Any]]) -> None:
    print(f"--- Running DHCP Packet Parsing Benchmarks ({iterations:,} iterations) ---")
    print(
        f"Decode: {benchmarks['decode_packet']['seconds']:.4f} seconds "
        f"({benchmarks['decode_packet']['ops_per_sec']:.1f} ops/sec)"
    )
    print(
        f"Encode: {benchmarks['encode_packet']['seconds']:.4f} seconds "
        f"({benchmarks['encode_packet']['ops_per_sec']:.1f} ops/sec)"
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
    payload = {
        "benchmark": "bench_parse",
        "python": sys.version.split()[0],
        "iterations": iterations,
        "metrics": benchmarks,
    }
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run DHCP packet parsing benchmark samples.")
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
