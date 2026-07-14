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

from pydhcp.options import DhcpOptionCode
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.network import IPv4
from pydhcp.options import DhcpOptions


def build_options_payload(option_count: int) -> bytearray:
    opts = DhcpOptions()
    for i in range(1, option_count + 1):
        opts[i] = bytearray([192, 168, 1, i])
    return opts.encode()


def test_memory_usage() -> None:
    backend = InMemoryLeaseBackend()
    options = DhcpOptions()
    for i in range(1000):
        client_id = f"client-{i}"
        ip = IPv4("192.168.1.1")
        backend.allocate(client_id, ip, 3600, options)


def _measure_benchmarks(iterations: int) -> OrderedDict[str, dict[str, Any]]:
    p0 = memoryview(build_options_payload(0))
    p5 = memoryview(build_options_payload(5))
    p20 = memoryview(build_options_payload(20))

    t0 = timeit.timeit(lambda: DhcpOptions().decode(p0), number=iterations)
    t5 = timeit.timeit(lambda: DhcpOptions().decode(p5), number=iterations)
    t20 = timeit.timeit(lambda: DhcpOptions().decode(p20), number=iterations)

    opts = DhcpOptions()
    opts[DhcpOptionCode.SUBNET_MASK] = IPv4("255.255.255.0")

    def round_trip() -> None:
        encoded = opts.encode()
        decoded = DhcpOptions()
        decoded.decode(memoryview(encoded))

    trt = timeit.timeit(round_trip, number=iterations)
    t_mem = timeit.timeit(test_memory_usage, number=100)
    return OrderedDict(
        [
            ("decode_0_options", {"seconds": t0, "ops_per_sec": iterations / t0, "iterations": iterations}),
            ("decode_5_options", {"seconds": t5, "ops_per_sec": iterations / t5, "iterations": iterations}),
            ("decode_20_options", {"seconds": t20, "ops_per_sec": iterations / t20, "iterations": iterations}),
            (
                "round_trip_encode_decode",
                {"seconds": trt, "ops_per_sec": iterations / trt, "iterations": iterations},
            ),
            (
                "lease_allocations_1000_clients",
                {"seconds": t_mem, "ops_per_sec": 100 / t_mem, "iterations": 100},
            ),
        ]
    )


def _print_benchmarks(iterations: int, benchmarks: OrderedDict[str, dict[str, Any]]) -> None:
    print(f"--- Running DHCP Options & Memory Benchmarks ({iterations:,} iterations) ---")
    print(
        f"Decode with 0 options:  {benchmarks['decode_0_options']['seconds']:.4f}s "
        f"({benchmarks['decode_0_options']['ops_per_sec']:.1f} ops/sec)"
    )
    print(
        f"Decode with 5 options:  {benchmarks['decode_5_options']['seconds']:.4f}s "
        f"({benchmarks['decode_5_options']['ops_per_sec']:.1f} ops/sec)"
    )
    print(
        f"Decode with 20 options: {benchmarks['decode_20_options']['seconds']:.4f}s "
        f"({benchmarks['decode_20_options']['ops_per_sec']:.1f} ops/sec)"
    )
    print(
        f"Round-trip encode/decode: {benchmarks['round_trip_encode_decode']['seconds']:.4f}s "
        f"({benchmarks['round_trip_encode_decode']['ops_per_sec']:.1f} ops/sec)"
    )
    print(
        "1000 lease allocations (x100 reps): "
        f"{benchmarks['lease_allocations_1000_clients']['seconds']:.4f}s "
        f"({benchmarks['lease_allocations_1000_clients']['ops_per_sec']:.1f} reps/sec)"
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
        "benchmark": "bench_options",
        "python": sys.version.split()[0],
        "iterations": iterations,
        "metrics": benchmarks,
    }
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run DHCP options and lease benchmark samples.")
    parser.add_argument(
        "--iterations",
        type=int,
        default=10000,
        help="Number of decode/round-trip iterations to run.",
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
