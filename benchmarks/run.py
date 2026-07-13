import argparse
import pathlib
import sys
from collections import OrderedDict
from typing import Any, Callable

REPO_ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, REPO_ROOT.as_posix())

BenchmarkResults = OrderedDict[str, dict[str, Any]]
JsonWriter = Callable[[pathlib.Path, int, BenchmarkResults], None]


def _run_suite(suite: str, iterations: int) -> tuple[BenchmarkResults, JsonWriter]:
    if suite == "options":
        from benchmarks.bench_options import run_benchmarks, write_json_report
    else:
        from benchmarks.bench_parse import run_benchmarks, write_json_report

    return run_benchmarks(iterations=iterations), write_json_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run pydhcp repository benchmarks")
    parser.add_argument(
        "--suite",
        choices=["parse", "options"],
        default="parse",
        help="Benchmark suite to run",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10000,
        help="Benchmark iteration count",
    )
    parser.add_argument(
        "--json-output",
        type=pathlib.Path,
        help="Optional path to write structured benchmark results as JSON",
    )
    args = parser.parse_args()

    benchmarks, write_json_report = _run_suite(args.suite, args.iterations)
    if args.json_output:
        write_json_report(args.json_output, args.iterations, benchmarks)


if __name__ == "__main__":
    main()
