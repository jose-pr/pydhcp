#!/usr/bin/env python3
"""Structured benchmark runner for pydhcp.

Drives the per-suite measurement scripts (`bench_parse.py`, `bench_options.py`,
`bench_listener.py`, `bench_server.py`) and emits one comparable JSON result per (version, interpreter):

    python benchmarks/run.py                  # print a summary only
    python benchmarks/run.py --save           # also write benchmarks/results/<name>.json
    python benchmarks/run.py --suite parse    # one suite instead of all
    python benchmarks/run.py --name wip       # custom result-file stem

Each metric is sampled `--repeat` times and reported as min/median/max
**milliseconds per call**. Why not a single `timeit` average: one average hides
run-to-run noise entirely, and on a loaded desktop that noise routinely exceeds
the effect being measured -- min/max make it visible instead of silently
folding it into the number. Compare on `median_ms`.

The result schema is the repo-standard one consumed by
`tools/compare_bench.py` in the shared engineering overlay, so a before/after
pair can be diffed mechanically rather than by eyeballing JSON.
"""

import argparse
import importlib
import json
import pathlib
import platform
import re
import statistics
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, REPO_ROOT.as_posix())

RESULTS_DIR = pathlib.Path(__file__).resolve().parent / "results"

# Per-suite inner-loop counts. They differ on purpose: the options suite
# includes a lease-allocation metric that is ~500x the cost of a packet decode,
# so a shared count would either make it take minutes or make the decode
# timings too short to be meaningful.
# The listener suite sends real datagrams over loopback, which costs far more
# than a decode; the server suite is a whole `handle()` per message.
SUITE_ITERATIONS = {"parse": 10000, "options": 1000, "listener": 1000, "server": 2000}
SUITES = tuple(SUITE_ITERATIONS)
REPEAT = 5


def _project_version() -> str:
    """Version of the tree under test, for the result name.

    The manifest first: an editable install keeps the version metadata it was
    installed with, so after a bump the installed metadata is the older one and
    would label the result with a version this tree is not. The installed
    metadata answers only when there is no manifest to read (a run from an
    installed package).
    """
    manifest = REPO_ROOT / "pyproject.toml"
    if manifest.is_file():
        text = manifest.read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if match:
            return match.group(1)
    try:
        from importlib.metadata import version

        return version("pydhcp")
    except Exception:
        return "unknown"


def _measure_suite(suite: str, iterations: int) -> Dict[str, Dict[str, Any]]:
    """One raw sample of a suite: {metric: {seconds, ops_per_sec, iterations}}.

    Uses the suites' `_measure_benchmarks` rather than their public
    `run_benchmarks` because the latter prints a console summary per call, and
    this runner calls it once per sample.
    """
    module = importlib.import_module(f"benchmarks.bench_{suite}")
    return module._measure_benchmarks(iterations)  # type: ignore[no-any-return]


def sample_suite(
    suite: str, iterations: int, repeat: int
) -> Dict[str, Dict[str, float]]:
    """Sample a suite `repeat` times, reduced to min/median/max ms per call."""
    _measure_suite(suite, iterations)  # warmup: the first run pays import costs

    per_call: Dict[str, List[float]] = {}
    for _ in range(repeat):
        for name, metric in _measure_suite(suite, iterations).items():
            ms = metric["seconds"] / metric["iterations"] * 1000
            # Suite-qualified so one result file can hold every suite without
            # two suites ever colliding on a metric name.
            per_call.setdefault(f"{suite}.{name}", []).append(ms)

    return {
        name: {
            "median_ms": round(statistics.median(samples), 6),
            "min_ms": round(min(samples), 6),
            "max_ms": round(max(samples), 6),
        }
        for name, samples in per_call.items()
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run pydhcp repository benchmarks")
    parser.add_argument(
        "--suite",
        choices=SUITES + ("all",),
        default="all",
        help="Benchmark suite to run (default: all)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        help="Override the per-suite inner iteration count",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=REPEAT,
        help=f"Samples per metric (default: {REPEAT})",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Write the result to benchmarks/results/<name>.json",
    )
    parser.add_argument(
        "--name",
        default=None,
        help="Result-file stem (default: pydhcp-<version>-py<major><minor>)",
    )
    args = parser.parse_args(argv)

    suites = list(SUITES) if args.suite == "all" else [args.suite]
    iterations = {suite: args.iterations or SUITE_ITERATIONS[suite] for suite in suites}

    metrics: Dict[str, Dict[str, float]] = {}
    for suite in suites:
        metrics.update(sample_suite(suite, iterations[suite], args.repeat))

    version = _project_version()
    pyver = f"py{sys.version_info.major}{sys.version_info.minor}"
    name = args.name or f"pydhcp-{version}-{pyver}"
    result = {
        "name": name,
        "pydhcp_version": version,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "iterations": dict(iterations, repeat=args.repeat),
        "metrics": metrics,
    }

    print(f"=== pydhcp benchmarks: {name} ===")
    print(f"{result['python']} on {result['processor']}")
    print(f"{'metric':34s} {'median':>11s} {'min':>11s} {'max':>11s}   (ms/call)")
    for key, metric in metrics.items():
        print(
            f"{key:34s} {metric['median_ms']:11.6f} "
            f"{metric['min_ms']:11.6f} {metric['max_ms']:11.6f}"
        )

    if args.save:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out = RESULTS_DIR / f"{name}.json"
        out.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(f"saved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
