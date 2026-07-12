from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_module():
    script_path = Path(__file__).resolve().parent.parent / "benchmarks" / "bench_options.py"
    spec = importlib.util.spec_from_file_location("bench_options", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_run_benchmarks_returns_named_metrics(monkeypatch) -> None:
    module = _load_module()
    timings = iter([1.0, 2.0, 4.0, 5.0, 10.0])
    monkeypatch.setattr(module.timeit, "timeit", lambda func, number: next(timings))

    results = module.run_benchmarks(iterations=1000)

    assert list(results) == [
        "decode_0_options",
        "decode_5_options",
        "decode_20_options",
        "round_trip_encode_decode",
        "lease_allocations_1000_clients",
    ]
    assert results["decode_0_options"]["iterations"] == 1000
    assert results["decode_0_options"]["ops_per_sec"] == 1000.0
    assert results["lease_allocations_1000_clients"]["iterations"] == 100
    assert results["lease_allocations_1000_clients"]["ops_per_sec"] == 10.0


def test_write_json_report_creates_expected_payload(tmp_path, monkeypatch) -> None:
    module = _load_module()
    timings = iter([1.0, 2.0, 4.0, 5.0, 10.0])
    monkeypatch.setattr(module.timeit, "timeit", lambda func, number: next(timings))
    output_path = tmp_path / "benchmarks" / "bench_options.json"
    results = module._measure_benchmarks(iterations=1)

    module.write_json_report(output_path, 1, results)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["benchmark"] == "bench_options"
    assert payload["iterations"] == 1
    assert payload["metrics"]["decode_0_options"]["iterations"] == 1
