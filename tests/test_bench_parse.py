from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_module():
    script_path = Path(__file__).resolve().parent.parent / "benchmarks" / "bench_parse.py"
    spec = importlib.util.spec_from_file_location("bench_parse", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_run_benchmarks_returns_named_metrics(monkeypatch) -> None:
    module = _load_module()
    timings = iter([2.0, 4.0])
    monkeypatch.setattr(module.timeit, "timeit", lambda func, number: next(timings))

    results = module.run_benchmarks(iterations=1000)

    assert list(results) == ["decode_packet", "encode_packet"]
    assert results["decode_packet"]["iterations"] == 1000
    assert results["decode_packet"]["ops_per_sec"] == 500.0
    assert results["encode_packet"]["ops_per_sec"] == 250.0


def test_write_json_report_creates_expected_payload(tmp_path, monkeypatch) -> None:
    module = _load_module()
    timings = iter([2.0, 4.0])
    monkeypatch.setattr(module.timeit, "timeit", lambda func, number: next(timings))
    output_path = tmp_path / "benchmarks" / "bench_parse.json"
    results = module._measure_benchmarks(iterations=1)

    module.write_json_report(output_path, 1, results)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["benchmark"] == "bench_parse"
    assert payload["iterations"] == 1
    assert payload["metrics"]["decode_packet"]["iterations"] == 1
