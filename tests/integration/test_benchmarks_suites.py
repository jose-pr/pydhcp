"""The `listener` and `server` benchmark suites run, and measure what they name.

A handful of iterations each: the numbers mean nothing here, but a suite that
sends nothing, or a server that answers no message, must fail instead of
reporting a fast time.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "benchmarks" / f"{name}.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_listener_suite_counts_every_datagram_it_sent() -> None:
    module = _load("bench_listener")

    # private: the benchmark script's helper, called with the timer replaced
    metrics = module._measure_benchmarks(iterations=120)

    assert list(metrics) == ["receive_datagram"]
    assert metrics["receive_datagram"]["iterations"] == 120
    assert metrics["receive_datagram"]["seconds"] > 0


def test_the_server_suite_has_the_server_answer_each_message() -> None:
    module = _load("bench_server")

    # private: the benchmark script's helper, called with the timer replaced
    metrics = module._measure_benchmarks(iterations=5)

    assert list(metrics) == ["handle_discover", "handle_request"]
    assert all(m["iterations"] == 5 and m["seconds"] > 0 for m in metrics.values())


def test_a_listener_suite_that_loses_a_datagram_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load("bench_listener")
    monkeypatch.setattr(module, "WAIT_SECONDS", 0.2)
    monkeypatch.setattr(module, "PAYLOAD_BYTES", b"\x00")  # not a DHCP message

    with pytest.raises(RuntimeError, match="datagrams"):
        # private: the benchmark script's helper, called with the timer replaced
        module._measure_benchmarks(iterations=3)
