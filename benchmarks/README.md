# DHCP Library Performance Benchmarks

This directory contains the benchmarks for measuring the serialization and deserialization performance of the `pydhcp` library.

## Benchmarks

### Structured output

`benchmarks/bench_options.py` and `benchmarks/bench_parse.py` support an optional
`--json-output <path>` flag so local runs and opt-in CI runs can archive comparable results
without changing the default human-readable console output.

### 1. Packet Parsing & Serialization (`benchmarks/bench_parse.py`)
Measures the operations per second (ops/sec) and total duration for 10,000 iterations of:
- **Decode**: Deserializing a typical `DHCPDISCOVER` packet payload into a `DhcpMessage` object.
- **Encode**: Serializing a constructed `DhcpMessage` object back into raw bytes.

#### Running the Benchmark
From the repository root directory, run:
```bash
python benchmarks/bench_parse.py
```

To capture structured parse-benchmark results:
```bash
python benchmarks/bench_parse.py --iterations 10000 --json-output benchmark-results/bench_parse.json
```

To capture structured option-benchmark results:
```bash
python benchmarks/bench_options.py --iterations 1000 --json-output benchmark-results/bench_options.json
```

## Performance Baseline

The baseline measurements taken on a Windows development machine (Python 3.12) are as follows:

| Operation | Total Time (10k iterations) | Throughput (ops/sec) |
|---|---|---|
| **Decode** (Deserialization) | ~0.11s | ~92,600 ops/sec |
| **Encode** (Serialization) | ~0.08s | ~120,800 ops/sec |
