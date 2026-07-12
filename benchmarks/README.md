# DHCP Library Performance Benchmarks

This directory contains the benchmarks for measuring the serialization and deserialization performance of the `pydhcp` library.

## Benchmarks

### 1. Packet Parsing & Serialization (`benchmarks/bench_parse.py`)
Measures the operations per second (ops/sec) and total duration for 10,000 iterations of:
- **Decode**: Deserializing a typical `DHCPDISCOVER` packet payload into a `DhcpMessage` object.
- **Encode**: Serializing a constructed `DhcpMessage` object back into raw bytes.

#### Running the Benchmark
From the repository root directory, run:
```bash
python benchmarks/bench_parse.py
```

## Performance Baseline

The baseline measurements taken on a Windows development machine (Python 3.12) are as follows:

| Operation | Total Time (10k iterations) | Throughput (ops/sec) |
|---|---|---|
| **Decode** (Deserialization) | ~0.11s | ~92,600 ops/sec |
| **Encode** (Serialization) | ~0.08s | ~120,800 ops/sec |
