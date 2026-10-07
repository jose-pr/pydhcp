# pydhcp benchmarks

Micro-benchmarks for the hot paths: DHCP message encode/decode, option block
encode/decode, in-memory lease allocation, the server's `handle()` and the
listener's receive path. Only the `listener` suite touches a socket (loopback,
one datagram sent at a time in batches): the others measure per-call CPU cost,
not the network behaviour that dominates a real server.

## Running

From the repository root:

```bash
python benchmarks/run.py                  # print a summary only
python benchmarks/run.py --save           # also write benchmarks/results/<name>.json
python benchmarks/run.py --suite parse    # one suite instead of all
python benchmarks/run.py --repeat 9       # more samples per metric
python benchmarks/run.py --name wip       # custom result-file stem
```

`--save` writes `benchmarks/results/pydhcp-<version>-py<major><minor>.json`,
with `<version>` read from `pyproject.toml` of the tree being measured (the
installed metadata of an editable install is the version it was installed at,
not the version of the checkout).
Results are **tracked in git on purpose** so a before/after pair is recoverable
from history rather than from a CI artifact that expires.

`--iterations` overrides the inner loop count for every selected suite. The
defaults differ per suite (`parse` 10 000, `options` 1 000, `listener` 1 000,
`server` 2 000) because the lease-allocation metric costs roughly 500x a packet
decode and a datagram sent over loopback costs far more than either; a shared
count would either run for minutes or leave the decode timings too short to mean
anything.

## Suites and metrics

Metric names are suite-qualified, so one result file can hold every suite.

### `parse` — `bench_parse.py`

A realistic `DHCPDISCOVER` (message type, client identifier, a 14-entry
parameter request list) encoded once at import and reused.

- `parse.decode_packet` — `DHCPMessage.decode` over that payload.
- `parse.encode_packet` — `DHCPMessage.encode` back to bytes (a three-option
  DISCOVER).
- `parse.encode_reply` — `DHCPMessage.encode` of a twelve-option server ACK.

### `options` — `bench_options.py`

The option block on its own, plus the lease backend.

- `options.decode_0_options` — decoding an empty option block; the fixed
  per-call overhead everything else is measured against.
- `options.decode_5_options` / `options.decode_20_options` — the same decode
  with 5 and 20 options, so the per-option cost is separable from the overhead.
- `options.round_trip_encode_decode` — encode then decode a single
  `SUBNET_MASK` option, covering the typed-value path rather than raw bytes.
- `options.lease_allocations_1000_clients` — 1 000 `InMemoryLeaseBackend`
  allocations per call. Reported per call like everything else, so it reads as
  milliseconds per 1 000 allocations, not per allocation.

### `listener` — `bench_listener.py`

A `DHCPListener` on `127.0.0.1` port 0 whose handler only counts, fed a recorded
DISCOVER from a UDP socket in batches of 50.

- `listener.receive_datagram` — from sending a batch until the handler has seen
  every datagram of it, per datagram: the socket receive, the decode and the
  dispatch, none of the server's own work. The suite fails if a datagram is
  lost instead of reporting a fast time.

### `server` — `bench_server.py`

`DHCPServer.handle()` with a policy that grants one fixed lease and a transport
that records what it is asked to send, so no socket and no lease store are in
the measurement. The suite fails if the server does not answer a message.

- `server.handle_discover` — one DISCOVER: input checks, lease decision, the
  OFFER built and encoded, and handed to the transport.
- `server.handle_request` — the same for a REQUEST naming this server, answered
  with an ACK.

## Result schema

Each `benchmarks/results/<name>.json` is a single JSON object:

| Key | Meaning |
| --- | --- |
| `name` | Result stem; matches the filename. |
| `pydhcp_version` | Version of the package measured. |
| `python` | Interpreter version, e.g. `3.14.6`. |
| `platform` / `processor` | Host identity. **Numbers are only comparable when both match.** |
| `timestamp` | UTC, seconds resolution. |
| `iterations` | Inner loop count per suite, plus `repeat` (samples per metric). |
| `metrics` | `{name: {min_ms, median_ms, max_ms}}`, **milliseconds per call**. |

Each metric is sampled `repeat` times and reduced to min/median/max rather than
reported as one `timeit` average. An average hides run-to-run noise completely;
min/max make it visible, which matters because on a desktop that noise is
routinely larger than the change being investigated. **Compare on `median_ms`.**

## Comparing two runs

The shared engineering overlay ships a comparator that consumes this schema
directly, so nobody has to eyeball two JSON blobs:

```bash
python "$ENGINEERING_OVERLAY_ROOT/tools/compare_bench.py" \
  benchmarks/results/before.json benchmarks/results/after.json
```

It diffs on `median_ms`, warns when `python` or `processor` differ, and exits
non-zero if any metric regressed past `--threshold` (default 10%).

## Local numbers are not a performance claim

There is deliberately **no baseline table in this file.** The table that used to
live here came from a single local run on one developer machine, and a single
run cannot support the claim a table implies.

Measured while writing this: two back-to-back `run.py --save` invocations on the
same commit, same machine, same interpreter differed by **10.1%** on
`options.lease_allocations_1000_clients` and 8.6% on
`options.round_trip_encode_decode` — larger than the regression threshold, with
no code change at all.

So:

- Use local runs as a **sanity check** — is this microseconds or milliseconds?
- Any number quoted in a release, changelog, or issue comes from a **CI run**
  (`workflow_dispatch` with `run_benchmarks`, or a `ci-bench-*` tag), which
  uploads `benchmarks/results/*.json` as an artifact. Commit that file as the
  baseline; the committed results, not this README, are the record.
- Never compare across machines or interpreter versions. The `processor` and
  `python` fields exist so a comparison can be refused rather than misread.

## Raw single-sample reports

`bench_parse.py` and `bench_options.py` are also runnable directly and take
`--json-output <path>`, which writes an unsampled `{seconds, ops_per_sec,
iterations}` report for one run. That is a debugging aid for a single
measurement — it carries no median and is **not** what `compare_bench.py`
reads. Use `run.py --save` for anything that will be compared.

## Where each result file comes from

`results/` is tracked, and a file in it says where it came from:

- `pydhcp-0.5.2-py314.json` — **a local run**, on one developer machine
  (Windows on ARM64, CPython 3.14), labelled by the installed metadata of an
  editable install made at 0.5.2, from a tree well past that tag. It predates
  the `listener` and `server` suites and the rule above that labels a result by
  the tree measured, so it is not a measurement of 0.5.2. It stays until CI
  results for the releases exist, and is then replaced by them.
- A file written by the `benchmark` job of `test.yml` (`workflow_dispatch` with
  `run_benchmarks`, or a `ci-bench-*` tag) is a CI result: the job uploads
  `benchmarks/results/*.json` as an artifact, and the artifact is what is
  committed here, unedited. Its `python`, `platform` and `processor` fields name
  the runner it was measured on.

A local run measures the machine it ran on: two back-to-back runs of the same
commit on the same developer machine came out **10.1%** apart, which is why a
number quoted anywhere comes from a CI result and not from a local run.
