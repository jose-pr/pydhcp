# pydhcp — contributor orientation

A DHCPv4 library, server, client, relay and capture tool. This file is for
someone working *on* the repository; it is not the API reference. Each
subpackage ships its own header beside its code:

| Header | Covers |
| --- | --- |
| [`src/pydhcp/AGENTS.md`](src/pydhcp/AGENTS.md) | listener, server, client, relay, capture, leases, metrics, NVT text, constants, CLI |
| [`src/pydhcp/packet/AGENTS.md`](src/pydhcp/packet/AGENTS.md) | the wire message and structured (de)serialization |
| [`src/pydhcp/options/AGENTS.md`](src/pydhcp/options/AGENTS.md) | the options container, code registry and payload codecs |
| [`src/pydhcp/_network/AGENTS.md`](src/pydhcp/_network/AGENTS.md) | the hardware-type enum, interface and socket-address types |

Those headers are meant to be read *instead of* the source, so they are kept
current with the code in the same commit that changes it.

## Layout

```
src/pydhcp/        the package (src layout — an editable install or PYTHONPATH is needed)
  packet/          DHCPMessage, enums, structured formats
  options/         DHCPOptions, DHCPOptionCode (_codes.py), _codecs/ payload codecs
  _network/        hardware-type, interface and socket-address types
  listener/        listeners and transports, one private module per responsibility
  cli/             the `pydhcp` command: App in __init__, one private module per subcommand
tests/             pytest suite, including tests/integration (real sockets on loopback)
examples/          runnable examples; tests/test_examples.py imports each one
benchmarks/        run.py plus per-suite scripts, JSON output for comparison
docs/              mkdocs site (mkdocs.yml at the root)
```

## Environment

Python **3.9** is the floor and is part of the contract — CI runs the suite on
3.9 through 3.14.

```bash
python -m pip install -e ".[dev,docs,toml]"
python -m pytest -q
```

The `toml` extra is not optional for a full run: without `tomli-w` the TOML and
INI cases skip rather than fail, so a run that looks green may not have
exercised them.

## Checks

Everything below runs in CI; run what your change touches.

```bash
python -m pytest -q                      # the suite
python -m mypy src                       # strict, and see the note below
python -m black --check src tests benchmarks examples
python -m mkdocs build --strict          # the docs site
```

**Run the suite and mypy on both Linux and Windows if you touch sockets,
paths, or anything platform-conditional.** This is not boilerplate caution —
every platform-divergent defect this project has had passed on one OS and
failed on the other: a broadcast POSIX refuses from a loopback-bound socket,
the `IP_PKTINFO` receive path, `os.path.splitdrive` being a no-op off Windows,
and asyncio's proactor loop having no `add_reader`. CI covers both, but the
feedback loop is much shorter locally.

mypy in particular must pass on **both**: typeshed marks POSIX-only socket
calls unavailable on Windows, so `sock.recvmsg(...)` is an `attr-defined`
error on one platform while a `# type: ignore` for it is an `unused-ignore`
error on the other. Neither platform alone can tell you the annotation is
right.

## Testing against a real client

Unit tests validate pydhcp against pydhcp. Several delivery defects were only
ever caught by a real DHCP client — a server that answered nothing on Linux, a
relay that forwarded eight requests of which zero arrived, an async listener
that received no broadcasts at all. If you change the receive or reply path,
run `tests/interop`: ISC dhclient against the server and through the relay,
over veth pairs in network namespaces the tests create and remove themselves.

```bash
sudo python -m pytest -q -rs tests/interop
```

It needs Linux, root (`sudo`), `ip netns` and the peer programs (`dhclient`; and
`busybox` for `udhcpc`, `dnsmasq` where a test uses them); every test skips,
with its reason, when one is missing, so a plain `pytest` run on Windows or
without root reports them skipped rather than failing. Nothing the lab does
touches the default namespace, and each test ends by asserting no namespace,
link, process or change to `/etc/resolv.conf` is left behind. The scenarios
state what the RFC requires; one that fails because of a known defect is a
strict `xfail` saying so, so the fix shows up as an unexpected pass.
`PYDHCP_INTEROP_LOGS=<dir>` keeps each test's process output and the frames
seen on each segment.

`decode()` is deliberately liberal: it accepts a 241-octet message, an `htype`
with no IANA name, `hlen = 0` (RFC 4390 requires it for IPoIB) and text that
is not valid UTF-8. `encode()` is strict — it pads to the 300-octet BOOTP
minimum and preserves the octets it was given. Liberal on receive, strict on
send; keep it that way.

## Conventions

- **Keep modules small enough to review in one sitting** — a few hundred
  lines. Split by responsibility into a package rather than letting one file
  grow, and keep the package's `__init__` re-exporting the names callers
  already import, so a split never moves a public import path. One deliberate
  exception: `options/_codes.py` is the `DHCPOptionCode` enum, ~830 lines of
  RFC-documented members, and an `Enum`'s members cannot be split across
  modules. A class too big for one module becomes layers, each subclassing the
  last (see `server/` and `packet/_*.py`).

- **Option codecs** live in `src/pydhcp/options/_codecs/` and are bound to codes
  in `_registry.py`. A codec must match the wire form its RFC defines, and a
  new one wants an RFC wire vector in `tests/test_option_types.py` — several
  codecs were wrong for a long time behind tests that asserted the wrong shape.
- **Names on the wire never get rewritten.** An unknown enum value becomes an
  unnamed pseudo-member rather than being replaced by a default, because a
  relay must forward what it received.
- **Anything an unauthenticated client controls needs a bound** — the lease
  store, the relay's pending map, the number of capture files. And any warning
  on such a path needs a rate limit, or the log becomes the second target.
- Commits are logical and small: behaviour, docs and CI in separate commits.

## Releasing

Version lives in `pyproject.toml`. Pre-1.0, a **MINOR** bump means the
documented API broke — new methods, new optional keyword arguments and fixes
are all PATCH, so a `~=0.x.0` subscriber gets additions without re-reading.
Pushing a `v*` tag publishes; `ci-*` tags only run CI.
