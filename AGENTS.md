# pydhcp — contributor orientation

A DHCPv4 library, server, client, relay and capture tool. This file is for
someone working *on* the repository; it is not the API reference. Each header
below describes its own directory and points to the ones nested in it.

| Header | Covers |
| --- | --- |
| [`src/pydhcp/AGENTS.md`](src/pydhcp/AGENTS.md) | the shipped API header: the root exports, the exceptions, the environment variables, and the table of the package headers beside the code (listener, server, client, relay, capture, packet, options, cli) |
| [`tests/AGENTS.md`](tests/AGENTS.md) | running the suite, the skips each platform expects, the layout, the network guard, the loopback rules, the real-peer tests |

Those headers are meant to be read *instead of* the source, so a change to the
public API updates its header in the same commit; `tests/test_shipped_headers.py`
fails when a name, a signature or a table row drifts.

## Layout

```
src/pydhcp/        the package (src layout: an editable install or PYTHONPATH is needed)
  packet/          DHCPMessage, enums, structured formats
  options/         DHCPOptions, DHCPOptionCode (_codes.py), _codecs/ payload codecs
  _network/        hardware-type, interface and socket-address types (private)
  listener/        listeners and transports, one private module per responsibility
  server/ client/ relay/ capture/   each role: _core.py under _sync.py and _asyncio.py drivers
  cli/             the `pydhcp` command: App in __init__, one private module per subcommand
tests/             pytest suite (tests/AGENTS.md)
examples/          runnable examples; tests/test_examples.py imports each one
benchmarks/        run.py plus per-suite scripts, JSON output for comparison
docs/              mkdocs site (mkdocs.yml at the root); `python docs/options_table.py --write`
                   regenerates the options table of options.md after a registry change
```

## Environment

Python **3.9** is the floor and is part of the contract; CI runs the suite on
3.9 through 3.14.

```bash
python -m pip install -e ".[dev,docs]"
python -m pytest -q
```

`dev` includes the `cli`, `yaml` and `toml` extras, so a development install
runs every test that depends on one.

## Checks

Everything below runs in CI; run what your change touches.

```bash
python -m pytest -q                      # the suite
python -m mypy src                       # strict, and see the note below
python -m black --check src tests benchmarks examples
python -m mkdocs build --strict          # the docs site
```

**Run the suite and mypy on both Linux and Windows if you touch sockets,
paths, or anything platform-conditional.** Every platform-divergent defect
this project has had passed on one OS and failed on the other: a broadcast
POSIX refuses from a loopback-bound socket, the `IP_PKTINFO` receive path,
`os.path.splitdrive` being a no-op off Windows, and asyncio's proactor loop
having no `add_reader`. mypy must pass on **both**: typeshed marks POSIX-only
socket calls unavailable on Windows, so `sock.recvmsg(...)` is an
`attr-defined` error on one platform while a `# type: ignore` for it is an
`unused-ignore` error on the other. A change to the receive or reply path also
runs the real-peer tests (`tests/AGENTS.md`).

## Conventions

- **Liberal on receive, strict on send.** `decode()` accepts what real senders
  emit; `encode()` is strict. The contract is in the packet header.
- **Keep modules small enough to review in one sitting** — a few hundred
  lines. Split by responsibility into a package rather than letting one file
  grow, and keep the package's `__init__` re-exporting the names callers
  already import, so a split never moves a public import path. One deliberate
  exception: `options/_codes.py` is the `DHCPOptionCode` enum, one
  RFC-documented member per IANA code (the one module over the limit), and an
  `Enum`'s members cannot be split across modules. A class too big for one
  module becomes layers, each subclassing the last (see `server/` and
  `packet/_*.py`). `tests/test_import_structure.py` pins this: the list of
  public modules (every other module is underscored), the 500-line limit with
  each module over it named and explained, and that no module imports a name
  through a re-exporting `__init__`.
- **Option codecs** live in `src/pydhcp/options/_codecs/` and are bound to codes
  in `_registry.py`. A codec must match the wire form its RFC defines, and a
  new one wants an RFC wire vector in `tests/conformance/rfc_vectors.py`.
- **Names on the wire never get rewritten.** An unknown enum value becomes an
  unnamed pseudo-member rather than being replaced by a default, because a
  relay must forward what it received.
- **Anything an unauthenticated client controls needs a bound** — the lease
  store, the relay's pending map, the number of capture files. And any warning
  on such a path needs a rate limit, or the log becomes the second target.
- **The command line is `duho`'s, and only `cli/` imports it**; `cli.main()`
  imports it inside the function. No command module is over 200 lines
  (`tests/test_cli_contract.py`); a test patches a name where the command module
  looks it up (`pydhcp.cli._server.DHCPServer`). Every subcommand derives from
  an internal `_Command` base that sets `_logger_name_ = "pydhcp"` (duho
  resolves the logger on the *parsed* instance, so setting it only on `App`
  leaves `-v` raising a logger named after the subcommand), and mixes in
  `duho.LoggingArgs`. A command returns `None` (status 0) or a status; a wrong
  invocation is a `ValueError` out of `__call__`, a failed run an `OSError` or
  the private `_Failed`, and `main` is the one place that prints and maps them.
  Declaring a field has four traps:
  - A **class-body field annotation** is resolved by `typing.get_type_hints` at
    parser-build time, even when quoted and even under `from __future__ import
    annotations`; on 3.9 `X | Y` fails there. Use `typing.Optional[...]`.
  - The **trailing flags tuple** after a field's docstring (`("--foo",)`) is read
    with `ast.literal_eval` on the class source: a literal only, never a call
    such as `Meta(...)`, or the field's whole metadata run is dropped without
    an error. Anything needing `Meta(...)` goes in `typing.Annotated[T, Meta(...)]`.
  - `Meta` has no `dest` field (`Meta(dest=...)` is a `TypeError` saying an
    argument's dest is its field name): only `Meta(kwargs={"dest": "mode"})`
    reaches `add_argument` (it is what `Packet.decode` and `Packet.encode` share
    one attribute through).
  - `App._help_formatter_ = duho.DefaultsFormatter` appends `(default: X)` to the
    help of an option whose default is not `None`, `""` or `False`: do not write
    one in a field's docstring.
- Commits are logical and small: behaviour, docs and CI in separate commits.

## Releasing

Version lives in `pyproject.toml`. Pre-1.0, a **MINOR** bump means the
documented API broke — new methods, new optional keyword arguments and fixes
are all PATCH, so a `~=0.x.0` subscriber gets additions without re-reading.
Each release gets a `CHANGELOG.md` section and a short `RELEASENOTES.md` entry.
Pushing a `v*` tag publishes; `ci-*` tags only run CI.
