# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

The 0.5.2 review remediation: 91 commits against a 339-finding multi-agent review.

### Added

- `AsyncDhcpRelay` and `AsyncDhcpCapture`, completing async parity. Mixed onto
  `AsyncDhcpListener` rather than copied, so the `IP_PKTINFO` receive path and every
  fix it gains are shared; a test parses both classes and fails if any receive-path
  line is duplicated. Verified with ISC dhclient over a veth pair.
- `DhcpListener.bound_addresses` / `AsyncDhcpListener.bound_addresses` — what a
  listener is actually bound to, read from the sockets. This is how a caller that
  passed port 0 learns the port it was given.
- `FileLeaseBackend.SAVE_INTERVAL_SECONDS`, with `flush()`, `close()` and context-manager
  support: opt-in write coalescing. **Off by default** — coalescing trades a property
  the operator cannot see going wrong (leases lost on a crash) for one they can already
  measure, which is the wrong way round for a default.
- `pydhcp server --lease-file PATH` (also `lease_file` under `[server]` in a config
  file). `docs/deployment.md` had always told operators to mount lease storage; until
  now the CLI had no way to write to it, so the volume stayed empty and every client
  renumbered on restart.
- `pydhcp server --per-interface` and `pydhcp relay --per-interface` — both classes
  already took the argument; only the CLI could not reach it.
- `python -m pydhcp` as an entry point.
- `UncompressedDomainList`, and `RecordList[T]` for codecs whose entries are records.

### Fixed

**The one that mattered most.** On Linux and macOS the default wildcard server received
nothing at all: the `IP_PKTINFO` path discarded the local address and interface index at
the line that needed them, so the server answered with identifier `0.0.0.0` and no
client ever completed a DORA. Measured against ISC dhclient 4.4.3: retransmitting
DISCOVER until it gave up, before; bound, after.

- **Server (RFC 2131).** A DHCPDISCOVER no longer extends the lease it is only probing,
  and a REQUEST about to be NAKed no longer renews the address it is refusing. Replies
  carry the server's `siaddr`/`sname`/`file` instead of echoing the client's — a client
  could nominate its own next-server and boot file, which is the pair a PXE client acts
  on. A DHCPRELEASE is checked against `ciaddr` before it frees anything. Option 54 is
  compared against every address this host holds, so a second socket on the same segment
  no longer deletes the binding the first just granted. Option 57 below the RFC 2132
  minimum is floored rather than making `encode` raise and the client get nothing. A
  lease with no time left produces no OFFER and NAKs a REQUEST rather than ACKing an
  empty reply. Lease length is the server's policy, honouring the RFC 2132 infinity
  sentinel. The base server no longer claims to be the network's router and resolver.
- **Wire format.** Every encoded packet leads with the message type on both encode
  paths. `sname`, `file` and `chaddr` raise instead of being silently truncated, and
  `hlen` is bounded to what `decode` accepts. Domain labels are measured in octets, not
  characters — every non-ASCII name was going out corrupt. Options 88 and 146 encode
  uncompressed, as RFC 4280 §4.6 and RFC 6731 require; 119 and 141 still compress, as
  theirs require. Outgoing messages are padded to the 300-octet BOOTP minimum. Six
  option codecs match the wire forms their RFCs define.
- **Relay.** A request is dropped only when its hop count *exceeds* the threshold
  (RFC 1542 §4.1.1) — it was refused one hop early — and the default is now the RFC's 4
  rather than its ceiling of 16. A relayed exchange is identified by client as well as
  transaction, so a forged xid cannot redirect an OFFER.
- **Client.** Retransmissions back off with jitter instead of repeating one interval,
  and carry a real `secs`. Replies match on `(xid, chaddr)`, so two exchanges on one
  client no longer consume each other's replies.
- **Async.** `stop()` called from a handler no longer hangs the loop on Linux — nothing
  it touched was thread-safe, and the selector loop never woke.
- **Lease store.** Bounded, so a forged-identity flood cannot exhaust it. The file
  survives a crash and no longer loses leases silently.
- **Capture and CLI.** Filter keywords match whatever their case — an uppercase `AND`
  compiled, matched nothing and reported nothing. Filter values are checked once at
  startup instead of raising per packet. A per-capture filename pattern is validated
  before binding. A capture run cannot create unbounded files per client identifier.
  The CLI calls itself `pydhcp`.
- **Registry.** A subscripted generic is the same class every time. A user's
  `register_type()` is no longer overwritten by the lazy registry load, and a failed
  load is retried rather than leaving every code as `Bytes`.

### Changed

- `DhcpServer.release_lease()` returns `bool` and no longer touches metrics — an orderly
  release, a DECLINE reporting an address conflict, and a reclaim after the client chose
  another server all arrive there, and only the caller knows which.
- `DhcpMetrics` gains `leases_declined` and `releases_ignored`. DECLINE used to count as
  a release, so an address-conflict storm read as orderly shutdowns.
- `DhcpRelay(max_hops=...)` defaults to 4 and must be 0..16.
- `DhcpClient(timeout=...)` is the *initial* retransmission interval, so a default call
  now takes up to ~14 s rather than ~6 s before giving up.
- The package installs a `NullHandler` and logs under `pydhcp.<module>`. With logging
  otherwise unconfigured this **silences** the WARNING-and-above that `logging.lastResort`
  used to print; configure a handler to see them.
- `DhcpOptions` rejects codes 0 and 255 on assignment — they are structural markers, not
  options. Receive stays liberal.
- Both import cycles removed; `HardwareAddressType` now lives in `pydhcp.network` and is
  re-exported from `pydhcp.packet`.

### Documentation

- The option code registry — 163 RFC-documented members — reaches the API reference for
  the first time.
- A repo-root `AGENTS.md`, which two shipped headers already cited.
- README and CHANGELOG links that only resolved inside a checkout, and CHANGELOG compare
  links naming three tags that never existed.

## [0.5.2] - 2026-08-16

### Changed

- **`duho` is now required as `>=0.5.0,<0.6`** (was `>=0.4.1`). The old floor
  predated duho 0.5.0, which changed how a `list`/`set`/`tuple` field used as an
  option parses: `--x a b` used to accumulate both values in one occurrence
  (`nargs="*"`), and an option field now takes one value per occurrence. The CLI
  declares `server: List[str]` as `--server`/`-s` on the `relay` subcommand and
  documents it as "(repeatable)", so a resolver was free to install a duho where
  that flag did not behave the way its own help text describes. The upper bound
  is the pre-1.0 rule that a minor bump means the documented API broke.
- **`netimps` is now required as `>=0.2.0,<0.3`** (was `>=0.2.2`), normalising it
  to the same minor-series form. Nothing this package calls (`normalize_host`,
  `bind`, `bind_error_hint`, `iter_addresses`, `APIPA`, `MACAddress`) was added
  after 0.2.0, so the exact-patch floor was stricter than the code justified.

## [0.5.1] - 2026-08-16

### Added

- **`DhcpOptions.copy()`** — returns an independent container: the codemap is
  preserved and every payload is copied into a fresh `bytearray`, so neither
  structural edits nor in-place mutation of a payload obtained from
  `get(..., decode=False)` can write through to the original.

### Changed

- The `netimps` requirement floor is raised to `>=0.2.2`. The previous
  `>=0.0.1` predated the API this package actually calls (`normalize_host`,
  `bind`, `bind_error_hint`, `iter_addresses`, `APIPA`, `MACAddress`), so a
  resolver was free to install a release that could not satisfy it.

### Fixed

- **Server responses no longer mutate the stored lease.**
  `DhcpServer._create_response` assigned `resp.options = lease.options`, so the
  response and the lease backend shared one `DhcpOptions` object. Everything the
  response pipeline did to it edited the allocation store: `IP_ADDRESS_LEASE_TIME`,
  `SERVER_IDENTIFIER`, `DHCP_MESSAGE_TYPE` and the echoed
  `RELAY_AGENT_INFORMATION` (option 82) were injected into the lease;
  `PARAMETER_REQUEST_LIST` filtering **permanently deleted** from the lease every
  option the client did not ask for; and `handle_inform` stripped the lease time.
  `InMemoryLeaseBackend.renew` carries the same object across renewals and
  `FileLeaseBackend` persisted the damage to disk. The response now takes
  `lease.options.copy()`.
- **`DhcpRelay._pending_clients` is bounded.** The `xid -> original client
  address` map grew without limit for xids whose replies never arrived, leaking
  memory in a long-running relay. It is now capped at
  `DhcpRelay.MAX_PENDING_CLIENTS` (1024) entries, oldest evicted first; an
  evicted entry only costs the port-68 fallback a real client listens on.
- `MACAddress.hex()` carries the real `bytes.hex` signature it forwards to
  (it had untyped `*args, **kwargs`, which also left its body unchecked).
- Removed two dead `isinstance(e, KeyboardInterrupt)` re-raise branches in
  `listener.py`: `KeyboardInterrupt` does not subclass `Exception`, so neither
  could ever run. The interrupt already propagates to the outer handler.
- `listener.py`'s socket-close bare `except:` is now `except Exception:`.
- `DhcpMessage.dumps()` printed `siaddr` twice, as "Server Address" and "Next
  Server"; it is one field and now prints once as "Next Server (siaddr)".

## [0.5.0] - 2026-07-24

### Changed

- **`cli.py` is rewritten on [`duho`](https://pypi.org/project/duho/)**, a
  declarative CLI framework, replacing hand-built `argparse`. Each subcommand
  (`interfaces`, `server`, `relay`, `packet`, `capture`) is now a `duho.Cmd`
  class with annotated fields instead of `add_argument` calls. Behavior and
  flags are preserved, with additions:
  - `pydhcp --version` now works (resolved from installed package metadata).
  - Per-subcommand `--log-level` is replaced by duho's shared verbosity
    scheme: `-v`/`-q` (repeatable) and `--loglevel KEY=VALUE`.
  - New short flags: `packet` gains `-i`/`-o`/`-f` (`--input`/`--output`/
    `--format`); `capture` gains `-l`/`-o`/`-f`/`-c` (`--listen`/`--output`/
    `--format`/`--count`); `server` and `relay` gain `-l` (`--listen`);
    `relay` also gains `-s` (`--server`).
  - `--help` now shows `(default: X)` next to any option with a non-empty
    default.
- Added `duho` as a runtime dependency.

## [0.4.1] - 2026-07-22

### Changed

- **Network enumeration now comes from `netimps`.** `network/platform.py` --
  503 lines of ctypes (`GetAdaptersInfo`, `getifaddrs` with hand-written
  sockaddr structs, plus `ipconfig`/`ip addr` text-scraping fallbacks) -- is
  deleted. Every address the old code found is still found, with identical
  prefixes and MACs, verified against a captured baseline before switching.
  - Adapter names are now **human-readable** (`"Wi-Fi"`) rather than Windows
    GUIDs.
  - **Loopback is now enumerated**, so a loopback-bound socket resolves to a
    real interface with its true `/8` instead of falling through to a
    synthetic `/32`.
  - `host_ip_interfaces()` gains `family=4` as the default, preserving the
    IPv4-only behaviour callers relied on.
- `MACAddress` is now a `netimps.MACAddress` subclass. The uppercase-hyphenated
  rendering is unchanged; it is no longer a `bytes` subclass, so use `.packed`
  for raw bytes (`.hex()` is kept as a passthrough). It gains `.oui`,
  `.is_multicast`, `.is_local` and ordering.
- `SocketAddress.listen()` delegates to `netimps.bind()`, which closes the
  socket before any exception propagates.
- Bind failures use `netimps.bind_error_hint`, which recognises the POSIX
  errnos *and* the Windows `WinError` codes. The DHCP-specific suggestions are
  appended rather than replacing the diagnosis.

### Fixed

- `_split_host_port` mis-parsed IPv6 listen specs: `"[::1]:67"` returned
  `("[::1]:67", None)`, silently dropping the port. It now delegates to
  `netimps.normalize_host`.

## [0.4.0] - 2026-07-14

### Added
- Added a basic listener-based `DhcpClient` for building, sending, and collecting DHCP client packets without configuring OS interfaces.
- Added reusable DHCP capture primitives and a `pydhcp capture` CLI with safe `and` filters, structured output streams/files/per-capture files, and trusted Python or command hooks.
- `pydhcp.config.load_config` (and `pydhcp server --config`) now accepts YAML and TOML in addition to JSON and INI, matching the formats already supported by `pydhcp.packet.structured`.
- Added `DhcpClient.discover_offer()` and `DhcpClient.dora()` to run a full DISCOVER/OFFER/REQUEST/ACK exchange (with retries and a timeout) in a single call, instead of hand-building each message.
- `DhcpServer` now echoes `RELAY_AGENT_INFORMATION` (option 82) unchanged from request to reply per RFC 3046 §2.2, when a relay agent includes it.
- Added Hypothesis-based property round-trip tests for the core option codecs (`U8`/`U16`/`U32`/`I32`, `Boolean`, `String`, `Bytes`, `List[IPv4Address]`, `DomainList`, `ClasslessRoute`) in `tests/test_property_roundtrip.py`, plus `hypothesis` as a `dev` extra.
- Documented `pydhcp.client`, `pydhcp.capture`, `pydhcp.packet`, `pydhcp.network`, and `pydhcp.lease` on the API reference site, and added FAQ entries for running a DORA handshake and picking a config file format.
- Added `DhcpRelay`, an RFC 1542 / RFC 2131 §4.1 / RFC 3046 DHCP relay agent: forwards client broadcasts to one or more configured upstream servers (stamping `giaddr`, incrementing `hops`, dropping packets past a configurable `max_hops`) and forwards server replies back to the original client, with optional `RELAY_AGENT_INFORMATION` (option 82) circuit-id/remote-id tagging. Includes a `pydhcp relay` CLI subcommand.

### Changed
- Reorganized package internals into clearer `packet`, `options`, and `network` subpackages; `DhcpOptionCode` now lives under `pydhcp.options`, and option codec classes live under `pydhcp.options.type`.
- Moved the message-level enums (`DhcpMessageType`, `OpCode`, `Flags`, `DhcpPort`, `HardwareAddressType`) from `pydhcp.enum` to `pydhcp.packet.enums`, re-exported from `pydhcp.packet`; the `pydhcp.enum` package is gone.
- Renamed the misspelled `pydhcp.constants.INIFINITE_LEASE_TIME` constant to `INFINITE_LEASE_TIME`.
- Split the 1,252-line `pydhcp.options.type` module into a subpackage (`base`, `net`, `scalar`, `vendor`, `mos` submodules); the public import path `pydhcp.options.type` and every name it exposes are unchanged.
- **Breaking**: removed the global mutable `pydhcp.metrics.METRICS` singleton. `DhcpListener` (and `DhcpServer`/`DhcpClient`) now own a per-instance `self.metrics: DhcpMetrics`, so counters no longer leak across independent listeners/servers in the same process (e.g. in tests). Added `DhcpMetrics.snapshot() -> dict[str, int]`.
- Precompiled the DHCP fixed-header `struct.Struct` in `pydhcp.packet.message` instead of re-parsing the format string on every encode/decode call, roughly 5x faster packet parsing (see structured JSON benchmark reports in `benchmarks/README.md`).
- **Breaking**: standardized the `pydhcp packet` CLI on the same conventions `capture` already used: `--input <path>` and `--output <path>` each accept `-` for stdin/stdout (POSIX convention) and default to `-`, and the five separate `--json`/`--yaml`/`--toml`/`--ini`/`--summary` flags collapsed into one `--format <fmt>` flag (default `json`). Removed `--stdin`, `--input-file`, `--output-file`, and inline `--input <text>` (unused/undocumented) — use `--input -` for stdin and a path for files.

### Fixed
- `mypy --strict` now passes cleanly across the whole package (was 40 errors in 8 files), surfacing and fixing one real bug along the way: a synthetic DHCPINFORM lease built with `expires=None` instead of the established "does not expire" sentinel `math.inf`.
- Fixed `DomainList` decoding silently dropping domains that follow a compression-pointer-terminated domain in the same option (affects `DOMAIN_SEARCH` and any other option backed by `DomainList`); found by the new Hypothesis property tests.

## [0.3.0] - 2026-07-13

### Added
- Added CCC option codec coverage and registered `DhcpOptionCode.CCC` for typed round trips.
- Clarified `DhcpServer` customization hooks, added DHCPINFORM option-only responses, and
  repaired examples so they match the current lease API.
- Made TOML packet support optional at import time, with clear `NotImplementedError` messages
  when `tomli` or `tomli-w` is unavailable.
- Added stricter short-packet diagnostics and `pydhcp packet --decode --summary` for compact
  DHCP capture inspection.
- Added multi-endpoint listener parsing for host:port strings, comma-separated CLI listen specs, and
  one-address/many-port tuples, plus `per_interface` constructor parity on sync and async servers.
- Added optional JSON benchmark report output for `benchmarks/bench_options.py` and uploaded the
  opt-in CI benchmark run as a workflow artifact for easier comparison across iterations.
- Added optional JSON benchmark report output for `benchmarks/bench_parse.py` so both benchmark
  entry points now share the same local artifact pattern.
- Extended the opt-in benchmark workflow to archive both parse and options benchmark JSON reports.
- Added the repo-local `benchmarks/run.py` wrapper so maintainers can choose `parse` or `options`
  benchmarks and optionally write structured JSON output without expanding the released package CLI.
- Added structured packet I/O for `pydhcp packet` with JSON, YAML, TOML, and INI round trips plus
  explicit stdin, inline, file, and output-file handling.

### Fixed
- Removed the stale `pydhcp packet --encode` CLI flag and replaced it with a real packet encoding
  mode backed by structured packet helpers.

## 0.2.1-rc.1 - 2026-07-12

### Added
- Expanded DHCP option-type registrations so common well-defined options decode to typed values.
- Added a "Common DHCP Options" docs page with typed examples and updated the custom-options example to prefer typed assignment.
- Added stricter option-type validation and `ClasslessRoute` truncation checks.
- Added wildcard listener `per_interface` support and exported `PktInfoUdpTransport`.
- Added typed codecs and registrations for policy filters, static routes, user classes, encapsulated vendor/relay sub-options, name service search, subnet selection, and RDNSS selection.

### Fixed
- Made `DhcpMessage.encode()` idempotent and tolerant of reserved flag bits during decode.
- Corrected `DhcpMessage.dumps()` field labels and `secs` packing behavior.

## 0.2.0 - 2026-07-12

### Added
- Created `benchmarks/bench_parse.py` packet parsing and serialization performance benchmarks.
- Added `benchmarks/README.md` documenting performance baselines.
- Added `AsyncDhcpListener` and `AsyncDhcpServer` classes implementing asyncio-based event loop integration.
- Added integration tests for async server in `tests/test_async.py`.
- Configured MkDocs documentation with Material theme and `mkdocstrings` auto-generated API references.
- Added `Transport`, `UdpTransport`, and `RequestContext` classes for structured transport-layer abstraction and Interface tracking.
- Added comprehensive unit testing coverage for packet deserialization and type-safe dictionary operations in `test_message.py` and `test_options.py`.
- Added integration tests verifying standard client DORA sequences and RFC 2131 routing logic in `tests/integration/test_dora.py`.
- Added missing `ALL_VPNS` option (Tag 254) to `DhcpOptionCode` after comparing against the latest IANA registry.
- Populated default `ROUTER` and `DNS` lease options in `DhcpServer.acquire_lease` using the server's interface IP.
- Added pluggable lease backend API (`LeaseBackend`) and implementations (`InMemoryLeaseBackend`, `FileLeaseBackend`) for state preservation and persistence.
- Added unit and integration tests for lease backends in `tests/test_lease_backend.py` and `tests/integration/test_dora.py`.
- Added validation checks for hardware address length (hlen <= 16) during packet decoding.
- Added socket binding error diagnostics that offer actionable suggestions for permission and address-in-use errors.
- Added unit tests for binding error handling and malformed packet input in `tests/test_permissions.py` and `tests/test_malformed_packets.py`.
- Added command-line interface (CLI) with `interfaces`, `server`, `packet`, and `bench` subcommands.
- Added JSON-based configuration loading support in `config.py`.
- Added in-process metrics counters (`packets_received`, `packets_sent`, etc.) in `metrics.py` to support observability.
- Added option parsing and lease allocation performance benchmarks in `benchmarks/bench_options.py`.
- Added async DHCP server concurrency stress tests under `tests/test_async_concurrency.py`.

### Changed
- Configured strict typechecking configuration in `pyproject.toml` and resolved all mypy type-checking errors across the library.
- Refactored `DhcpMessageType` and `OptionOverload` to implement the `DhcpOptionType` interface directly and avoid PEP 561 / type conflicts with `BaseFixedLengthInteger` and Enums.
- Refactored `DhcpServer.handle` to accept `RequestContext` instead of `SocketSession`, split processing into message-type specific handlers (`handle_discover`, etc.), and comply strictly with RFC 2131 routing paths.
- Enriched `NetworkInterface` and `host_ip_interfaces()` to yield fully detailed adapter metadata.
- Refactored `DhcpServer` and `AsyncDhcpServer` to accept and delegate lease lifecycle events (allocate, lookup, renew, release) to a configurable `lease_backend`.
- Refactored options parsing in `DhcpOptions.decode` to handle truncated option lengths gracefully by logging a warning and parsing remaining bytes instead of crashing.
- Added debug-level logging for packet arrival and lease allocation including client XIDs.
- Renamed misspelled `contants.py` to `constants.py` and updated all internal references.
- Added strict `__all__` public exports list to `src/pydhcp/__init__.py`.

### Fixed
- Fixed bug in `ClasslessRoute` destination descriptor parsing/serialization that caused incorrect length calculations for CIDR/8.
- Fixed forward reference type resolution issue for `DhcpOption` in `_options.py`.
- Fixed options encoding `OverflowError` when option size limit is infinite.
- Fixed `BaseDhcpOptionCode.__int__` returning constant zero, correcting enum integer conversion for option codes.

## 0.1.0 - 2026-07-11

### Added

- Initial release.

[Unreleased]: https://github.com/jose-pr/pydhcp/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/jose-pr/pydhcp/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/jose-pr/pydhcp/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/jose-pr/pydhcp/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/jose-pr/pydhcp/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/jose-pr/pydhcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jose-pr/pydhcp/compare/5d1f19e7bac784c926966eaf8561a3c588b2f5f2...v0.3.0
