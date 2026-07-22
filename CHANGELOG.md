# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

## [0.2.1-rc.1] - 2026-07-12

### Added
- Expanded DHCP option-type registrations so common well-defined options decode to typed values.
- Added a "Common DHCP Options" docs page with typed examples and updated the custom-options example to prefer typed assignment.
- Added stricter option-type validation and `ClasslessRoute` truncation checks.
- Added wildcard listener `per_interface` support and exported `PktInfoUdpTransport`.
- Added typed codecs and registrations for policy filters, static routes, user classes, encapsulated vendor/relay sub-options, name service search, subnet selection, and RDNSS selection.

### Fixed
- Made `DhcpMessage.encode()` idempotent and tolerant of reserved flag bits during decode.
- Corrected `DhcpMessage.dumps()` field labels and `secs` packing behavior.

## [0.2.0] - 2026-07-12

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

## [0.1.0] - 2026-07-11

### Added

- Initial release.

[0.3.0]: https://github.com/jose-pr/pydhcp/compare/v0.2.1-rc.1...v0.3.0
[0.2.1-rc.1]: https://github.com/jose-pr/pydhcp/compare/v0.2.0...v0.2.1-rc.1
[0.2.0]: https://github.com/jose-pr/pydhcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jose-pr/pydhcp/releases/tag/v0.1.0
