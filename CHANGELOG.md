# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Added optional JSON benchmark report output for `benchmarks/bench_options.py` and uploaded the
  opt-in CI benchmark run as a workflow artifact for easier comparison across iterations.
- Added optional JSON benchmark report output for `benchmarks/bench_parse.py` so both benchmark
  entry points now share the same local artifact pattern.
- Extended the opt-in benchmark workflow to archive both parse and options benchmark JSON reports.
- Extended `pydhcp bench` so the CLI can choose `parse` or `options` benchmarks and optionally
  write structured JSON output.

### Fixed
- Removed the stale `pydhcp packet --encode` CLI flag so the packet subcommand no longer advertises
  an unsupported mode.

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

[0.2.0]: https://github.com/jose-pr/pydhcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jose-pr/pydhcp/releases/tag/v0.1.0
