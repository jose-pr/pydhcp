# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Created `benchmarks/bench_parse.py` packet parsing and serialization performance benchmarks.
- Added `benchmarks/README.md` documenting performance baselines.

### Changed
- Configured strict typechecking configuration in `pyproject.toml` and resolved all mypy type-checking errors across the library.
- Refactored `DhcpMessageType` and `OptionOverload` to implement the `DhcpOptionType` interface directly and avoid PEP 561 / type conflicts with `BaseFixedLengthInteger` and Enums.

### Fixed
- Fixed bug in `ClasslessRoute` destination descriptor parsing/serialization that caused incorrect length calculations for CIDR/8.
- Fixed forward reference type resolution issue for `DhcpOption` in `_options.py`.

## [0.1.0] - 2026-07-11

### Added

- Initial release.

[Unreleased]: https://github.com/jose-pr/pydhcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jose-pr/pydhcp/releases/tag/v0.1.0
