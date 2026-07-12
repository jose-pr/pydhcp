# pydhcp

[![Version](https://img.shields.io/pypi/v/pydhcp.svg)](https://pypi.org/project/pydhcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/pydhcp.svg)](https://pypi.org/project/pydhcp/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/pydhcp/)

A Python DHCP library and server implementation.

## Features

- **DHCP Packet Parsing** — Full support for parsing and constructing DHCP packets.
- **DHCP Server** — Highly customizable and async-friendly DHCP server.

## Installation

```bash
pip install pydhcp
```

## Quick start

### Synchronous Server
```python
from pydhcp.server import DhcpServer

server = DhcpServer()
server.listen()
```

### Asynchronous Server
```python
import asyncio
from pydhcp.server import AsyncDhcpServer

async def main():
    server = AsyncDhcpServer()
    await server.start()
    # Keep running or handle other async tasks
    # To stop: await server.stop()

asyncio.run(main())
```

## Command Line Interface (CLI)

`pydhcp` includes a command line interface for listing network adapters, decoding packets, running benchmarks, and starting servers.

```bash
# List all network interfaces
pydhcp interfaces

# Decode a hex-encoded DHCP packet
pydhcp packet --decode "01010600..."

# Run performance benchmarks
pydhcp bench

# Start the DHCP server from JSON or INI config
pydhcp server --config config.json

# Increase logging while debugging
pydhcp server --listen 127.0.0.1:6767 --log-level debug
```

## Development

See development notes for environment setup, dependency install, and test commands.

For comprehensive validation in GitHub Actions, the test workflow also supports
manual `workflow_dispatch` runs and safe `ci-*` tags. Benchmarks stay opt-in:
use the workflow's `run_benchmarks` input or a `ci-bench-*` tag when you want
the benchmark harness included.

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Pushing a tag matching `v*` triggers the release
workflow.

### Documentation site

MkDocs builds the API reference from `docs/`, published on every release. The docs also include a "Common DHCP Options" page with typed examples.

## License

MIT — see [LICENSE](LICENSE).
