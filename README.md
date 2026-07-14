# pydhcp

[![Version](https://img.shields.io/pypi/v/pydhcp.svg)](https://pypi.org/project/pydhcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/pydhcp.svg)](https://pypi.org/project/pydhcp/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/pydhcp/)

A Python DHCP library and server implementation.

`pydhcp` is pure Python and targets Python 3.9 and newer. Packet parsing and
structured packet tooling are portable; actual DHCP serving still depends on OS
socket permissions and platform-specific UDP behavior.

## Features

- **DHCP Packet Parsing** — Full support for parsing and constructing DHCP packets.
- **DHCP Server Base** — A simple, async-friendly server foundation with overrideable lease and option policy hooks.
- **DHCP Client & Capture Tools** — Basic packet-client builders and a tshark-like capture command for troubleshooting.

## Installation

```bash
pip install pydhcp
```

TOML packet encode/decode support is optional. Install `pydhcp[toml]` if you want
`pydhcp packet --toml`; JSON, YAML, and INI support remain available with the base package.

## Quick start

### Synchronous Server
```python
from pydhcp.server import DhcpServer

server = DhcpServer(listen="*")
server.listen()
```

The built-in server intentionally keeps allocation policy small. It renews existing leases
and responds to client-requested addresses, while applications can subclass `DhcpServer`
or provide a custom lease backend for pools, reservations, and site-specific options.

You can also bind explicit endpoints or multiple ports when you do not want wildcard behavior:

```python
server = DhcpServer(listen=[("127.0.0.1", [6767, 6768])], per_interface=True)
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

### Basic Packet Client

`DhcpClient` is a packet-level helper for tests and troubleshooting. It sends DHCP
messages and queues matching replies, but it does not configure host network interfaces.

```python
from pydhcp.client import DhcpClient

client = DhcpClient(listen=("127.0.0.1", 6768))
discover = client.build_discover(b"\x00\x11\x22\x33\x44\x55")
client.send(discover, destination="127.0.0.1", port=6767)
```

## Command Line Interface (CLI)

`pydhcp` includes a command line interface for listing network adapters, decoding packets, and starting servers.

```bash
# List all network interfaces
pydhcp interfaces

# Decode a hex-encoded DHCP packet from stdin as JSON
pydhcp packet --decode --input - --format json

# Decode a hex-encoded DHCP packet from stdin as a compact text summary
pydhcp packet --decode --input - --format summary

# Encode structured packet text back to hex
pydhcp packet --encode --input packet.json --format json --output packet.hex

# Capture DHCPDISCOVER packets as newline-delimited JSON on stdout
pydhcp capture --listen 127.0.0.1:6767 --filter msg_type=DHCPDISCOVER --output -

# Write one structured file per capture
pydhcp capture --listen 127.0.0.1:6767 --output "output/{client_id}/{timestamp}_{msg_type}.{format}" --output-mode per-capture --format json

# Invoke a trusted local command hook with each captured packet on stdin
pydhcp capture --listen 127.0.0.1:6767 --hook ./on-dhcp-capture

# Start the DHCP server from JSON or INI config
pydhcp server --config config.json

# Listen on multiple explicit endpoints while debugging
pydhcp server --listen 127.0.0.1:6767,127.0.0.1:6768

# Increase logging while debugging
pydhcp server --listen 127.0.0.1:6767 --log-level debug
```

## Development

See development notes for environment setup, dependency install, and test commands.

For comprehensive validation in GitHub Actions, the test workflow also supports
manual `workflow_dispatch` runs and safe `ci-*` tags. Benchmarks stay repo-local and opt-in:
use the workflow's `run_benchmarks` input or a `ci-bench-*` tag when you want
the benchmark harness included. The repository wrapper and individual benchmark scripts can also
write structured JSON reports for local comparison or CI artifact upload:

```bash
.\.venv\3.12.10\Scripts\python.exe benchmarks\run.py --suite parse --iterations 10000 --json-output benchmark-results/bench_parse.json
.\.venv\3.12.10\Scripts\python.exe benchmarks\run.py --suite options --iterations 1000 --json-output benchmark-results/bench_options.json
.\.venv\3.12.10\Scripts\python.exe benchmarks\bench_parse.py --iterations 10000 --json-output benchmark-results/bench_parse.json
.\.venv\3.12.10\Scripts\python.exe benchmarks\bench_options.py --iterations 1000 --json-output benchmark-results/bench_options.json
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Pushing a tag matching `v*` triggers the release
workflow.

### Documentation site

MkDocs builds the API reference from `docs/`, published on every release. The docs also include a "Common DHCP Options" page with typed examples.

## License

MIT — see [LICENSE](LICENSE).
