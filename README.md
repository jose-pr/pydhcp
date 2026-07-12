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

```python
from pydhcp.server import DhcpServer

server = DhcpServer()
server.listen()
```

## Development

See development notes for environment setup, dependency install, and test commands.

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Pushing a tag matching `v*` triggers the release
workflow.

### Documentation site

MkDocs builds the API reference from `docs/`, published on every release.

## License

MIT — see [LICENSE](LICENSE).
