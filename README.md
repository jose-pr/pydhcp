# pydhcp

[![Tests](https://github.com/jose-pr/pydhcp/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/jose-pr/pydhcp/actions/workflows/test.yml)
[![Version](https://img.shields.io/pypi/v/pydhcp.svg)](https://pypi.org/project/pydhcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/pydhcp.svg)](https://pypi.org/project/pydhcp/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/pydhcp/blob/main/LICENSE)
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
`pydhcp packet --format toml`; JSON, YAML, and INI support remain available with the
base package.

## Quick start

### Synchronous Server
```python
from pydhcp.server import DHCPServer

with DHCPServer(listen="*") as server:    # binds; does not serve yet
    server.serve_forever()                # until shutdown(); Ctrl-C raises KeyboardInterrupt
```

`serve_forever()` receives on the calling thread. `start()` receives on a daemon
thread instead and returns; `shutdown()` ends either and never blocks, so a
handler may call it; `wait_closed()` blocks until receiving has stopped; `close()`
(which leaving the `with` block calls) does both and then releases the sockets.
Closed is final. The library installs no signal handler: the `pydhcp` commands
turn Ctrl-C into `shutdown()`, and an application that wants the same catches
`KeyboardInterrupt` around `serve_forever()`.

The built-in server intentionally keeps allocation policy small. It offers the address a
client asks for in its DISCOVER (holding it for `OFFER_HOLD_SECONDS`, two minutes, until the
client's REQUEST commits it) and renews existing leases, while applications can subclass `DHCPServer`
or provide a custom lease backend for pools, reservations, and site-specific options.

You can also bind explicit endpoints or multiple ports when you do not want wildcard behavior.
A socket bound to an address hears no broadcast on Linux, so this serves unicast peers and
tests, not clients that have no address yet:

```python
server = DHCPServer(listen=[("127.0.0.1", [6767, 6768])], per_interface=True)
server.serve_forever()
```

### Asynchronous Server

Every listener has an asyncio counterpart -- `AsyncDHCPListener`,
`AsyncDHCPServer`, `AsyncDHCPRelay` and `AsyncDHCPCapture`. Each pair is two
sibling drivers over one private core that owns no socket, thread or clock, so a
fix to the rules reaches both; neither is a subclass of the other, and a test
fails if a receive-path line is duplicated between them.

```python
import asyncio
from pydhcp.server import AsyncDHCPServer

async def main():
    async with AsyncDHCPServer() as server:   # binds; does not serve yet
        await server.serve_forever()          # until shutdown() or cancelled

asyncio.run(main())
```

`serve_forever()` receives in the calling task. `await server.start()` receives
in background tasks and returns once the sockets are bound, for an application that
has its own work to await; `shutdown()` (never blocks, safe from a handler) ends
either one, `await wait_closed()` returns once receiving has stopped, and
`await aclose()` (which leaving `async with` awaits) releases the sockets. Handlers
run on a worker thread, so a blocking `handle()` will not stall the rest of your
application.

### Basic Packet Client

`DHCPClient` is a packet-level helper for tests and troubleshooting. It sends DHCP
messages and queues matching replies, but it does not configure host network interfaces.

```python
from pydhcp.client import DHCPClient

client = DHCPClient(listen=("127.0.0.1", 6768))
discover = client.build_discover(b"\x00\x11\x22\x33\x44\x55")
client.send(discover, dst="127.0.0.1", port=6767)
```

`AsyncDHCPClient` is the same client on an event loop: `send`, `discover_offer` and
`dora` are coroutines with the same keywords, and the receive tasks run between
`await client.start()` and `await client.aclose()`.

```python
import asyncio
from pydhcp.client import AsyncDHCPClient


async def main() -> None:
    async with AsyncDHCPClient(listen=("127.0.0.1", 6768)) as client:
        await client.start()
        ack = await client.dora(
            b"\x00\x11\x22\x33\x44\x55", destination="127.0.0.1", port=6767
        )
        print(ack)  # raises DHCPTimeoutError, or DHCPRefusedError for a DHCPNAK


asyncio.run(main())
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

# Record the datagrams as the clients sent them, in a file tcpdump and Wireshark open
pydhcp capture --listen 127.0.0.1:6767 --output heard.pcap

# Read a capture file instead of listening; send its requests again to a test server
pydhcp capture --read heard.pcap --filter msg_type=DHCPDISCOVER
pydhcp replay --input heard.pcap --server 192.0.2.1 --no-delay

# Write one structured file per capture (at most --max-files files, 1000 by default:
# the capture then ends with status 1 and says how many records it refused)
pydhcp capture --listen 127.0.0.1:6767 --output "output/{client_id}/{timestamp}_{msg_type}.{format}" --per-capture --format json

# Invoke a trusted local command hook with each captured packet on stdin
# (on Windows the hook is a program with an extension: ./on-dhcp-capture.cmd)
pydhcp capture --listen 127.0.0.1:6767 --hook ./on-dhcp-capture

# Start the DHCP server from JSON or INI config
pydhcp server --config config.json

# Listen on multiple explicit endpoints while debugging
pydhcp server --listen 127.0.0.1:6767,127.0.0.1:6768

# Increase logging while debugging (-v is repeatable; --loglevel targets one logger)
pydhcp server --listen 127.0.0.1:6767 -v
pydhcp server --listen 127.0.0.1:6767 --loglevel pydhcp:DEBUG
```

### Exit status and errors

`pydhcp` exits 0 on success (also after Ctrl-C), 1 when a run fails (an address in
use, a file that cannot be written) and 2 when the invocation is wrong (a bad option, a
malformed `--listen`, `relay` without `--server`, a configuration file that cannot be
used). An error is one line on stderr, `pydhcp: error: ...`; results go to stdout.
`pydhcp.cli.main(argv)` returns the same status instead of exiting.

### Settings and environment variables

Every option can also come from an environment variable, and `server`, `relay` and
`capture` from a configuration file. The order is: the option, then the variable, then the
file, then the default. The file is named, never searched for: `--config FILE` or
`PYDHCP_CONFIG` (`-` reads standard input and needs `--config-format json|yaml|toml|ini`).
It has one section per command and the keys are the field names:

```yaml
# server.yaml
server:
  listen: 127.0.0.1:6767
  lease_file: /var/lib/pydhcp/leases.json
relay:
  server: [192.0.2.1, 192.0.2.2]
```

A file that does not parse, a section or key the command does not have (a misspelled
`sever:`, another command's section) is refused by name with status 2, naming the file and
the position; nothing starts on defaults by mistake.

| Variable | Sets |
| --- | --- |
| `PYDHCP_CONFIG`, `PYDHCP_CONFIG_FORMAT` | `--config`, `--config-format` |
| `PYDHCP_TRACEBACK` | `1`, `true`, `yes`, `on` (any case) print a traceback for an error; `0`, `false`, `no`, `off` or empty do not; any other text is an error |
| `PYDHCP_SERVER_LISTEN`, `PYDHCP_SERVER_PER_INTERFACE`, `PYDHCP_SERVER_LEASE_FILE` | `server --listen`, `--per-interface`, `--lease-file` |
| `PYDHCP_RELAY_LISTEN`, `PYDHCP_RELAY_SERVER` (comma-separated), `PYDHCP_RELAY_MAX_HOPS`, `PYDHCP_RELAY_INSERT_RELAY_AGENT_INFO`, `PYDHCP_RELAY_CIRCUIT_ID`, `PYDHCP_RELAY_REMOTE_ID`, `PYDHCP_RELAY_PER_INTERFACE` | `relay --listen`, `--server`, `--max-hops`, `--insert-relay-agent-info`, `--circuit-id`, `--remote-id`, `--per-interface` |
| `PYDHCP_CAPTURE_LISTEN`, `PYDHCP_CAPTURE_FILTER`, `PYDHCP_CAPTURE_RECORD_FORMAT`, `PYDHCP_CAPTURE_OUTPUT`, `PYDHCP_CAPTURE_PER_CAPTURE`, `PYDHCP_CAPTURE_MAX_FILES`, `PYDHCP_CAPTURE_COUNT`, `PYDHCP_CAPTURE_HOOK`, `PYDHCP_CAPTURE_HOOK_FAIL_FAST`, `PYDHCP_CAPTURE_PER_INTERFACE`, `PYDHCP_CAPTURE_READ` | `capture --listen`, `--filter`, `--format`, `--output`, `--per-capture`, `--max-files`, `--count`, `--hook`, `--hook-fail-fast`, `--per-interface`, `--read` |
| `PYDHCP_REPLAY_INPUT`, `PYDHCP_REPLAY_SERVER`, `PYDHCP_REPLAY_SPEED`, `PYDHCP_REPLAY_NO_DELAY`, `PYDHCP_REPLAY_MAX_DELAY`, `PYDHCP_REPLAY_LIMIT` | `replay --input`, `--server`, `--speed`, `--no-delay`, `--max-delay`, `--limit` |
| `PYDHCP_PACKET_INPUT`, `PYDHCP_PACKET_OUTPUT`, `PYDHCP_PACKET_FORMAT` | `packet --input`, `--output`, `--format` |
| `PYDHCP_INTERFACES_FORMAT` | `interfaces --format` |

A boolean accepts `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off`. `PYDHCP_MCP` is not
read: no command is served as a tool. A command hook is given `PYDHCP_CAPTURE_CLIENT_ID`,
`PYDHCP_CAPTURE_MSG_TYPE`, `PYDHCP_CAPTURE_XID` and `PYDHCP_CAPTURE_FORMAT`.

## Development

See [`AGENTS.md`](https://github.com/jose-pr/pydhcp/blob/main/AGENTS.md) for environment setup, dependency install, and test commands.

For comprehensive validation in GitHub Actions, the test workflow also supports
manual `workflow_dispatch` runs and safe `ci-*` tags. Benchmarks stay repo-local and opt-in:
use the workflow's `run_benchmarks` input or a `ci-bench-*` tag when you want
the benchmark harness included.

```bash
python benchmarks/run.py                 # print a summary
python benchmarks/run.py --save          # write benchmarks/results/<name>.json
python benchmarks/run.py --suite parse   # one suite instead of all
```

Results are min/median/max ms per call over repeated samples; see
[`benchmarks/README.md`](https://github.com/jose-pr/pydhcp/blob/main/benchmarks/README.md)
for the schema and for why local timings are not a performance claim.

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/jose-pr/pydhcp/blob/main/CHANGELOG.md). Pushing a tag matching `v*` triggers the release
workflow.

### Documentation site

MkDocs builds the API reference from `docs/`. The site is rebuilt and published when a release completes and when a documentation change reaches `main`, and can be rebuilt on demand from any ref (`docs.yml`, run manually). The docs also include a "Common DHCP Options" page with typed examples.

## License

MIT — see [LICENSE](https://github.com/jose-pr/pydhcp/blob/main/LICENSE).
