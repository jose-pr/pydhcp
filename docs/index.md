# pydhcp

A Python DHCP library and server implementation.

## Features

- **DHCP Packet Parsing & Construction**: Full control and type safety over DHCP message structures.
- **Synchronous & Asynchronous Sockets**: Standard threaded listening loops (`DHCPListener`/`DHCPServer`/`DHCPRelay`/`DHCPCapture`) and an asyncio counterpart for each (`AsyncDHCPListener`/`AsyncDHCPServer`/`AsyncDHCPRelay`/`AsyncDHCPCapture`). Each async half is a sibling of its synchronous twin over the same private core, not a subclass or a parallel implementation, so a fix reaches both.
- **Client & Capture Helpers**: Packet-level client builders and structured DHCP capture output for troubleshooting.
- **Relay Agent**: `DHCPRelay` forwards client traffic to upstream DHCP servers per RFC 1542 / RFC 2131 §4.1, with hop-limit loop protection and optional RFC 3046 option-82 tagging.
- **Flexible Options System**: Easy options manipulation using type-safe custom dictionaries.

## Installation

Install using pip:

```bash
pip install pydhcp
```

## Quick Start

### Synchronous DHCP Server
```python
from pydhcp.server import DHCPServer

# Binds the default DHCP server ports; Ctrl-C raises KeyboardInterrupt
with DHCPServer() as server:
    server.serve_forever()
```

`start()` receives on a daemon thread instead and returns. `shutdown()` ends
either and never blocks, so a handler may call it; `wait_closed()` blocks until
receiving has stopped; `close()` (which leaving the `with` block calls) does both
and then releases the sockets. Closed is final, and the library installs no
signal handler.

### Asynchronous DHCP Server
```python
import asyncio
from pydhcp.server import AsyncDHCPServer

async def main():
    async with AsyncDHCPServer() as server:   # binds; does not serve yet
        await server.serve_forever()          # until shutdown() or cancelled

asyncio.run(main())
```

`serve_forever()` receives in the calling task; `await server.start()` receives in
background tasks and returns once the sockets are bound, for an application with its
own work to await. `shutdown()` ends either, `await wait_closed()` returns once
receiving has stopped, and `await aclose()` (which leaving `async with` awaits)
releases the sockets.
Handlers run on a single worker thread rather than on the event loop, so a blocking
`handle()` will not stall the rest of your application; they still run one at a time and
in arrival order.
At most `max_queued` datagrams (default 1024) wait for the handler; one that arrives
when the backlog is full is dropped and counted in `metrics.packets_dropped_backlog`.

### Basic Packet Client

```python
from pydhcp.client import DHCPClient

client = DHCPClient(listen=("127.0.0.1", 6768))
discover = client.build_discover(b"\x00\x11\x22\x33\x44\x55")
client.send(discover, destination="127.0.0.1", port=6767)
```

`DHCPClient` is intentionally packet-level tooling; it does not configure the operating
system network stack.
