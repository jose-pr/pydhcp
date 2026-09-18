# pydhcp

A Python DHCP library and server implementation.

## Features

- **DHCP Packet Parsing & Construction**: Full control and type safety over DHCP message structures.
- **Synchronous & Asynchronous Sockets**: Standard threaded listening loops (`DhcpListener`/`DhcpServer`) and modern asyncio endpoints (`AsyncDhcpListener`/`AsyncDhcpServer`).
- **Client & Capture Helpers**: Packet-level client builders and structured DHCP capture output for troubleshooting.
- **Relay Agent**: `DhcpRelay` forwards client traffic to upstream DHCP servers per RFC 1542 / RFC 2131 §4.1, with hop-limit loop protection and optional RFC 3046 option-82 tagging.
- **Flexible Options System**: Easy options manipulation using type-safe custom dictionaries.

## Installation

Install using pip:

```bash
pip install pydhcp
```

## Quick Start

### Synchronous DHCP Server
```python
from pydhcp.server import DhcpServer

# Automatically binds to default DHCP server ports
server = DhcpServer()
server.listen()
```

### Asynchronous DHCP Server
```python
import asyncio
from pydhcp.server import AsyncDhcpServer

async def main():
    server = AsyncDhcpServer()
    await server.start()      # binds and starts receiving; returns immediately
    try:
        await asyncio.Event().wait()   # serve until cancelled (Ctrl-C)
    finally:
        server.stop()

asyncio.run(main())
```

`start()` returns as soon as the sockets are bound, so something has to keep the loop
alive — await your application's own work there instead of the `Event` if you have any.
Handlers run on a single worker thread rather than on the event loop, so a blocking
`handle()` will not stall the rest of your application; they still run one at a time and
in arrival order.

### Basic Packet Client

```python
from pydhcp.client import DhcpClient

client = DhcpClient(listen=("127.0.0.1", 6768))
discover = client.build_discover(b"\x00\x11\x22\x33\x44\x55")
client.send(discover, destination="127.0.0.1", port=6767)
```

`DhcpClient` is intentionally packet-level tooling; it does not configure the operating
system network stack.
