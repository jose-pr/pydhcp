# pydhcp

A Python DHCP library and server implementation.

## Features

- **DHCP Packet Parsing & Construction**: Full control and type safety over DHCP message structures.
- **Synchronous & Asynchronous Sockets**: Standard threaded listening loops (`DhcpListener`/`DhcpServer`) and modern asyncio endpoints (`AsyncDhcpListener`/`AsyncDhcpServer`).
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
    await server.start()
    
    # Wait or run other async application logic
    # To shut down cleanly:
    # await server.stop()

asyncio.run(main())
```
