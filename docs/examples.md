# Examples

This page collects a few short patterns that are useful when you start wiring `pydhcp` into a real service.

## Custom lease backend

The server accepts a pluggable lease backend. That makes it easy to persist leases in memory for tests and swap in a file-backed store for simple deployments.

```python
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.server import DhcpServer

server = DhcpServer(lease_backend=InMemoryLeaseBackend())
server.listen()
```

## Custom options

`DhcpOptions` behaves like an ordered mapping, so you can build option sets explicitly and preserve encode order.

```python
from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode

options = DhcpOptions()
options[DhcpOptionCode.HOST_NAME] = b"workstation-01"
options[DhcpOptionCode.DOMAIN_NAME] = b"example.internal"
```

## Inspecting packets

The CLI can decode packets and print their fields, which is handy when you are debugging client behavior or validating captures.

```bash
pydhcp packet --help
```
