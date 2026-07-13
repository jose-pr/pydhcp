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

## Custom server policy

`DhcpServer` is designed as a base implementation. Override `acquire_lease()` when your
application owns address-pool selection, reservations, or site-specific options.

```python
from datetime import datetime, timedelta

from pydhcp import DhcpLease, DhcpOptions
from pydhcp.enum import DhcpOptionCode
from pydhcp.netutils import IPv4
from pydhcp.server import DhcpServer


class FixedLeaseServer(DhcpServer):
    def acquire_lease(self, client_id, server_id, msg):
        options = DhcpOptions()
        options[DhcpOptionCode.DNS] = [IPv4("1.1.1.1")]
        return DhcpLease(
            IPv4("192.0.2.50"),
            datetime.now() + timedelta(hours=1),
            options,
        )
```

For DHCPINFORM-only customization, override `get_inform_options()` so clients can receive
configuration options without allocating an address.

## Listening on all interfaces

If you want the server to bind every local IPv4 interface, pass `'*'` or `0.0.0.0`.
You can also force the portable per-interface path with `per_interface=True`.

```python
from pydhcp.server import DhcpServer

server = DhcpServer(listen="*", per_interface=True)
server.listen()
```

For deterministic local testing or tools that need several explicit sockets, pass a list of
endpoints or a tuple with multiple ports.

```python
from pydhcp.server import DhcpServer

server = DhcpServer(listen=[("127.0.0.1", [6767, 6768])], per_interface=True)
server.listen()
```

The CLI accepts comma-separated endpoint strings for the same workflow.

```bash
pydhcp server --listen 127.0.0.1:6767,127.0.0.1:6768 --log-level debug
```

## Custom options

`DhcpOptions` behaves like an ordered mapping, so you can build option sets explicitly and preserve encode order.

```python
from pydhcp import DhcpOptions
from pydhcp.enum import DhcpOptionCode

options = DhcpOptions()
options[DhcpOptionCode.HOSTNAME] = "workstation-01"
options[DhcpOptionCode.DOMAIN_NAME] = "example.internal"
```

For more typed examples across the built-in option families, see [Common DHCP Options](options.md).

## Inspecting packets

The CLI can decode packets and print their fields, which is handy when you are debugging client behavior or validating captures.

```bash
pydhcp packet --decode --stdin --json
```

For terminal inspection, use the summary output.

```bash
pydhcp packet --decode --stdin --summary
```

Structured packet text can also be encoded back to packet hex.

```bash
pydhcp packet --encode --input-file packet.json --json --output-file packet.hex
```

TOML packet workflows require the optional TOML extra: `pip install pydhcp[toml]`.
