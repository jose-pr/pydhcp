# Examples

This page collects a few short patterns that are useful when you start wiring `pydhcp` into a real service.

## Server config file

`pydhcp server --config` accepts JSON, YAML, TOML, or INI, selected by file extension. A YAML config:

```yaml
server:
  listen: "*"
```

```bash
pydhcp server --config server.yaml
```

TOML support requires Python 3.11+ (stdlib `tomllib`) or the optional `tomli` package on older versions.

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
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4
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

## Basic packet client

`DhcpClient` is a small packet client for tests and troubleshooting. It can build and send
common DHCP client messages and queue matching replies, but it does not configure the
operating system network stack.

```python
from pydhcp.client import DhcpClient
from pydhcp.options import DhcpOptionCode

client = DhcpClient(listen=("127.0.0.1", 6768))
discover = client.build_discover(
    b"\x00\x11\x22\x33\x44\x55",
    parameter_request_list=[DhcpOptionCode.SUBNET_MASK, DhcpOptionCode.ROUTER],
)
client.send(discover, destination="127.0.0.1", port=6767)
reply = client.next_reply(timeout=5)
```

The example uses high ports so it can run without privileged DHCP ports during local tests.
Real DHCP traffic on ports 67/68 may require elevated privileges depending on your OS.

### Full DORA exchange in one call

`DhcpClient.dora()` runs DISCOVER → OFFER → REQUEST → ACK and returns the final DHCPACK (or
`None` if any step times out). The listener loop must be running (`start()`) so replies reach
the client's internal queue.

```python
from pydhcp.client import DhcpClient

client = DhcpClient(listen=("0.0.0.0", 68))
client.start()
ack = client.dora(b"\x00\x11\x22\x33\x44\x55", timeout=2.0, retries=2)
if ack is not None:
    print(f"Leased {ack.yiaddr}")
```

Use `discover_offer()` instead if you only need the DHCPOFFER without following through with a
DHCPREQUEST.

## Relaying DHCP across subnets

`DhcpRelay` implements the RFC 1542 / RFC 2131 §4.1 / RFC 3046 relay agent role: it forwards
client broadcasts to one or more configured upstream DHCP servers (stamping `giaddr` and
incrementing `hops`), and forwards server replies back to the original client.

```python
from pydhcp.relay import DhcpRelay

relay = DhcpRelay(
    listen="*",
    server_addresses=["10.0.0.53", ("10.0.1.53", 6767)],
    max_hops=16,
)
relay.bind()
relay.listen()
```

Pass `insert_relay_agent_info=True` (with `circuit_id`/`remote_id`) to tag forwarded requests with
`RELAY_AGENT_INFORMATION` (option 82) per RFC 3046 — a request that already carries option 82 (a
chained relay) is passed through unmodified rather than double-tagged.

```bash
pydhcp relay --listen 127.0.0.1:6767 --server 127.0.0.1:6768 --insert-relay-agent-info --circuit-id aabbcc
```

## Capturing DHCP packets

The capture command listens with the same endpoint syntax as the server and writes structured
packet data. Use `-` for stdout.

```bash
pydhcp capture --listen 127.0.0.1:6767 --filter msg_type=DHCPDISCOVER --output -
```

Capture filters support exact matches joined by `and`.

```bash
pydhcp capture --filter "op=BOOTREQUEST and src_port=68"
pydhcp capture --filter "client_id=01:AA:BB:CC:DD:EE:FF"
pydhcp capture --filter "option.DHCP_MESSAGE_TYPE=DHCPREQUEST"
```

Write one file containing all accepted captures:

```bash
pydhcp capture --listen 127.0.0.1:6767 --output captures.json --format json
```

Write one file per accepted packet:

```bash
pydhcp capture --listen 127.0.0.1:6767 --format json --output "output/{client_id}/{timestamp}_{msg_type}.{format}" --output-mode per-capture
```

Hooks can be trusted Python callables or command paths. Command hooks receive the serialized
packet on stdin and metadata in `PYDHCP_CAPTURE_*` environment variables.

```bash
pydhcp capture --hook myhooks:on_capture
pydhcp capture --hook ./on-dhcp-capture
```

## Custom options

`DhcpOptions` behaves like an ordered mapping, so you can build option sets explicitly and preserve encode order.

```python
from pydhcp import DhcpOptions
from pydhcp.options import DhcpOptionCode

options = DhcpOptions()
options[DhcpOptionCode.HOSTNAME] = "workstation-01"
options[DhcpOptionCode.DOMAIN_NAME] = "example.internal"
```

For more typed examples across the built-in option families, see [Common DHCP Options](options.md).

## Inspecting packets

The CLI can decode packets and print their fields, which is handy when you are debugging client behavior or validating captures.

```bash
pydhcp packet --decode --input - --format json
```

For terminal inspection, use the summary output.

```bash
pydhcp packet --decode --input - --format summary
```

`--input`/`--output` default to `-` (stdin/stdout), following standard POSIX convention, so both
can be omitted when piping. Structured packet text can also be encoded back to packet hex, and
`--input`/`--output` accept a file path in place of `-`.

```bash
pydhcp packet --encode --input packet.json --format json --output packet.hex
```

TOML packet workflows require the optional TOML extra: `pip install pydhcp[toml]`.
