# Examples

This page collects a few short patterns that are useful when you start wiring `pydhcp` into a real service.

## Server config file

`pydhcp server --config` (or `PYDHCP_CONFIG`) accepts JSON, YAML, TOML, or INI, selected by file extension (`--config-format` names it when the file name does not; `--config -` reads standard input). The file holds a section named for the command, `server`, whose keys are the command's field names (`listen`, `per_interface`, `lease_file`); `relay` and `capture` have sections of their own. A section or key the command does not have is an error. A YAML config:

```yaml
server:
  listen: "*"
```

```bash
pydhcp server --config server.yaml
```

`listen` is text (`"127.0.0.1:6767,127.0.0.2:6768"`), an `[address, port]` pair
(`listen: [127.0.0.1, 6767]`) or a list of either. `None`/`null` as the address is the
wildcard; an empty value, a boolean or a bare number is an error. Text that is not an
IPv4 address names an interface (see [Listening on one
interface](#listening-on-one-interface)).

TOML support requires Python 3.11+ (stdlib `tomllib`) or the optional `tomli` package on older versions.

## Custom lease backend

The server accepts a pluggable lease backend. That makes it easy to persist leases in memory for tests and swap in a file-backed store for simple deployments.

```python
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.server import DHCPServer

server = DHCPServer(lease_backend=InMemoryLeaseBackend())
server.serve_forever()
```

## Custom server policy

`DHCPServer` is designed as a base implementation. Override `acquire_lease()` when your
application owns address-pool selection, reservations, or site-specific options.

The base implementation offers only what it knows first-hand from the receiving
interface — `SUBNET_MASK` and `BROADCAST_ADDRESS`. In particular it does **not** send
`ROUTER` or `DNS`: the machine running the server is not necessarily a gateway or a
resolver, and naming it as both would point clients' off-link traffic and name lookups at
a host that handles neither. Supply the real values here, as below.

```python
from datetime import datetime, timedelta, timezone

from pydhcp import DHCPLease, DHCPOptions
from pydhcp.options import DHCPOptionCode
from ipaddress import IPv4Address as IPv4
from pydhcp.server import DHCPServer


class FixedLeaseServer(DHCPServer):
    def acquire_lease(self, client_id, server_id, msg, *, commit):
        options = DHCPOptions()
        options[DHCPOptionCode.DNS] = [IPv4("1.1.1.1")]
        return DHCPLease(
            IPv4("192.0.2.50"),
            datetime.now(timezone.utc) + timedelta(hours=1),
            options,
        )
```

`acquire_lease()` runs on the server itself, so an attribute it keeps (a counter for the
next free host, say) is the server's own. `commit` says what kind of call it is: a
DHCPDISCOVER makes one call with `commit=False`, and a DHCPREQUEST makes two, `commit=False`
to decide and `commit=True` to commit the ACK. An override that writes to a store of its
own, or that extends a binding, does that only when `commit` is true.

A server that keeps its leases in a store of its own (as above, where nothing is stored) is
asked about a client in four places: INIT-REBOOT, RELEASE, DECLINE and a REQUEST that
names another server. The first goes through `acquire_lease()`; the others ask
`lookup_lease(client_id)`, which reads `lease_backend` unless you override it, and a
release reaches your store through `release_lease()`. Override those two when the leases
are not in `lease_backend`. A DHCPDECLINE quarantines an address only when `lookup_lease()`
says the sender holds it. When you do store leases in `lease_backend`, answer a
`commit=False` call with `offer` and a `commit=True` call with `commit`, so that an address
offered to a client that never accepts is given back.

A backend you pass in is yours: `close()` leaves it open (flush a `FileLeaseBackend`
yourself, or use it as a context manager); a backend the server made is closed with it.

For DHCPINFORM-only customization, override `get_inform_options()` so clients can receive
configuration options without allocating an address.

## Listening on all interfaces

To serve every local IPv4 interface, listen on the wildcard: `'*'` or `0.0.0.0` (the
default). One socket receives broadcasts from every segment and learns which interface each
datagram arrived on.

```python
from pydhcp.server import DHCPServer

server = DHCPServer(listen="*")
server.serve_forever()
```

`per_interface=True`, like naming an address in `listen`, binds one socket per address
instead. **On Linux such a socket hears no broadcast**, so a client that has no address yet is
not served through it (macOS and the BSDs are expected to behave the same, unmeasured;
Windows delivers the broadcast). Use it for unicast traffic and for tests, not to serve
unconfigured clients; pydhcp warns once per process when it binds an address.

## Listening on one interface

To serve one interface and not the others, name it: an adapter name, a MAC or a
`netimps.Interface`, with an optional port.

```python
from pydhcp.server import DHCPServer

server = DHCPServer(listen="eth1")             # the adapter named eth1, default ports
server = DHCPServer(listen="eth1:6767")        # ... on port 6767
server = DHCPServer(listen="aa-bb-cc-dd-ee-ff:6767")   # the adapter with that MAC
server = DHCPServer(listen=("aa:bb:cc:dd:ee:ff", 6767))
server.serve_forever()
```

```bash
pydhcp server --listen eth1
```

The text is read as an IPv4 address first, then as a MAC (`aa:bb:cc:dd:ee:ff`,
`aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`, `aabbccddeeff`), and otherwise as an adapter
name; a host name is **never resolved**, so `localhost` is looked for among the
adapters. The port follows the last colon (`eth0:1` is `eth0`, port 1): a colon-spelled MAC
takes its port in a pair, and an adapter whose name holds a colon, or looks like an
address or a MAC, is passed as a `netimps.Interface`. The adapter is looked up when the
listener binds, and one that does not exist is an error then.

This is one wildcard socket: a socket bound to an address hears no broadcast on Linux, so
the listener has to hear every interface to hear a client that has no address. On Linux
the socket is bound to the device, so the kernel delivers only that interface's datagrams;
elsewhere the listener drops, before decoding, a datagram that arrived on another interface,
and counts it in `metrics.packets_dropped_other_interface` (which stays 0 on Linux in normal
operation). Naming the wildcard on the same port (`"*:67"`)
removes the limit.

For deterministic local testing or tools that need several explicit sockets, pass a list of
endpoints or a tuple with multiple ports.

```python
from pydhcp.server import DHCPServer

server = DHCPServer(listen=[("127.0.0.1", [6767, 6768])], per_interface=True)
server.serve_forever()
```

The CLI accepts comma-separated endpoint strings for the same workflow.

```bash
pydhcp server --listen 127.0.0.1:6767,127.0.0.1:6768 -v
```

## Basic packet client

`DHCPClient` is a small packet client for tests and troubleshooting. It can build and send
common DHCP client messages and queue matching replies, but it does not configure the
operating system network stack.

```python
from pydhcp.client import DHCPClient
from pydhcp.options import DHCPOptionCode

client = DHCPClient(listen=("127.0.0.1", 6768))
discover = client.build_discover(
    b"\x00\x11\x22\x33\x44\x55",
    parameter_request_list=[DHCPOptionCode.SUBNET_MASK, DHCPOptionCode.ROUTER],
)
client.send(discover, dst="127.0.0.1", port=6767)
reply = client.next_reply(timeout=5)
```

The example uses high ports so it can run without privileged DHCP ports during local tests.
Real DHCP traffic on ports 67/68 may require elevated privileges depending on your OS.

### Full DORA exchange in one call

`DHCPClient.dora()` runs DISCOVER → OFFER → REQUEST → ACK and returns the final DHCPACK. It
raises `DHCPTimeoutError` (also a `TimeoutError`) when no usable OFFER or ACK arrives, and
`DHCPRefusedError` when the server answers the REQUEST with a DHCPNAK (the NAK is its `nak`
attribute); a NAK ends the exchange at once. `timeout` is the first retransmission interval and
`deadline` bounds the whole call in seconds. The listener loop must be running (`start()`) so
replies reach the client's internal queue.

```python
from pydhcp import DHCPRefusedError, DHCPTimeoutError
from pydhcp.client import DHCPClient

client = DHCPClient(listen=("0.0.0.0", 68))
client.start()
try:
    ack = client.dora(b"\x00\x11\x22\x33\x44\x55", timeout=2.0, retries=2, deadline=30)
    print(f"Leased {ack.yiaddr}")
except DHCPTimeoutError:
    print("no server answered")
except DHCPRefusedError as refused:
    print(f"the server refused: {refused}")
finally:
    client.close()
```

Use `discover_offer()` instead if you only need the DHCPOFFER without following through with a
DHCPREQUEST.

## Relaying DHCP across subnets

`DHCPRelay` implements the RFC 1542 / RFC 2131 §4.1 / RFC 3046 relay agent role: it forwards
client broadcasts to one or more configured upstream DHCP servers (stamping `giaddr` and
incrementing `hops`), and forwards server replies back to the original client.

```python
from pydhcp.relay import DHCPRelay

relay = DHCPRelay(
    listen="*",
    server_addresses=["10.0.0.53", ("10.0.1.53", 6767)],
    max_hops=16,
)
relay.serve_forever()
```

Pass `insert_relay_agent_info=True` with `circuit_id` and/or `remote_id` to tag the requests that
reach the relay straight from a client with `RELAY_AGENT_INFORMATION` (option 82) per RFC 3046. A
request another relay already stamped (its `giaddr` is set) is forwarded without a second tag, and a
request that would not fit the option within the relay's `max_packet_size` is forwarded without it
and counted in `metrics.relay_info_omitted`. The flag without an id, or an id without the flag, is a
`ValueError`.

```bash
pydhcp relay --listen 127.0.0.1:6767 --server 127.0.0.1:6768 --insert-relay-agent-info --circuit-id aabbcc
```

## Capturing DHCP packets

The capture command listens with the same endpoint syntax as the server and writes structured
packet data. Use `-` for stdout.

```bash
pydhcp capture --listen 127.0.0.1:6767 --filter msg_type=DHCPDISCOVER --output -
```

Capture filters are `key=value` or `key!=value` clauses joined by `and`; a comma in a value means
"any of" (except in `option.NAME`). A value that no packet could match, such as a message type name that
does not exist, is refused when the capture starts.

```bash
pydhcp capture --filter "op=BOOTREQUEST and src_port=68"
pydhcp capture --filter "client_id=01:AA:BB:CC:DD:EE:FF"
pydhcp capture --filter "option.DHCP_MESSAGE_TYPE=DHCPREQUEST"
pydhcp capture --filter "msg_type=DHCPDISCOVER,DHCPREQUEST and src!=192.0.2.1"
```

Write one file containing all accepted captures:

```bash
pydhcp capture --listen 127.0.0.1:6767 --output captures.json --format json
```

Write one file per accepted packet:

```bash
pydhcp capture --listen 127.0.0.1:6767 --format json --output "output/{client_id}/{timestamp}_{msg_type}.{format}" --output-mode per-capture
```

The filename pattern uses values the client chooses, so one run creates at most `--max-files`
distinct files (1000 by default). The packet that needs one more ends the capture with status 1
and a last line saying how many records were refused; raise the limit, or use a pattern without
`{client_id}`. A value in a filename is cut at 64 characters and ends in a hash, so a long client
identifier still gets its own file. A record that cannot be written (the directory is a file, the
disk is full) ends the capture the same way, with one line naming the path, and a single output
file that cannot be appended to is refused before the capture binds.

Hooks can be trusted Python callables or commands. Command hooks receive the serialized
packet on stdin and metadata in `PYDHCP_CAPTURE_*` environment variables
(`PYDHCP_CAPTURE_CLIENT_ID`, `PYDHCP_CAPTURE_MSG_TYPE`, `PYDHCP_CAPTURE_XID` and
`PYDHCP_CAPTURE_FORMAT`); they are started with no arguments and no shell, and killed, with any
process they started, after `HOOK_TIMEOUT_SECONDS` (10 seconds). The same hook is available
to a program as `pydhcp.capture.command_hook(...)`. A command with a
directory in its name (`./on-dhcp-capture`, `/opt/hooks/export`) is that file, found relative
to the working directory when the capture starts; a bare name (`export`) is looked up on
`PATH`. A file in the working directory is therefore written `./name`.

```bash
pydhcp capture --hook myhooks:on_capture
pydhcp capture --hook ./on-dhcp-capture
```

## Custom options

`DHCPOptions` behaves like an ordered mapping, so you can build option sets explicitly and preserve encode order.

```python
from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode

options = DHCPOptions()
options[DHCPOptionCode.HOSTNAME] = "workstation-01"
options[DHCPOptionCode.DOMAIN_NAME] = "example.internal"
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
