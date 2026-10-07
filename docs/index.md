# pydhcp

A **pure-Python DHCPv4 library with a server, a client, a relay agent and a
capture tool**, each in a blocking and an asyncio form over typed messages and
options. It targets Python 3.9 and newer: packet parsing and the structured
formats are portable, while actually serving DHCP still depends on OS socket
permissions and platform-specific UDP behavior.

- **Packet parsing and construction**: every DHCPv4 message, a `DHCPOptionCode` member and
  a typed codec for each IANA option, and a JSON, YAML, TOML or INI form of every message.
  Liberal on receive, strict on send.
- **Server base**: lease and option policy hooks, an in-memory and a file lease backend, and
  a threaded and an asyncio driver (`DHCPServer`, `AsyncDHCPServer`) over one core, so a fix
  to the rules reaches both.
- **Relay agent**: `DHCPRelay` forwards client traffic to upstream servers per RFC 1542 /
  RFC 2131 §4.1, with hop-limit loop protection and optional RFC 3046 option-82 tagging.
- **Packet client and capture**: `DHCPClient` builds and sends the client messages and runs a
  DORA exchange; `DHCPCapture` and the `pydhcp capture` command record, filter, replay and
  hand each packet to a hook.

## Installation

```bash
pip install pydhcp
```

The library (packets, options, server, client, relay, capture) needs nothing else. What
else you ask of it is an extra, one for each capability:

| Extra | Adds | Needed for |
| --- | --- | --- |
| `cli` | `duho` | the `pydhcp` command (`python -m pydhcp`) |
| `yaml` | `PyYAML` | YAML packets and `.yaml` configuration files |
| `toml` | `tomli-w`, and `tomli` before Python 3.11 | TOML packets and capture files; `.toml` configuration files before Python 3.11 |

For example `pip install "pydhcp[cli,yaml]"`. JSON and INI need no extra.

## 30-second tour

```python
from pydhcp.server import DHCPServer

with DHCPServer(listen="*") as server:    # binds; does not serve yet
    server.serve_forever()                # until shutdown(); Ctrl-C raises KeyboardInterrupt
```

`start()` receives on a daemon thread instead and returns. `shutdown()` ends
either and never blocks, so a handler may call it; `wait_closed()` blocks until
receiving has stopped; `close()` (which leaving the `with` block calls) does both
and then releases the sockets. Closed is final, and the library installs no
signal handler.

```python
from pydhcp.client import DHCPClient

client = DHCPClient(listen=("127.0.0.1", 6768))
discover = client.build_discover(b"\x00\x11\x22\x33\x44\x55")
client.send(discover, dst="127.0.0.1", port=6767)
```

`DHCPClient` is intentionally packet-level tooling; it does not configure the operating
system network stack.

```bash
pydhcp capture --listen 127.0.0.1:6767 --filter msg_type=DHCPDISCOVER --output -
pydhcp server --config server.yaml
```

## Learn more

- [API reference](api.md): the message, the options, the roles and the capture tools,
  from their docstrings.
- [Examples](examples.md): a custom lease backend, a custom server policy, a config file,
  the packet client and a full DORA exchange.
- [Common DHCP options](options.md): typed examples for the options most sites set.
- [Deployment](deployment.md) and [Troubleshooting](troubleshooting.md).
- [FAQ](faq.md) and the [changelog](changelog.md).
