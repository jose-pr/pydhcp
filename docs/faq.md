# FAQ

## Why does the server use a synthetic interface on loopback?

In sandboxed or minimal environments, interface enumeration may not return a matching `NetworkInterface` record for `127.0.0.1`. The server falls back to a synthetic interface so tests and local demos still work.

## Why are some clients sent broadcast replies?

If the server cannot send a direct unicast packet to the requested address, it falls back to broadcast delivery. That keeps local development usable even when the requested lease address is not reachable from the host network.

## Why are the docs split into several short pages?

The project has a few different operational concerns now: API reference, examples, deployment, and troubleshooting. Keeping them separate makes it easier to find the right piece without scrolling through a giant wall of text.

## How do I run a DORA handshake from Python?

Use `DhcpClient.dora()` — it broadcasts a DHCPDISCOVER, waits for a DHCPOFFER, sends a matching DHCPREQUEST, and waits for the DHCPACK, returning `None` if any step times out after the configured retries. The client's listener loop must be started first (`client.start()`) so replies reach its internal queue. See [Examples](examples.md#full-dora-exchange-in-one-call) for a full snippet, or `DhcpClient.discover_offer()` if you only need the offer.

## Which config formats does the CLI accept?

`pydhcp server --config` accepts JSON, YAML, TOML, or INI, selected by file extension (`.json`, `.yaml`/`.yml`, `.toml`, `.ini`). TOML support requires Python 3.11+ (stdlib `tomllib`) or the optional `tomli` package on older versions. See [Examples](examples.md#server-config-file).
