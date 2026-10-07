# FAQ

## Why does the log say it is using a synthetic interface?

When no host adapter holds the address a datagram arrived on, the listener hands the handler a placeholder interface (`unknown[<address>]`, a /32 with no MAC) and logs one WARNING for each address. A server cannot derive an address pool from a /32, so it answers nothing from it. The usual cause is a listener bound to an address that the host's adapters do not list; name an address or an adapter that the host has (`pydhcp interfaces` lists them).

## Why are some clients sent broadcast replies?

A client with no address yet cannot answer ARP for the one it was offered, so a reply unicast to it on a plain UDP socket is lost without an error. The server therefore answers such a client by broadcast, whether or not its `BROADCAST` flag is set, and a DHCPNAK with no relay is always broadcast. The exceptions are an exchange over loopback, where there is no ARP and POSIX refuses the broadcast, and a server with `UNICAST_TO_UNCONFIGURED_CLIENT` set. A send that fails is never retried as a broadcast: it raises `OSError`.

## How do I run a DORA handshake from Python?

Use `DHCPClient.dora()` — it broadcasts a DHCPDISCOVER, waits for a DHCPOFFER, sends a matching DHCPREQUEST, and waits for the DHCPACK, raising `DHCPTimeoutError` if no usable reply arrives after the configured retries (or the call's `deadline`) and `DHCPRefusedError` if the server answers with a DHCPNAK. The client's listener loop must be started first (`client.start()`) so replies reach its internal queue. See [Examples](examples.md#full-dora-exchange-in-one-call) for a full snippet, or `DHCPClient.discover_offer()` if you only need the offer.

## Which config formats does the CLI accept?

`pydhcp server --config` (or `PYDHCP_CONFIG`) accepts JSON, YAML, TOML, or INI, selected by file extension (`.json`, `.yaml`/`.yml`, `.toml`, `.ini`) or by `--config-format`. YAML needs the `yaml` extra, and TOML Python 3.11+ (stdlib `tomllib`) or the `toml` extra on older versions. See [Examples](examples.md#server-config-file).
