# Release notes

The companion to [CHANGELOG.md](CHANGELOG.md): what a user upgrading needs to read for each
release, in a few lines. The changelog has the detail of every change. No performance statement is
made here that is not a result in `benchmarks/results/` recorded by CI.

## [Unreleased]

### Upgrading from 0.7.0

This release breaks the documented API: the changelog's "Renamed" table maps every old name to
its new one, "Removed" lists what is gone and "Changed" has the detail of each behaviour. No old
name is kept as an alias and there is no deprecation period, so an upgrade is a search and replace
and a read of this list.

- **Install.** `pip install pydhcp` is the library. The `pydhcp` command needs `pip install
  "pydhcp[cli]"`, YAML packets and `.yaml` configuration files need `"pydhcp[yaml]"`, and TOML
  needs `"pydhcp[toml]"`; `import pydhcp` imports none of them. A missing one is an `ImportError`
  (or a `DHCPConfigError` for a configuration file) that names the extra, where it was a
  `NotImplementedError`. `netimps>=0.4.0,<0.5` (0.3 is no longer supported) and `pktcap>=0.1.0,<0.2`
  are required.
- **Names.** Acronyms are upper case and the generic names take the `DHCP` prefix: `DhcpServer` is
  `DHCPServer`, `DhcpOptionCode` is `DHCPOptionCode`, `Transport` is `DHCPTransport`, `OpCode` is
  `DHCPOpcode`, `UdpTransport` is `UDPTransport`, and the codecs follow (`CccOption` is
  `CCCOption`, `SipServers` is `SIPServers`). The codec called `IPv4Address` is `IPv4AddressOption`;
  `IPv4Address` is only the address type. Conversions are named once: `DHCPMessage.summary()`,
  `from_text`/`to_text`, `pydhcp.packet.structured.loads`/`dumps`, `SocketAddress.to_tuple()`.
- **Imports.** The public modules are `pydhcp`, `pydhcp.client`, `.server`, `.relay`, `.capture`,
  `.listener`, `.packet`, `.options`, `.lease`, `.exceptions`, `.cli` and
  `pydhcp.packet.structured`; every other module is private, so `pydhcp.listener.sync`,
  `pydhcp.server.handlers`, `pydhcp.options.type` and their like are gone. `pydhcp.network` is
  private and holds only pydhcp's own types: import the address aliases from `ipaddress` and
  `LINK_LOCAL_V4`, `MACAddress` and `SocketOption` from `netimps`.
- **Lifecycle.** Every listener and role has one vocabulary: `bind()`, `start()` (returns `None`,
  raises what the bind raised), `serve_forever()`, `shutdown()`, `wait_closed(timeout=None)`,
  `close()` and `with` (`await aclose()` and `async with` on the asyncio classes). `listen()`,
  `stop()` and `wait()` are gone. Closed is final: using a closed role raises `RuntimeError`.
  `AsyncDHCPServer`, `AsyncDHCPRelay` and `AsyncDHCPCapture` are no longer subclasses of the
  synchronous ones. Constructors take `listen` (and `server_addresses` on the relays)
  positionally, the rest as keywords, and open nothing.
- **Exceptions.** `pydhcp.exceptions` holds `DHCPError` and its subclasses. A decoder raises
  `DHCPDecodeError` (a `ValueError`) for malformed octets, a rejected constructor argument
  raises `DHCPValueError`, and `dora()` and `discover_offer()` raise `DHCPTimeoutError` or
  `DHCPRefusedError` where they returned `None`. `NoClientIdentity` is `NoClientIdentityError`.
- **Values.** The record codecs and `DHCPLease` are read-only values that compare by content;
  `DHCPMessage` takes `op` and keywords; a text option takes text and an integer codec holds
  exactly its range. A missing END marker still decodes and a flags field keeps its reserved bits.
- **Server behaviour.** A reply to a relay goes to port 67 and any other reply to port 68; a
  client with no address is answered by broadcast (over loopback by unicast); a DHCPDISCOVER no
  longer reserves an address for the lease time; a DHCPREQUEST is answered from what the server
  holds, shape by shape (RFC 2131 section 4.3.2); the stock allocator refuses a `giaddr` outside
  the served network. A backend needs the six `LeaseBackend` methods, or the server refuses it.
- **Command line.** `pydhcp.cli.main(argv=None)` returns the status instead of exiting: 0 on
  success, 1 for a failed run, 2 for a wrong invocation (a configuration error included).
  `pydhcp capture --output-mode` is `--per-capture`, `pydhcp relay --server` is required,
  `PYDHCP_TRACEBACK` reads a boolean, `PYDHCP_MCP=stdio` no longer serves the commands as tools,
  and the settings follow one order for every command (the option, then its environment variable,
  then the configuration file, then the default). The capture filter's grammar is pktcap's.
- **New.** `pydhcp capture --format pcap|pcapng` and `--read FILE`, `pydhcp replay`, the
  capture dissector for pktcap, `AsyncDHCPClient`, `deadline=` on the client's exchanges,
  `listen` on an interface by name, and the `Bound:` log record. The options page of the
  documentation lists every named option code with its codec and RFC.

The version in development is 0.8.0; the number of the release is chosen when it is cut.

## [0.7.0] - 2026-10-03

Requires netimps 0.3.3. A taken port raises `netimps.AddressInUseError`, host-address lookups use
netimps' enumeration cache, a listener asks for a 1 MiB receive buffer (`RECEIVE_BUFFER_SIZE`),
and the client's retransmission schedule comes from `netimps.backoff_delays`. Fixes: `encode()`
refuses fewer messages it could encode, a wildcard listener learns the arrival interface on
every platform and Python (receiving goes through `netimps.UdpEndpoint`), `listen="0.0.0.0:67"`
and `"*:67"` are wildcards, and a client that went away no longer costs the server an ERROR on
Windows. Removed: `pydhcp.network.SocketSession`.

## [0.6.1] - 2026-09-28

The `duho` floor is `>=0.6.0,<0.7`; no code changed. `PYDHCP_MCP=stdio` (duho 0.6's MCP launch
mode) is left at duho's default.

## [0.6.0] - 2026-09-21

The 0.5.2 review remediation. The default wildcard server answered nothing on Linux and macOS
(the `IP_PKTINFO` path discarded the local address and interface index); it now completes a DORA
with ISC dhclient. Server, wire-format, relay, client, async, lease-store, capture and registry
fixes are listed by area in the changelog. Added: `AsyncDhcpRelay` and `AsyncDhcpCapture`,
`bound_addresses`, `FileLeaseBackend.SAVE_INTERVAL_SECONDS`, `pydhcp server --lease-file`,
`--per-interface`, `python -m pydhcp`. Breaking: `pydhcp.IPv4Address`, `List`, `Bytes`, `String`
and `Boolean` are no longer re-exported from the top level (import them from
`pydhcp.options.type`) and `pydhcp.constants.MISSING` is private. The package installs a
`NullHandler`, so the WARNING-and-above that `logging.lastResort` printed is silent until a
handler is configured; `netimps>=0.3.1,<0.4` is required.

## [0.5.2] - 2026-08-16

Dependency ranges only: `duho>=0.5.0,<0.6` and `netimps>=0.2.0,<0.3`, so a resolver cannot pick a
release the code does not work with.

## [0.5.1] - 2026-08-16

Added `DhcpOptions.copy()`. Fixed: a server response no longer mutates the stored lease (the
`PARAMETER_REQUEST_LIST` filter used to delete options from it for good), the relay's pending
table is bounded (`MAX_PENDING_CLIENTS`, 1024), and `DhcpMessage.dumps()` prints `siaddr` once.
The `netimps` floor is `>=0.2.2`.

## [0.5.0] - 2026-07-24

The command line is rewritten on `duho`: flags and behaviour are kept, `pydhcp --version` works,
`-v`/`-q` and `--loglevel` replace the per-subcommand `--log-level`, and several short flags are
added. `duho` is a runtime dependency.

## [0.4.1] - 2026-07-22

Network enumeration comes from `netimps` (the 503 lines of ctypes are deleted): adapter names are
human-readable, loopback is enumerated, and `MACAddress` is a `netimps.MACAddress` subclass. Fixed
`_split_host_port` for IPv6 listen specs.

## [0.4.0] - 2026-07-14

Added `DhcpClient` (`discover_offer()`, `dora()`), `DhcpRelay` with a `pydhcp relay` command, the
capture primitives and `pydhcp capture`, option 82 echo in the server, YAML and TOML configuration
files and Hypothesis round-trip tests. Breaking: the global `METRICS` singleton is gone (each
listener owns `metrics`), `pydhcp packet` takes `--input`/`--output` (`-` for stdio) and one
`--format`, and the internals moved into `packet`, `options` and `network` subpackages. Fixed a
`DomainList` decode that dropped domains after a compression pointer.

## [0.3.0] - 2026-07-13

Added CCC option codecs, DHCPINFORM option-only replies, optional TOML support, structured packet
I/O for `pydhcp packet` (JSON, YAML, TOML, INI), multi-endpoint listen specs and JSON benchmark
reports.

## [0.2.1-rc.1] - 2026-07-12

Typed codecs for the common options, wildcard `per_interface` listening, an idempotent
`DhcpMessage.encode()` and corrected `dumps()` labels.

## [0.2.0] - 2026-07-12

Added `AsyncDhcpListener` and `AsyncDhcpServer`, the `Transport` abstraction, pluggable lease
backends, the first command line (`interfaces`, `server`, `packet`, `bench`), JSON configuration,
metrics counters and the benchmark scripts. Fixed `ClasslessRoute` length handling and the
infinite-size options overflow.

## [0.1.0] - 2026-07-11

Initial release.
