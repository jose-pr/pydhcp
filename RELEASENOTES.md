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

- **Install.** `pip install pydhcp` is the library and needs `netimps>=0.4.1,<0.5` alone (0.3 is
  no longer supported). The `pydhcp` command needs `pip install "pydhcp[cli]"`; captures
  (`pydhcp capture`, `pydhcp replay`, `sniff_dhcp`) and a message as YAML, TOML or INI text need
  `"pydhcp[pktcap]"` (and `"pktcap[yaml,toml]"` for the format libraries); a `.toml` settings file
  needs `"pydhcp[toml]"` before Python 3.11; `import pydhcp` imports none of them. A missing one is
  an `ImportError` (or a `DHCPConfigError` for a configuration file) that names the extra, where it
  was a `NotImplementedError`. pydhcp declares no PyYAML and reads no YAML settings file: a
  `.yaml` file is refused, and is converted to TOML or JSON (the last row of the table below).
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
  `LINK_LOCAL_V4` and `SocketOption` from `netimps`; `pydhcp.MACAddress` is `netimps.MACAddress`.
- **Lifecycle.** Every listener and role has one vocabulary: `bind()`, `start()` (returns `None`,
  raises what the bind raised), `serve_forever()`, `shutdown()`, `wait_closed(timeout=None)`,
  `close()` and `with` (`await aclose()` and `async with` on the asyncio classes). `listen()`,
  `stop()` and `wait()` are gone. Closed is final: using a closed role raises `RuntimeError`.
  `AsyncDHCPServer` and `AsyncDHCPRelay` are no longer subclasses of the
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
  the served network; an OFFER and an ACK carry the renewal and rebinding times (options 58 and
  59, `RENEWAL_TIMES`); a DHCPDECLINE of an address of the served network is believed whoever
  sent it (`DECLINE_REQUIRES_LEASE = True` marks only an address the sender holds). A backend
  needs the six `LeaseBackend` methods, or the server refuses it.
- **Command line.** `pydhcp.cli.main(argv=None)` returns the status instead of exiting: 0 on
  success, 1 for a failed run, 2 for a wrong invocation (a configuration error included).
  `pydhcp relay --server` is required, `PYDHCP_TRACEBACK` reads a boolean, `PYDHCP_MCP=stdio`
  serves `packet` and `interfaces` as tools, and the settings follow one order for every command
  (the option, then its environment variable, then the configuration file, then the default).
- **Captures are pktcap's.** `pydhcp capture` is pktcap's `capture` command with DHCP's defaults,
  and pydhcp's own capture classes, filter, file-name pattern and hook runner are gone. What
  moved, from 0.7.0:

  | 0.7.0 | now |
  | --- | --- |
  | `DhcpCapture(listen, packet_filter, sink, hook)`, `AsyncDhcpCapture` | `for frame in sniff_dhcp(listen)` and `async for frame in asniff_dhcp(listen)`, written with `pktcap.copy_frames(frames, writer, select=, each=)` |
  | `CaptureEvent` (`.message`, `.message_type`, `.client_id`, `.xid`) | `pktcap.DissectedFrame`: `frame.layer(DHCPLayer)` has `message_type`, `client_id`, `xid` (an `int`) and `message` (the mapping); `DHCPMessage.decode(frame.datagram().payload)` is the message |
  | `compile_capture_filter(text)` | `pktcap.compile_capture_filter(text, pktcap.frame_filter_for(capture_dissector().registry))` |
  | `validate_filename_pattern`, `CaptureEvent.format_filename`, `FILENAME_FIELDS`, `pydhcp.cli.MAX_PER_CAPTURE_FILES` | `pktcap.CaptureWriter(target, format, per_record=True, fields=("client_id", "msg_type", "xid"))`, whose `max_files` is 1000 |
  | `pydhcp.cli.HOOK_TIMEOUT_SECONDS` | `--hook-timeout` (10 seconds); `pktcap.command_hook(command, timeout=)`, which with `fail_fast=True` raises `pktcap.CaptureHookError` |
  | `pydhcp capture --output-mode per-capture` | `--per-record`; the other two modes need no option |
  | `pydhcp capture -f FORMAT`, `-c N` | `--format FORMAT` (`-f` is `--filter`), `--count N` |
  | filter keys `src_port`, `dst_port`, `interface` | `sport`, `dport`, and `--listen NAME` |
  | a record: the message mapping | pktcap's record of the frame (`time`, `linktype`, `length`, `layers`, `payload`); the old line is `jq -c '.layers[-1].message'` |
  | a record file is appended to | replaced, unless `--append` |
  | a hook gets `PYDHCP_CAPTURE_CLIENT_ID`, `_MSG_TYPE`, `_XID`, `_FORMAT` and the message on standard input | `PKTCAP_HOOK_CLIENT_ID`, `_MSG_TYPE`, `_XID`, `_FORMAT` and the record; the client identifier is written as in a file name, `01_02_00_00_99_00_02` where it was `01:02:00:00:99:00:02` |
  | a `module:function` hook gets a `CaptureEvent`, and is found in the working directory | it gets a `pktcap.DissectedFrame`, and its module must be on `PYTHONPATH` |
  | a command hook named by a bare name; a `.cmd` or `.bat` hook on Windows | `./name` for a file in the working directory (a bare name is looked up on `PATH` alone); a program (an `.exe`) |
  | a settings file `server.yaml` (`server:` / `listen: "*"`) | `server.toml` (`[server]` / `listen = "*"`) or JSON |

  A file budget spent (`--max-files`, 1000) is counted and the capture goes on, ending with status
  1; an `--output` ending that names no format is status 2, where it was JSON; and an INI message
  has a `[record]` section where it had `[message]` (the old one is still read). A removed option
  or filter key is refused by name.

  The development tree had more names after 0.7.0 that no release shipped, and they are gone or
  renamed too: `DHCPCaptureWriter` and `MAX_CAPTURE_FILES` (`pktcap.CaptureWriter`),
  `pydhcp.capture.command_hook` and `DHCPHookError` (`pktcap.command_hook`,
  `pktcap.CaptureHookError`), `read_capture(source)` (`pktcap.read_dissected(source,
  dissector=capture_dissector())`), `replay_capture(source, server)` (`pktcap.replay_to(datagrams,
  server, 67)`), `--per-capture` (`--per-record`), `replay --server` (`--to`), the `[capture]`
  keys `packet_filter`, `packet_format` and `per_capture` (`filter`, `format`, `per_record`) and
  the variables `PYDHCP_CAPTURE_RECORD_FORMAT`, `PYDHCP_CAPTURE_PER_CAPTURE` and
  `PYDHCP_REPLAY_SERVER` (`PYDHCP_CAPTURE_FORMAT`, `PYDHCP_CAPTURE_PER_RECORD`,
  `PYDHCP_REPLAY_TO`). An option, a key or a variable among them is refused, status 2.
- **New.** `pydhcp replay`, which sends the requests of a capture file to a server you name;
  `pydhcp capture --read FILE`, `--format pcap|pcapng|text`, `--max-files`, `--interface`,
  `--datagrams`, `--append`, `--duration` and `--hook-timeout`; `sniff_dhcp` and `asniff_dhcp`,
  `DHCPLayer.summary()` and the DHCP dissector and filter keys for pktcap (`pktcap_plugin`);
  `AsyncDHCPClient`, `deadline=` on the client's exchanges, `listen` on an interface by name, and
  the `Bound:` log record. The options page of the documentation lists every named option code
  with its codec and RFC.

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
