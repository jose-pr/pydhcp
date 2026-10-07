# `pydhcp` — public API header

Header-file-style reference for the `pydhcp` package. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; read it (or the README beside it)
with `importlib.resources.files("pydhcp")`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

`pydhcp` exports what the common task needs, listed under "Root exports". Every other
name has one home, its role module or one of `pydhcp.options`, `pydhcp.packet`,
`pydhcp.lease` and `pydhcp.exceptions`, and is imported from it
(`from pydhcp.options import ClientFQDN`): "Where names live" lists every public
module's exports. A name outside a module's `__all__` is not API. Modules and packages
starting with `_` are private (`pydhcp._network`, `_config`, `_constants`, `_nvt`, `_log`,
`_metrics` and the underscored modules of each package). The root re-exports one type
of another package, `MACAddress`, the object `netimps.MACAddress`, because
`NetworkInterface.mac` hands one to a caller; `IPv4Address`, `IPv4Network` and
`IPv4Interface` come from `ipaddress`, and nothing else of `netimps` is re-exported
(import it from there). `load_config` and the size constants are in private modules
and are not importable from a public one.

Install with `pip install pydhcp`; its required dependencies are `netimps` and `pktcap`.
The `cli` extra (`pip install "pydhcp[cli]"`) adds `duho`, which the `pydhcp` command
needs; the `yaml` extra adds PyYAML (YAML packets and configuration files) and the `toml`
extra `tomli-w`, and `tomli` before Python 3.11 (TOML packets, capture files and
configuration files). A missing one is named where it is used, with its
`pip install "pydhcp[<extra>]"` line. Importing `pydhcp` or `pydhcp.cli` never imports
`duho`, `yaml`, `tomllib`, `tomli` or `tomli_w`. Nor does importing `pydhcp` or one of
its packages import `asyncio`: `AsyncDHCPListener`, `AsyncDHCPServer`, `AsyncDHCPClient`,
`AsyncDHCPRelay` and `AsyncDHCPCapture` are bound when first accessed, under the same
names and import paths. Python 3.9 or newer.

`netimps` supplies the packet-info receive and reply sockets (`UDPEndpoint`), socket
binding, host:port parsing, interface enumeration (`get_interface`, `iter_interfaces`,
`Interface`, `MACAddress`), the retransmission schedule (`backoff_delays`) and bind-error
hints; `pktcap` writes, reads, dissects and replays captures and parses the filter grammar.

`pydhcp.__version__` — the installed distribution's version, read from its metadata.

A large topic keeps its public names in the header beside the code that implements it;
those headers ship in the package, at the paths below (`importlib.resources.files("pydhcp")`).

| Header | Covers |
| --- | --- |
| `pydhcp/AGENTS.md` | this file: the root exports, the network types, the metrics, logging, NVT text and constants, the exceptions, the command line in brief, the environment variables, the gotchas |
| `pydhcp/listener/AGENTS.md` | `DHCPListener`, `AsyncDHCPListener`, the `listen` forms, the transports, `DHCPRequestContext`, host interface enumeration |
| `pydhcp/server/AGENTS.md` | `DHCPServer`, `AsyncDHCPServer`, the hooks you override, and the leases: `DHCPLease`, `LeaseBackend` and the two backends |
| `pydhcp/client/AGENTS.md` | `DHCPClient`, `AsyncDHCPClient`: the message builders, `discover_offer`, `dora` |
| `pydhcp/relay/AGENTS.md` | `DHCPRelay`, `AsyncDHCPRelay` and the pending-client table |
| `pydhcp/capture/AGENTS.md` | `DHCPCapture`, `AsyncDHCPCapture`, `CaptureEvent`, `DHCPCaptureWriter`, the filter expression, `command_hook`, reading and replaying a capture file, DHCP as a pktcap layer |
| `pydhcp/packet/AGENTS.md` | `DHCPMessage`, its enums, `HardwareAddressType`, `pydhcp.packet.structured` |
| `pydhcp/options/AGENTS.md` | `DHCPOptions`, `DHCPOptionCode`, how to write a codec, the value laws |
| `pydhcp/options/_codecs/AGENTS.md` | every payload codec: scalars, addresses and routes, domain names, vendor and TLV containers, MoS and CCC |
| `pydhcp/cli/AGENTS.md` | the `pydhcp` command: subcommands, flags, settings and configuration files, exit statuses, environment variables |

## Where names live

Every public module's `__all__`.

| Module | Exports |
| --- | --- |
| `pydhcp` | `AsyncDHCPCapture`, `AsyncDHCPClient`, `AsyncDHCPListener`, `AsyncDHCPRelay`, `AsyncDHCPServer`, `CaptureEvent`, `ClasslessRoute`, `ClientIdentifier`, `DHCPCapture`, `DHCPClient`, `DHCPConfigError`, `DHCPDecodeError`, `DHCPError`, `DHCPFlags`, `DHCPHookError`, `DHCPLease`, `DHCPListener`, `DHCPMessage`, `DHCPMessageType`, `DHCPOpcode`, `DHCPOption`, `DHCPOptionCode`, `DHCPOptionCodes`, `DHCPOptionType`, `DHCPOptions`, `DHCPPort`, `DHCPRefusedError`, `DHCPRelay`, `DHCPRequestContext`, `DHCPServer`, `DHCPTimeoutError`, `DHCPTransport`, `DHCPValueError`, `DomainList`, `FileLeaseBackend`, `IPv4AddressLike`, `InMemoryLeaseBackend`, `LeaseBackend`, `MACAddress`, `NetworkInterface`, `NoClientIdentityError`, `OptionOverload`, `PktInfoUDPTransport`, `PolicyFilter`, `RDNSSSelection`, `RelayAgentInformation`, `SocketAddress`, `StaticRoute`, `TLVOption`, `U16`, `U32`, `U8`, `UDPTransport`, `URIList`, `UncompressedDomainList`, `UserClass`, `VendorSpecificInformation`, `__version__`, `compile_capture_filter` |
| `pydhcp.capture` | `AsyncDHCPCapture`, `CaptureEvent`, `CaptureHook`, `CapturePredicate`, `CaptureSink`, `DHCPCapture`, `DHCPCaptureWriter`, `DHCPLayer`, `FILENAME_FIELDS`, `HOOK_TIMEOUT_SECONDS`, `MAX_CAPTURE_FILES`, `PacketFilterLike`, `UNIQUE_FILENAME_FIELDS`, `capture_dissector`, `command_hook`, `compile_capture_filter`, `dissect_dhcp`, `read_capture`, `register_dhcp_dissector`, `replay_capture` |
| `pydhcp.cli` | `App`, `Capture`, `Interfaces`, `Packet`, `Relay`, `Replay`, `Server`, `main` |
| `pydhcp.client` | `AsyncDHCPClient`, `ClientIdentifierLike`, `DHCPClient` |
| `pydhcp.exceptions` | `DHCPConfigError`, `DHCPDecodeError`, `DHCPError`, `DHCPHookError`, `DHCPRefusedError`, `DHCPTimeoutError`, `DHCPValueError`, `NoClientIdentityError` |
| `pydhcp.lease` | `DHCPLease`, `FileLeaseBackend`, `InMemoryLeaseBackend`, `LeaseBackend` |
| `pydhcp.listener` | `AsyncDHCPListener`, `BROADCAST_ADDRESS`, `DHCPListener`, `DHCPMetrics`, `DHCPRequestContext`, `DHCPTransport`, `ListenLike`, `PktInfoUDPTransport`, `UDPTransport` |
| `pydhcp.options` | `BaseDHCPOptionCode`, `BaseFixedLengthInteger`, `Boolean`, `Bytes`, `CCCAPBackoffRetry`, `CCCAPBackoffRetrySubOption`, `CCCASBackoffRetry`, `CCCASBackoffRetrySubOption`, `CCCKDCServerAddressList`, `CCCKDCServerAddressSubOption`, `CCCKerberosRealmName`, `CCCKerberosRealmNameSubOption`, `CCCOption`, `CCCPrimaryDHCPServerAddress`, `CCCPrimaryDHCPServerAddressSubOption`, `CCCProvisioningServerAddress`, `CCCProvisioningServerAddressSubOption`, `CCCProvisioningServerFQDN`, `CCCProvisioningTimer`, `CCCProvisioningTimerSubOption`, `CCCSecondaryDHCPServerAddress`, `CCCSecondaryDHCPServerAddressSubOption`, `CCCSecurityTicketControl`, `CCCSecurityTicketControlSubOption`, `CCCSubOption`, `CCCTicketGrantingServerUtilization`, `CCCTicketGrantingServerUtilizationSubOption`, `ClasslessRoute`, `ClientFQDN`, `ClientIdentifier`, `DHCPOption`, `DHCPOptionCode`, `DHCPOptionCodes`, `DHCPOptionType`, `DHCPOptions`, `DomainList`, `DomainName`, `EncapsulatedOptions`, `FixedLengthInteger`, `Flag`, `I32`, `IPv4AddressOption`, `List`, `MAX_OPTION_CODE`, `MIN_OPTION_CODE`, `MoSFQDNList`, `MoSFQDNRecord`, `MoSIPv4AddressList`, `MoSIPv4AddressRecord`, `OctetString`, `OptionCode`, `OptionCodec`, `OptionOverload`, `PCPServerList`, `PolicyFilter`, `RDNSSSelection`, `RecordList`, `RelayAgentInformation`, `SIPServers`, `StaticRoute`, `StatusCode`, `String`, `TLVOption`, `U16`, `U32`, `U8`, `URIList`, `UncompressedDomainList`, `UserClass`, `VIVendorClass`, `VIVendorClassRecord`, `VIVendorSpecificInformation`, `VIVendorSpecificInformationRecord`, `VendorSpecificInformation` |
| `pydhcp.packet` | `DHCPFlags`, `DHCPMessage`, `DHCPMessageType`, `DHCPOpcode`, `DHCPPort`, `HardwareAddressType` |
| `pydhcp.packet.structured` | `dumps`, `loads` |
| `pydhcp.relay` | `AsyncDHCPRelay`, `DEFAULT_MAX_HOPS`, `DHCPRelay`, `RFC1542_MAX_HOPS`, `ServerAddressLike` |
| `pydhcp.server` | `AsyncDHCPServer`, `DHCPServer` |

## Root exports (`pydhcp`)

What `pydhcp` itself exports, each with the header that holds its detail. A signature
here is the constructor's; the methods are in the header named.

```python
DHCPListener(listen=None, *, poll_interval=None, max_packet_size=None, per_interface=None,
    reuse_address=None, receive_buffer_size=None)
AsyncDHCPListener(listen=None, *, max_packet_size=None, per_interface=None, reuse_address=None,
    receive_buffer_size=None, max_queued=None)
DHCPServer(listen=None, *, poll_interval=None, max_packet_size=None, lease_backend=None,
    per_interface=None, reuse_address=None, receive_buffer_size=None)
AsyncDHCPServer(listen=None, *, max_packet_size=None, lease_backend=None, per_interface=None,
    reuse_address=None, receive_buffer_size=None, max_queued=None)
DHCPClient(listen=None, *, poll_interval=None, max_packet_size=None, per_interface=None,
    reuse_address=None, receive_buffer_size=None)
AsyncDHCPClient(listen=None, *, max_packet_size=None, per_interface=None, reuse_address=None,
    receive_buffer_size=None)
DHCPRelay(listen=None, server_addresses=(), *, max_hops=4, insert_relay_agent_info=False,
    circuit_id=None, remote_id=None, trust_client_relay_agent_info=False, poll_interval=None,
    max_packet_size=None, per_interface=None, reuse_address=None, receive_buffer_size=None)
AsyncDHCPRelay(listen=None, server_addresses=(), *, max_hops=4, insert_relay_agent_info=False,
    circuit_id=None, remote_id=None, trust_client_relay_agent_info=False, max_packet_size=None,
    per_interface=None, reuse_address=None, receive_buffer_size=None, max_queued=None)
DHCPCapture(listen=None, *, packet_filter=None, sink=None, hook=None, hook_fail_fast=False,
    poll_interval=None, max_packet_size=None, per_interface=None, reuse_address=None,
    receive_buffer_size=None)
AsyncDHCPCapture(listen=None, *, packet_filter=None, sink=None, hook=None, hook_fail_fast=False,
    max_packet_size=None, per_interface=None, reuse_address=None, receive_buffer_size=None,
    max_queued=None)
CaptureEvent(message, context, captured_at, datagram=None)
compile_capture_filter(text)
DHCPMessage(op, *, htype=HardwareAddressType.ETHERNET, hlen=None, hops=0, xid=0,
    secs=timedelta(0), flags=DHCPFlags.UNICAST, ciaddr=IPv4Address("0.0.0.0"),
    yiaddr=IPv4Address("0.0.0.0"), siaddr=IPv4Address("0.0.0.0"), giaddr=IPv4Address("0.0.0.0"),
    chaddr=b'', sname='', file='', options=None)
DHCPOptions(codemap=None)
TLVOption(code, value)
ClasslessRoute(gateway, network=None)
DHCPLease(ip, expires=None, options=None, *, offered=False)
InMemoryLeaseBackend()
FileLeaseBackend(filepath)
UDPTransport(socket)
PktInfoUDPTransport(socket, endpoint=None)
DHCPRequestContext(transport, interface, client, client_mac, ifindex=None, local_ip=None,
    received_at=None, received_monotonic=None, destination=None, is_unicast=None, payload=None)
```

- `DHCPListener` and `AsyncDHCPListener` — the receive loop on a thread and on an event
  loop, which every role is built on: the `listen` forms, the lifecycle, the request
  context (`pydhcp/listener/AGENTS.md`).
- `DHCPServer` and `AsyncDHCPServer` — the server, with the hooks you override and the
  lease policy (`pydhcp/server/AGENTS.md`).
- `DHCPClient` and `AsyncDHCPClient` — the packet-level client (`pydhcp/client/AGENTS.md`).
- `DHCPRelay` and `AsyncDHCPRelay` — the RFC 1542 relay agent (`pydhcp/relay/AGENTS.md`).
- `DHCPCapture` and `AsyncDHCPCapture` — the capture role; `CaptureEvent` is one message it
  heard and `compile_capture_filter` turns a filter expression into a predicate
  (`pydhcp/capture/AGENTS.md`).
- `DHCPMessage` — the DHCPv4 wire message, with `decode`, `encode` and the structured
  forms; `DHCPMessageType`, `DHCPOpcode`, `DHCPFlags` and `DHCPPort` are the enums a
  caller passes (`pydhcp/packet/AGENTS.md`).
- `DHCPOptions` — the option container a message carries; `DHCPOptionCode` names the IANA
  codes, `DHCPOption` is one decoded pair, `DHCPOptionCodes` a list of codes, and
  `DHCPOptionType` the base class of every codec (`pydhcp/options/AGENTS.md`).
- `TLVOption`, `ClasslessRoute`, `ClientIdentifier`, `DomainList`, `UncompressedDomainList`,
  `OptionOverload`, `PolicyFilter`, `StaticRoute`, `RDNSSSelection`, `RelayAgentInformation`,
  `URIList`, `UserClass`, `VendorSpecificInformation`, `U8`, `U16` and `U32` — the codecs a
  handler most often assigns (`pydhcp/options/_codecs/AGENTS.md`).
- `DHCPLease` — one address held by one client, as a read-only value; `LeaseBackend` is the
  protocol a store implements, `InMemoryLeaseBackend` and `FileLeaseBackend` the two stores
  (`pydhcp/server/AGENTS.md`).
- `DHCPTransport` — the protocol a reply is sent through; `UDPTransport` and
  `PktInfoUDPTransport` send on a socket, and `DHCPRequestContext` is what a handler is
  given with each message (`pydhcp/listener/AGENTS.md`).
- `SocketAddress`, `NetworkInterface` and `IPv4AddressLike` — the network types, below; `MACAddress` — `netimps.MACAddress`, the type of `NetworkInterface.mac`.
- The exceptions `DHCPError`, `DHCPDecodeError`, `DHCPValueError`, `DHCPConfigError`,
  `NoClientIdentityError`, `DHCPTimeoutError`, `DHCPHookError` and `DHCPRefusedError` — below.
- `__version__` — `pydhcp.__version__`, the installed distribution's version.

## Network types (`pydhcp`)

pydhcp's own address and interface types, defined in the private `pydhcp._network`.
Nothing here is an alias of a `netimps` or `ipaddress` object: those are imported from
`netimps` and `ipaddress`. `SocketAddress`, `NetworkInterface` and `IPv4AddressLike`
(`Union[IPv4Address, str]`, what a function accepts for an IPv4 address) are exported by
`pydhcp`, and `HardwareAddressType` by `pydhcp.packet`.

```python
SocketAddress(ip, port)
SocketAddress.from_socket(sock) -> SocketAddress
SocketAddress.to_tuple() -> tuple[str, int]
SocketAddress.parse(text) -> SocketAddress
SocketAddress.try_parse(text, default=None)
NetworkInterface(name, ip_interface, mac=None)
```

- **`SocketAddress`** (`NamedTuple[ip: IPv4Address, port: int]`) —
  `ip` is a `str` or an `ipaddress.IPv4Address`; both arguments are required
  and the constructor does no I/O. A `port` outside 0-65535 raises
  `DHCPValueError`. `str()` is `"host:port"`.
  - **`SocketAddress.from_socket()`** — the local address a
    socket is bound to; it asks the socket (`getsockname()`).
  - **`.to_tuple()`** — plain `(str, int)` pair for stdlib socket
    calls.
  - **`SocketAddress.parse()`** — from `"host:port"`, which is
    what `str()` writes; `DHCPValueError` for anything else, `TypeError` for a
    non-text. `SocketAddress.try_parse(text, default=None)` answers `default`
    for text that does not parse.
  - It does not bind: the listener calls `netimps.bind()`, which raises
    **`netimps.AddressInUseError`** for every "the port is taken" shape and
    whose message is what the caller sees. It is a different thing from
    `netimps.SocketAddress`, which is a `(host, port)` tuple alias.

- **`NetworkInterface`** (`NamedTuple[name: str, ip_interface:
  IPv4Interface | IPv6Interface, mac: netimps.MACAddress | None = None]`) —
  `.ip` and `.network` properties delegate to `ip_interface`. A hardware
  address prints with `mac.format("-", upper=True)` where the form
  `AA-BB-CC-DD-EE-FF` is wanted (`pydhcp interfaces` does); `str(mac)` is
  netimps' own, lowercase and colon-separated.

## Metrics (`pydhcp.listener`)

```python
DHCPMetrics()
DHCPMetrics.reset()
DHCPMetrics.snapshot()
```

- **`DHCPMetrics`** — plain counters, one instance per listener/server/
  client/relay/capture (`self.metrics`), never a module-level singleton.
  `.reset() -> None` zeroes all counters; `.snapshot() -> dict[str, int]`
  returns a plain dict copy.
  - **`DHCPMetrics.FIELDS`** (class var) — the counter names, in snapshot
    order, and the single source `__init__`/`.reset()`/`.snapshot()` all read.
    Add a counter here and it is initialised, reset and reported; the three read it, so a counter cannot be incremented and never reported.
  - Today: `packets_received`, `packets_sent`, `leases_offered`, `leases_allocated`,
    `leases_renewed`, `leases_released`, `leases_declined`, `releases_ignored`,
    `packets_dropped_hop_limit`, `packets_dropped_untrusted`,
    `packets_dropped_truncated`, `packets_dropped_error`,
    `replies_dropped_overflow`, `packets_dropped_backlog` (async hand-off
    drops and stop-time discards), `packets_decoded_leniently` (datagrams the
    decoder accepted although an option was cut short or a text field was not
    UTF-8: one per datagram; option text is read when a handler asks for it, so
    a bad option string is not counted), `packets_dropped_no_client_id` (a
    server dropped a message with neither option 61 nor a hardware address),
    `packets_dropped_other_server` (a message other than a REQUEST naming
    another server), `addresses_refused` (a requested address the server
    refused to lease, or a message relayed from a network the stock allocator does not serve), `replies_dropped_pin` (a broadcast reply that could not
    be pinned to the interface the request arrived on, with or without its index,
    and was dropped rather than sent by an interface the routing table picks) and
    `packets_dropped_other_interface` (a datagram dropped before decoding because it
    arrived on an interface the listener was not told to serve; on Linux the socket is
    bound to its device and the kernel delivers none, so the count stays 0),
    `informs_ignored` (a DHCPINFORM whose `ciaddr` is neither the sender's address nor
    in the served network, or absent), `relay_info_omitted` (a message sent without
    option 82 because it would not fit in the options field: a reply the server
    echoed it into, or a request the relay would have added it to),
    `packets_dropped_relay_loop` (a request whose `giaddr` is an address of the relay),
    `packets_dropped_malformed_option` (a message dropped for an option 50 or 54 of
    the wrong length), `options_ignored_malformed` (an option 51 or 57 of the wrong
    length, treated as absent), `declines_ignored` (a DHCPDECLINE that quarantined
    nothing: the sender holds no lease for the address, it is outside the served
    network, or option 54 names another server) and `quarantines_refused` (an
    address the full quarantine refused).
  - **`leases_offered` counts offers, `leases_allocated` counts commits.** A
    DHCPOFFER holds an address (`offer`) and adds one to `leases_offered`; the
    REQUEST that accepts it (`commit`), or an address allocated and committed
    in one step, adds one to `leases_allocated`. `offers_withdrawn` counts
    offers dropped because the client's REQUEST named another server.
    `leases_renewed` and `leases_released` count bound leases only.
  - `leases_declined` counts `DHCPDECLINE` apart from `leases_released`, because it means the opposite — the client found the address already in use. An address-conflict storm must not read as orderly shutdowns. `releases_ignored` counts releases refused for naming an address
    the client does not hold.

## Logging (`pydhcp`)

- **`LOGGER`** — the package logger, `logging.getLogger("pydhcp")`. Every
  module logs through its own `getLogger(__name__)` child, so an embedder can
  raise or silence one component (`pydhcp.listener`, `pydhcp.server`) without
  touching the others; they all propagate to `pydhcp`.
- **A line a sender can provoke is rate-limited.** For every such reason (an
  undecodable or oversized datagram, a receive or handler error, a message a
  role drops or ignores, a failing pin, a failing hook) the first occurrence is
  written, then at most one line per 60 s for that reason, carrying the running
  count (`[N occurrences so far; ...]`). The listener owns the limiter; the
  table of reasons is capped (128, then one entry shared by the rest) and the
  counts of `metrics` stay exact. A traceback is written for the first occurrence of
  a reason only, and a handler error's reason is its exception class. Text a
  sender wrote (a client identifier, an error's message) is escaped and cut at 80
  characters. A decoder writes at DEBUG only: option and text leniency is counted
  as `packets_decoded_leniently`.

## NVT text (`pydhcp._nvt`)

```python
decode(raw: bytes, what="text") -> str
encode(text: str) -> bytes
display(text: str) -> str
```

The fields RFC 2131/2132 call NVT ASCII — `sname`, `file`, and the `String`
options — carry other encodings in practice. Three helpers keep such a value
lossless on the wire and safe on a screen; use them rather than calling
`bytes.decode`/`str.encode` on these fields directly.

- **`decode`** — UTF-8, with undecodable octets
  preserved via `surrogateescape` (logged at DEBUG, naming `what`, and counted by
  the listener that is decoding). Replacing them would make a relay forward a *different* boot filename than it received.
- **`encode`** — restores those octets exactly. Valid UTF-8
  is unaffected in both directions.
- **`display`** — the lossy step, at the boundary where a
  value is shown rather than parsed: surrogates become U+FFFD, so the result is
  safe for a terminal, a log, or a strict serializer.

## Constants (`pydhcp._constants`)

Not importable from a public module: they live in the private
`pydhcp._constants`.

- **`WILDCARD_V4`** — `IPv4Address("0.0.0.0")`: the "every address" bind target, and
  the source of a client that has none yet. netimps has no such constant.
- **`BOOTP_MIN_PACKET_SIZE`** (300) — the minimal BOOTP message (RFC 951's
  fixed header plus its 64-octet vend field). `DHCPMessage.encode()` pads to
  it: RFC 1542 §2.1 has a relay agent check a datagram can hold this and
  "silently discard" it otherwise, so a shorter message is droppable, not
  merely unusual.
- **`DHCP_MIN_LEGAL_PACKET_SIZE`** (576) — the smallest message every client
  must accept (RFC 2131 §2), and `encode()`'s default `max_packetsize` — its
  default, not its minimum: `encode()` accepts anything from 269 up.
  Exceeding it needs the client's option 57 (`MAXIMUM_DHCP_MESSAGE_SIZE`);
  `DHCPRelay._encode_for_forward` reads that option rather than shrinking a
  reply it is only forwarding (a request goes at the relay's own `max_packet_size`).
- **`UDP_MIN_PACKET_SIZE`** (28) — IPv4 + UDP headers, subtracted from a
  message-size limit to get the DHCP payload budget.
- **`UDP_MAX_PACKET_SIZE`** (65535) — the listeners' default
  `max_packet_size`.
- **`INFINITE_LEASE_TIME`** (`0xFFFFFFFF`) — RFC 2131's "infinite" lease.

## Exceptions (`pydhcp.exceptions`)

```python
DHCPConfigError(msg, path=None, lineno=None, colno=None)
DHCPRefusedError(message, nak)
```

All of them are also exported by `pydhcp`.

- **`DHCPError(Exception)`** — the base of everything pydhcp raises on its
  own account.
- **`DHCPDecodeError(DHCPError, ValueError)`** — octets that are not the
  message or option they were read as. Every decoder (`DHCPMessage.decode`,
  each option codec, `DHCPOptions.get`) raises it, and nothing else, for
  malformed input.
- **`DHCPValueError(DHCPError, ValueError)`** — a value a codec or message
  field cannot represent (an entry past 255 octets, a header field out of
  range).
- **`DHCPConfigError`** (a `DHCPError` and a `ValueError`) — a configuration file that cannot be used: it does not parse, its
  top level is not a mapping, it names a section or key the command does not
  have, or its format cannot be told. `str()` is one line, `path:line:col: msg`,
  with no text from the document.
- **`NoClientIdentityError(DHCPError, ValueError)`** — `DHCPMessage.get_client_id()`
  on a message with neither option 61 nor a hardware address.
- **`DHCPTimeoutError(DHCPError, TimeoutError)`** — a client exchange (`dora()`,
  `discover_offer()`) ended with no usable reply: the retransmissions or the call's
  `deadline` ran out; or a `command_hook` program ran past its `timeout` and was killed.
- **`DHCPHookError(DHCPError)`** — a `command_hook` created with `fail_fast=True` whose
  program exited non-zero; the message names the program, the status and the tail of its
  standard error.
- **`DHCPRefusedError`** (a `DHCPError`) — the server answered the DHCPREQUEST with a
  DHCPNAK. `.nak` is the DHCPNAK `DHCPMessage` (its `DHCP_MESSAGE` option, when
  present, says why); it copies and pickles with its NAK.

A caller's own mistake (a wrong argument type, a bad option code, a bad
`max_packetsize`) stays a plain `TypeError` or `ValueError`.

## Command line

`pydhcp.cli.main(argv=None) -> int` runs the `pydhcp` command (`python -m pydhcp` is the
same) and returns the exit status; the command classes are not API beyond their names. The
subcommands are `interfaces`, `server`, `relay`, `packet`, `capture` and `replay`. The
extra it needs, every flag, the settings layers, the exit statuses and the output formats
are in `pydhcp/cli/AGENTS.md`.

## Environment variables

Read when the command starts, by the command line only: `import pydhcp` reads none of
them, and the library never writes to the environment. A boolean accepts `1`, `true`,
`yes`, `on` and `0`, `false`, `no`, `off`, in any case; empty counts as unset; any other
text is an error naming the variable (status 2). A setting comes from the option, else its
variable, else the configuration file, else the default.

Every option of every subcommand has the variable `PYDHCP_<COMMAND>_<OPTION>` (the command
and the option's field name in upper case: `PYDHCP_SERVER_LEASE_FILE`); the table of them
is in `pydhcp/cli/AGENTS.md`. The ones that follow no such rule:

| Variable | Sets |
| --- | --- |
| `PYDHCP_CONFIG` | the configuration file, as `--config`; `-` is standard input. Default: none |
| `PYDHCP_CONFIG_FORMAT` | `json`, `yaml`, `toml` or `ini`, as `--config-format`. Default: from the file's extension |
| `PYDHCP_TRACEBACK` | a boolean: when on, an error is raised with its traceback (status 1) instead of one `pydhcp: error:` line. Default: off; `0` is off |
| `PYDHCP_MCP` | not read: the root disables the tool server, and the variable is left untouched |
| `PYDHCP_CAPTURE_RECORD_FORMAT` | `capture --format`: `PYDHCP_CAPTURE_FORMAT` is one of the four a hook is given |
| `PYDHCP_CAPTURE_CLIENT_ID`, `PYDHCP_CAPTURE_MSG_TYPE`, `PYDHCP_CAPTURE_XID`, `PYDHCP_CAPTURE_FORMAT` | **set for a command hook**, not read: the client identifier (colon-separated upper-case hex, or `UNKNOWN`), the message type's name (`DHCPDISCOVER`), the transaction id (eight upper-case hex digits) and the record format of the packet the hook is given on standard input (`json` when the output is a capture file) |

## Gotchas

- The package installs a `NullHandler` on `pydhcp`, per the stdlib guidance for
  libraries. One consequence worth knowing: with logging otherwise
  unconfigured, `logging.lastResort` would print WARNING and above to stderr,
  and a `NullHandler` counts as a handler, so those lines go silent instead.
  Configure a handler to see them. The CLI is unaffected — it installs its own.
- A string from `decode()` may hold surrogates, so
  `str.encode("utf-8")` on it raises and `json.dumps(..., ensure_ascii=False)`
  fails at write time. Anything rendering one must call `display()` first —
  `DHCPMessage.summary()`, `.to_mapping()` and `String.to_json()` already do.
