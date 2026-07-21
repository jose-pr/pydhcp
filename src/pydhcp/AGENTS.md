# `pydhcp` — public API header

Header-file-style reference for the top-level `pydhcp` package: every
`pydhcp/__init__.py` export with its signature, arguments, contract, and
gotchas, so this module can be consumed without reading its source. For the
project overview, install, and CLI, see the repo-root `AGENTS.md`. The
`network`, `options`, and `packet` subpackages have their own headers
(`src/pydhcp/{network,options,packet}/AGENTS.md`); `pydhcp/__init__.py`
re-exports everything from those subpackages too, so `from pydhcp import
DhcpMessage` etc. all work directly off the top-level package.

## Listener / transport (`listener.py`)

- **`DhcpListener(listen=None, select_timeout=None, max_packet_size=None,
  per_interface=None)`** — synchronous, thread-based receive loop.
  `listen`: `None`/`"*"` (wildcard, expands to every host interface unless
  `IP_PKTINFO` is available), a `"host:port"` string, an `IPv4`, a
  `(host, port_or_ports)` tuple, or a sequence of any of those (comma-joined
  strings split automatically). `select_timeout` (default 1s) bounds the
  `select()` poll. `max_packet_size` defaults to `UDP_MAX_PACKET_SIZE`
  (65535). `per_interface=True` disables `IP_PKTINFO` wildcard routing and
  binds one socket per interface instead. Every instance owns
  `self.metrics: DhcpMetrics` — there is no global metrics singleton.
  - `.bind() -> None` — open/refresh sockets for `self._listen`; raises
    `PermissionError` for privileged ports (<1024 without rights) and
    `OSError` for `EADDRINUSE`, both with an actionable message.
  - `.listen() -> None` — blocking receive loop; decodes each datagram,
    resolves the receiving `NetworkInterface`, builds a `RequestContext`, and
    calls `self.handle(msg, context)`. Catches and logs per-packet exceptions
    (not `KeyboardInterrupt`) so one bad packet never kills the loop.
  - `.start(cancellation_token=None) -> Thread | None` — runs `.listen()` on
    a background thread and installs a `SIGINT` handler that calls `.stop()`;
    returns `None` if already started.
  - `.stop() -> None` / `.wait() -> None` — signal and block on the
    cancellation `threading.Event`.
  - `.handle(msg, context) -> None` — override point; base implementation is
    a no-op. Called for every successfully decoded packet.
- **`AsyncDhcpListener(listen=None, max_packet_size=None,
  per_interface=None)`** — `asyncio` counterpart. `await .start()` binds and
  creates one `DatagramProtocol` endpoint per socket; `await .stop()` closes
  transports and sockets. Same `.handle()` override point and per-instance
  `self.metrics`.
- **`Transport`** — abstract `.send(data, dest: IPv4, port: int, client_mac:
  bytes) -> int`; base raises `NotImplementedError`.
- **`UdpTransport(socket)`** — plain UDP send; unicast failures automatically
  retry as a broadcast (logged as a warning).
- **`PktInfoUdpTransport(socket)`** — POSIX `IP_PKTINFO`-aware transport for
  wildcard sockets; falls back to `UdpTransport.send` when `ifindex`/
  `local_ip` aren't set or the platform lacks `sendmsg`/`IP_PKTINFO`.
- **`RequestContext`** (`NamedTuple`) — `transport: Transport`, `interface:
  NetworkInterface`, `client: SocketAddress`, `client_mac: bytes`,
  `ifindex: int | None = None`, `local_ip: IPv4 | None = None`. Handlers use
  `context.transport`/`context.interface` to reply out the same interface a
  request arrived on.
- **`ListenSpec`** — type alias for the `listen` argument accepted above.

**Gotcha**: a socket bound to a specific loopback address (`127.0.0.1`, not
`0.0.0.0`) cannot originate a UDP broadcast send on POSIX (Windows is lenient
and silently allows it). Any test/deployment that binds to a specific loopback
IP and needs a broadcast reply path should pass `broadcast=False` through the
client build helpers below to keep the exchange unicast.

## Server (`server.py`)

- **`DhcpServer(listen=None, select_timeout=None, max_packet_size=None,
  lease_backend=None, per_interface=None)`** (`DhcpListener` subclass) —
  `lease_backend` defaults to a fresh `InMemoryLeaseBackend()`.
  - `.acquire_lease(client_id, server_id, msg) -> DhcpLease | None` —
    override point. Base impl renews an existing lease, else allocates when
    the client supplies `REQUESTED_IP` or a non-wildcard `ciaddr`; returns
    `None` when nothing can be allocated (silently drops the message).
  - `.release_lease(client_id, server_id, msg) -> None` — override point,
    releases via the lease backend.
  - `.get_inform_options(server_id, msg) -> DhcpOptions` — override point for
    DHCPINFORM-only option sets (no address allocated).
  - `.handle_discover/.handle_request/.handle_decline/.handle_release/
    .handle_inform(msg, context) -> None` — per-message-type handlers called
    from `.handle()`; each is independently overridable.
  - `.handle(msg, context) -> None` — dispatches on `DHCP_MESSAGE_TYPE`;
    ignores non-`BOOTREQUEST` messages and messages addressed to a different
    `SERVER_IDENTIFIER` than this interface's IP (releasing the lease first
    if it was a DHCPREQUEST).
  - Reply destination (`_filter_and_send`): unicasts to `giaddr:67` when a
    relay is in play (RFC 2131 §4.1); otherwise uses `ciaddr`, then
    broadcasts if the client's `BROADCAST` flag is set, else `yiaddr`,
    falling back to `255.255.255.255`. `RELAY_AGENT_INFORMATION` (option 82)
    on the request is echoed back unmodified on the reply, per RFC 3046 §2.2.
- **`AsyncDhcpServer(listen=None, max_packet_size=None, lease_backend=None,
  per_interface=None)`** — same allocation logic as `DhcpServer`, running on
  `AsyncDhcpListener`.

## Client (`client.py`)

- **`DhcpClient(listen=None, select_timeout=None, max_packet_size=None,
  per_interface=None)`** (`DhcpListener` subclass) — packet-level client for
  tests/troubleshooting; does **not** configure OS network interfaces.
  - `.build_discover/.build_request/.build_inform/.build_release/
    .build_decline(chaddr, *, xid=None, ..., broadcast=True) -> DhcpMessage`
    — construct (but don't send) each message type. `chaddr` is required
    bytes; `xid` defaults to a random 32-bit value; `client_identifier` and
    `parameter_request_list` are added to every builder that accepts them.
  - `.send(message, destination=IPv4("255.255.255.255"),
    port=DhcpPort.SERVER) -> int` — binds lazily on first call, sends via a
    fresh `UdpTransport`, and tracks the message's `xid` in
    `self._pending_xids` so `.handle()` only queues matching replies.
  - `.discover_offer(chaddr, *, timeout=2.0, retries=2, destination=...,
    port=..., **discover_kwargs) -> DhcpMessage | None` — broadcasts
    DHCPDISCOVER (with retries) and returns the first DHCPOFFER, or `None`.
  - `.dora(chaddr, *, timeout=2.0, retries=2, destination=..., port=...,
    broadcast=True, **discover_kwargs) -> DhcpMessage | None` — full
    DISCOVER→OFFER→REQUEST→ACK exchange; returns the DHCPACK or `None`.
    **`broadcast` forwards to both the DISCOVER and the follow-up REQUEST.**
  - `.next_reply(timeout=None) -> tuple[DhcpMessage, RequestContext] | None`
    / `.drain_replies() -> list[...]` — pull queued BOOTREPLY messages.
  - `.on_reply(msg, context) -> None` — override hook called after a
    BOOTREPLY is accepted and queued (no-op by default).

**Gotcha**: `.dora()`/`.discover_offer()` require the listener's receive loop
to actually be running (`client.start()`) — replies only reach the internal
queue via `.handle()`, which the background thread calls. A `DhcpClient`
that's never started will always time out waiting for a reply.

## Relay (`relay.py`)

- **`DhcpRelay(listen=None, server_addresses=(), max_hops=16,
  insert_relay_agent_info=False, circuit_id=None, remote_id=None,
  select_timeout=None, max_packet_size=None, per_interface=None)`**
  (`DhcpListener` subclass) — RFC 1542 / RFC 2131 §4.1 / RFC 3046 relay
  agent. `server_addresses` is required and non-empty (each entry an `IPv4`,
  a string, or a `(host, port)` tuple; bare entries default to port 67) —
  raises `ValueError` otherwise. `insert_relay_agent_info=True` adds option
  82 with `circuit_id`/`remote_id` sub-options (skipped, with a warning, if
  the request already carries one).
  - `.handle(msg, context) -> None` — forwards `BOOTREQUEST` to every
    configured server (stamping `giaddr` and incrementing `hops`; drops and
    counts in `metrics.packets_dropped_hop_limit` once `hops > max_hops`) and
    forwards `BOOTREPLY` back to the original client.

**Gotcha**: a relay reply must not assume the client listens on well-known
port 68 — DHCPOFFER/ACK never carries the original client's UDP source port.
`DhcpRelay` tracks `xid -> original client SocketAddress` in
`self._pending_clients` (populated on forward, consumed on reply) so clients
on non-standard ports still get routed correctly; falls back to port 68 if
the xid was never observed by this relay instance.

## Capture (`capture.py`)

- **`DhcpCapture(listen=None, packet_filter=None, sink=None, hook=None,
  hook_fail_fast=False, select_timeout=None, max_packet_size=None,
  per_interface=None)`** (`DhcpListener` subclass) — `packet_filter` is
  either a filter-expression string (compiled via `compile_capture_filter`)
  or a `Callable[[CaptureEvent], bool]`; `sink` gets every accepted event;
  `hook` also gets every accepted event but exceptions are only logged
  unless `hook_fail_fast=True` (then re-raised). `self.accepted_count` tracks
  how many events passed the filter.
- **`CaptureEvent`** (frozen dataclass) — `message: DhcpMessage`, `context:
  RequestContext`, `captured_at: datetime`. Properties: `.source` /
  `.destination` (`SocketAddress`), `.message_type` (str name or `"UNKNOWN"`),
  `.client_id` (str), `.xid` (8-hex-digit str). `.format_filename(pattern,
  format) -> str` fills `{client_id}`/`{timestamp}`/`{msg_type}`/`{xid}`/
  `{format}` placeholders (each value filesystem-sanitized).
- **`compile_capture_filter(text) -> Callable[[CaptureEvent], bool]`** —
  `None`/blank → always-true. Otherwise parses `and`-joined `key=value`
  clauses (`or` unsupported, raises `ValueError`). Keys: `op`, `msg_type`,
  `xid` (int, any base), `client_id`, `chaddr`, `src`, `src_port`, `dst`,
  `dst_port`, `interface`, or `option.<NAME_OR_CODE>` (compares the option's
  decoded/enum-name or string value). Unknown keys raise `ValueError`
  eagerly, at compile time.

**Gotcha**: `CaptureEvent.destination` casts `context.interface.ip` to `IPv4`
to satisfy `SocketAddress`; an IPv6-only interface isn't actually handled
(`NetworkInterface.ip` is `IPv4Address | IPv6Address`) — capture on an
IPv6-only interface can break at runtime.

## Leases (`lease.py`)

- **`DhcpLease`** (`NamedTuple`) — `ip: IPv4 | None`, `expires: datetime |
  float` (`math.inf` for an infinite lease), `options: DhcpOptions`.
- **`LeaseBackend`** (`Protocol`) — `.allocate(client_id, ip, ttl,
  options=None) -> DhcpLease | None`, `.lookup(client_id) -> DhcpLease |
  None`, `.release(client_id) -> bool`, `.renew(client_id, ttl) -> DhcpLease
  | None`. `ttl` is seconds; pass `math.inf` for an infinite lease.
- **`InMemoryLeaseBackend()`** — dict-backed reference implementation;
  `.lookup()` evicts (and returns `None` for) expired leases lazily.
- **`FileLeaseBackend(filepath="leases.json")`** (`InMemoryLeaseBackend`
  subclass) — persists to JSON after every allocate/release/renew; malformed
  or missing files are silently ignored on load (starts empty), and save
  failures are silently swallowed too (best-effort persistence, not a
  durable store).

## Metrics (`metrics.py`)

- **`DhcpMetrics()`** — plain counters, one instance per listener/server/
  client/relay/capture (`self.metrics`), never a module-level singleton.
  Fields: `packets_received`, `packets_sent`, `leases_allocated`,
  `leases_renewed`, `leases_released`, `packets_dropped_hop_limit`.
  `.reset() -> None` zeroes all counters; `.snapshot() -> dict[str, int]`
  returns a plain dict copy.

## Config loading (`config.py`)

- **`load_config(filepath: str) -> dict[str, Any]`** — dispatches on the
  file extension: `.ini` (via `configparser`, one dict per section), `.yaml`/
  `.yml`, `.toml` (raises `NotImplementedError` with an actionable message on
  Python <3.11 without `tomli` installed), else JSON. Used by the `server`/
  `relay` CLI subcommands' `--config` flag.

## CLI (`cli.py`)

- **`main() -> None`** — the `pydhcp` console-script entry point
  (`[project.scripts]` in `pyproject.toml`). Subcommands: `interfaces`,
  `server` (`--config`, `--listen`, `--log-level`), `relay` (`--listen`,
  `--server` repeatable, `--max-hops`, `--insert-relay-agent-info`,
  `--circuit-id`, `--remote-id`, `--log-level`), `packet` (`--decode`/
  `--encode`, `--input`/`--output` accepting `-` for stdio, `--format
  json|yaml|toml|ini|summary`), `capture` (`--listen`, `--filter`,
  `--format`, `--output` file/pattern/`-`, `--output-mode
  stream|single|per-capture`, `--count`, `--hook` `module:function` or an
  executable path, `--hook-fail-fast`, `--per-interface`, `--log-level`).
  Not designed to be imported and called with custom `argv` — it parses
  `sys.argv` directly.

**Gotcha**: capture's newline-delimited JSON stream output (`--format json`
in `stream`/`single` mode) is compact JSON by design (one object per line);
use `dump_message(..., "json")` directly only for single structured packet
files where pretty JSON is acceptable.
