# `pydhcp` — public API header

Header-file-style reference for the top-level `pydhcp` package: every
`pydhcp/__init__.py` export with its signature, arguments, contract, and
gotchas, so this module can be consumed without reading its source. For the
project overview, install, and CLI, see <https://github.com/jose-pr/pydhcp>. The
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
  per_interface=None)`** — `asyncio` counterpart, with the same receive path,
  the same `IP_PKTINFO` wildcard routing and the same `listen` forms as
  `DhcpListener`. `await .start()` binds and registers each socket with the
  event loop; `.stop()` unregisters and closes them. `.stop()` is **not** a
  coroutine — it is reached through the inherited `DhcpListener` contract,
  where nobody awaits it — but `await .stop()` still works. Same `.handle()`
  override point and per-instance `self.metrics`.
  - Handlers run on a single worker thread, not on the event loop: `.handle()`
    is ordinary blocking code, so running it inline stalled every other
    coroutine in the host application. One worker, so handlers still run one
    at a time in arrival order — the lease backends are not thread-safe.
  - `await .wait() -> None` — returns when `.stop()` is called; returns
    immediately if never started. `.listen()` raises `NotImplementedError`
    (there is no blocking loop to enter — use `start()` then `wait()`).
  - On loops without socket readability (Windows' default proactor loop) it
    falls back to a `DatagramProtocol` endpoint per socket. That path cannot
    carry `IP_PKTINFO`, which is absent on those platforms anyway.
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
  - The reply is built from `lease.options.copy()`, never the lease's own
    container: the response pipeline injects bookkeeping options and the
    `PARAMETER_REQUEST_LIST` filter deletes everything the client did not
    ask for — all of which used to write through to the lease backend. An
    `.acquire_lease()` override returning a lease whose options it also keeps
    a reference to is therefore safe.
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
    **`broadcast` forwards to both the DISCOVER and the follow-up REQUEST**,
    as do `client_identifier` and `parameter_request_list` — RFC 2131 §4.2
    and §4.4.1 require the same values in every subsequent message, and the
    identifier is what the server keys the lease on. Returns `None` (with a
    warning) if the OFFER carries no `SERVER_IDENTIFIER`, since a SELECTING
    REQUEST must echo it (§4.3.2).
  - `.next_reply(timeout=None) -> tuple[DhcpMessage, RequestContext] | None`
    / `.drain_replies() -> list[...]` — pull queued BOOTREPLY messages.
  - `.on_reply(msg, context) -> None` — override hook called after a
    BOOTREPLY is accepted and queued (no-op by default).
  - **`MAX_QUEUED_REPLIES`** (class var, 1024) — cap on undrained replies. An
    idle client (nothing sent yet) accepts every BOOTREPLY on the segment, so
    that `start()` + `.on_reply()` works as an observer; past the cap the
    oldest is discarded and counted in `metrics.replies_dropped_overflow`.

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
the xid was never observed by this relay instance. That map is bounded at
`DhcpRelay.MAX_PENDING_CLIENTS` (1024) entries, oldest evicted first, so xids
whose replies never arrive cannot grow it without limit; an evicted entry only
costs the port-68 fallback, which is where a real client listens anyway. Raise
the class attribute if a deployment genuinely has more than 1024 exchanges in
flight at once.

## Capture (`capture.py`)

- **`DhcpCapture(listen=None, packet_filter=None, sink=None, hook=None,
  hook_fail_fast=False, select_timeout=None, max_packet_size=None,
  per_interface=None)`** (`DhcpListener` subclass) — `packet_filter` is
  either a filter-expression string (compiled via `compile_capture_filter`)
  or a `Callable[[CaptureEvent], bool]`; `sink` gets every accepted event;
  `hook` also gets every accepted event but exceptions are only logged
  unless `hook_fail_fast=True`, in which case the failure is re-raised, stored
  on `self.hook_error` and the receive loop is stopped. Check `hook_error`
  after `listen()` returns to tell a hook failure from an ordinary shutdown --
  re-raising alone does not reach the caller, because `handle()` runs inside
  the listener's per-packet exception handler. `self.accepted_count` tracks
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
  `.reset() -> None` zeroes all counters; `.snapshot() -> dict[str, int]`
  returns a plain dict copy.
  - **`DhcpMetrics.FIELDS`** (class var) — the counter names, in snapshot
    order, and the single source `__init__`/`.reset()`/`.snapshot()` all read.
    Add a counter here and it is initialised, reset and reported; the three
    used to repeat the list, which is how one gets incremented but never
    reported.
  - Today: `packets_received`, `packets_sent`, `leases_allocated`,
    `leases_renewed`, `leases_released`, `packets_dropped_hop_limit`,
    `packets_dropped_untrusted`, `replies_dropped_overflow`.

## Constants (`constants.py`)

Not re-exported from the top-level package — import from `pydhcp.constants`.

- **`BOOTP_MIN_PACKET_SIZE`** (300) — the minimal BOOTP message (RFC 951's
  fixed header plus its 64-octet vend field). `DhcpMessage.encode()` pads to
  it: RFC 1542 §2.1 has a relay agent check a datagram can hold this and
  "silently discard" it otherwise, so a shorter message is droppable, not
  merely unusual.
- **`DHCP_MIN_LEGAL_PACKET_SIZE`** (576) — the smallest message every client
  must accept (RFC 2131 §2), and `encode()`'s default `max_packetsize`.
  Exceeding it needs the client's option 57 (`MAXIMUM_DHCP_MESSAGE_SIZE`);
  `DhcpRelay._encode_for_forward` reads that option rather than shrinking a
  reply it is only forwarding.
- **`UDP_MIN_PACKET_SIZE`** (28) — IPv4 + UDP headers, subtracted from a
  message-size limit to get the DHCP payload budget.
- **`UDP_MAX_PACKET_SIZE`** (65535) — the listeners' default
  `max_packet_size`.
- **`INFINITE_LEASE_TIME`** (`0xFFFFFFFF`) — RFC 2131's "infinite" lease.
- **`MISSING`** / **`Missing`** — sentinel for "argument not supplied", where
  `None` is a meaningful value.

## NVT text (`nvt.py`)

The fields RFC 2131/2132 call NVT ASCII — `sname`, `file`, and the `String`
options — carry other encodings in practice. Three helpers keep such a value
lossless on the wire and safe on a screen; use them rather than calling
`bytes.decode`/`str.encode` on these fields directly.

- **`decode(raw: bytes, what="text") -> str`** — UTF-8, with undecodable octets
  preserved via `surrogateescape` (logged once, naming `what`). Replacing them
  meant a relay forwarded a *different* boot filename than it received.
- **`encode(text: str) -> bytes`** — restores those octets exactly. Valid UTF-8
  is unaffected in both directions.
- **`display(text: str) -> str`** — the lossy step, at the boundary where a
  value is shown rather than parsed: surrogates become U+FFFD, so the result is
  safe for a terminal, a log, or a strict serializer.

**Gotcha**: a string from `decode()` may hold surrogates, so
`str.encode("utf-8")` on it raises and `json.dumps(..., ensure_ascii=False)`
fails at write time. Anything rendering one must call `display()` first —
`DhcpMessage.dumps()`, `.to_mapping()` and `String.__json__()` already do.

## Config loading (`config.py`)

- **`load_config(filepath: str) -> dict[str, Any]`** — dispatches on the
  file extension: `.ini` (via `configparser`, one dict per section), `.yaml`/
  `.yml`, `.toml` (raises `NotImplementedError` with an actionable message on
  Python <3.11 without `tomli` installed), else JSON. Used by the `server`/
  `relay` CLI subcommands' `--config` flag.

## CLI (`cli.py`)

Built on [`duho`](https://pypi.org/project/duho/) (a declarative CLI
framework: `duho.Cli`/`duho.Cmd` classes with annotated fields instead of
hand-built `argparse`). Each subcommand is a `Cmd` subclass — a data class of
CLI fields plus a `__call__(self)` entrypoint — registered on the root
`App(Cli)`'s `_subcommands_`. Every subcommand mixes in `duho.LoggingArgs`
for logging (`-v`/`-q`/`--loglevel`, `self._logger_`); there is no
per-subcommand `--log-level` flag anymore (superseded by duho's verbosity
scheme). Every subcommand derives from an internal `_Command` base that sets
`_logger_name_ = "pydhcp"`, so `self._logger_` resolves the same `pydhcp`
logger the library itself writes to via `pydhcp.log.LOGGER`, and `-v`/`-q`
change that logger's level. The attribute has to live on the subcommand: duho
resolves the logger on the *parsed* instance, so setting it only on `App` left
`-v` raising the level of a logger named after the subcommand while `pydhcp`
stayed at the root level and the library's output never appeared.

- **`main() -> None`** — the `pydhcp` console-script entry point
  (`[project.scripts]` in `pyproject.toml`); calls `duho.main(App)`. Subcommands:
  `interfaces`, `server` (`--config`, `--listen`), `relay` (`--listen`,
  `--server` repeatable, `--max-hops`, `--insert-relay-agent-info`,
  `--circuit-id`, `--remote-id`), `packet` (`--decode`/`--encode` mutually
  exclusive+required, `--input`/`--output` accepting `-` for stdio, `--format
  json|yaml|toml|ini|summary`), `capture` (`--listen`, `--filter`,
  `--format`, `--output` file/pattern/`-`, `--output-mode
  stream|single|per-capture`, `--count`, `--hook` `module:function` or an
  executable path, `--hook-fail-fast`, `--per-interface`). Also gets
  `--version` (via `App._version_ = duho.AUTO`, resolved from installed
  package metadata) for free. Not designed to be imported and called with
  custom `argv` — it parses `sys.argv` directly.
- `Relay.server` has no CLI-level `required=True`: an empty/omitted
  `--server` simply reaches `DhcpRelay(...)`, which already raises
  `ValueError("DhcpRelay requires at least one server address")` — no need
  to duplicate that validation at the argparse layer.

**Gotchas (duho field declarations, Python 3.9 target)**:
- A **class-body field annotation** (not a bare function annotation) is
  resolved by duho via `typing.get_type_hints` at parser-build time — even
  when quoted as a string (`"str | None"`) and even under `from __future__
  import annotations`. On Python 3.9 the PEP 604 `X | Y` syntax fails there
  (`TypeError: unsupported operand type(s) for |`) because `get_type_hints`
  actually evaluates the string. Use `typing.Optional[str]` (or
  `typing.Union[...]`) for any optional CLI field instead of `str | None`.
  Plain function signatures elsewhere in the module are unaffected since
  duho never introspects those.
- The **trailing flags tuple** after a field's docstring (e.g. `("--foo",)`)
  is parsed via `ast.literal_eval` on the class's *source* — it must be a
  literal (strings/numbers/tuples), never a call like `Meta(...)` or
  `NS(...)`. Putting a call in that tuple silently drops the entire
  metadata run for that field (including the flags!) rather than erroring,
  because `_class_constants` treats a non-literal expression as "end of this
  field's metadata" and resets attribution. Any option that needs `Meta(...)`
  (`choices=`, `conflicts=`, `required=`, `dest=` overrides, etc.) belongs in
  `typing.Annotated[T, Meta(...)]` on the annotation itself, not in the
  flags tuple.
- `Meta(dest=...)` is a declared `Meta` field but is **not** read by duho's
  `ArgumentBuilder._kwargs()` — that method always recomputes
  `dest = self.name` and only a raw-escape-hatch `kwargs={...}` override
  (`Meta(kwargs={"dest": "mode"})`) actually reaches `add_argument`. Needed
  for `Packet.decode`/`Packet.encode`: two `store_const` bool fields sharing
  one parsed attribute (`self.mode`) via a `conflicts=`-grouped
  mutually-exclusive pair, the flags-shape `packet --decode`/`--encode`
  requires.
- `App._help_formatter_ = duho.DefaultsFormatter` auto-appends `(default: X)`
  to `--help` output for any option whose default isn't `None`/`""`/`False`
  (skips the noise of an unset optional or an off `store_true` flag) — don't
  hand-write "(default: ...)" in a field's docstring, it's redundant and can
  drift out of sync with the real default.
- Capture's newline-delimited JSON stream output (`--format json` in
  `stream`/`single` mode) is compact JSON by design (one object per line);
  use `dump_message(..., "json")` directly only for single structured packet
  files where pretty JSON is acceptable.
