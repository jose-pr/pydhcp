# `pydhcp` — public API header

Header-file-style reference for the top-level `pydhcp` package: every
`pydhcp/__init__.py` export with its signature, arguments, contract, and
gotchas, so this module can be consumed without reading its source. For the
project overview, install, and CLI, see <https://github.com/jose-pr/pydhcp>. The
`network`, `options`, and `packet` subpackages have their own headers
(`src/pydhcp/{network,options,packet}/AGENTS.md`).

**`pydhcp/__init__.py` re-exports much of those subpackages, but not all of
them** — the previous wording said "everything", and 17 documented or
subpackage names are not importable from `pydhcp`, among them `DhcpMetrics`,
`ListenSpec`, `load_config`, `main`, `DhcpMessageType`, `DhcpPort`, `Flags`,
`HardwareAddressType`, `OpCode`, `host_ip_interfaces` and `WILDCARD_IPv4`.
`from pydhcp import DhcpMessage` works; `from pydhcp import DhcpMessageType`
does not. Import from the owning module when a name is not in `__all__`
(82 names today).

**Name collision, worth knowing before you annotate anything**:
`pydhcp.IPv4Address` is the option **codec** (`pydhcp.options.type.net`), not
`ipaddress.IPv4Address`. The codec subclasses the stdlib type, so
`isinstance(codec_value, ipaddress.IPv4Address)` is True — but the direction
you actually write, `isinstance(interface.ip, pydhcp.IPv4Address)`, is
**False**. The stdlib type is re-exported as **`pydhcp.IPv4`**. `List`,
`String`, `Bytes`, `Boolean` and `U8`/`U16`/`U32` are codecs too, and shadow
builtins and `typing` names under `from pydhcp import *`.

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
  - **Wildcard expansion uses the APIPA-filtered address list.** `"*"` without
    `IP_PKTINFO` becomes one socket per `host_ip_interfaces()` address, which
    excludes 169.254/16: binding is *selection* (which addresses this process
    answers on), not *resolution* (which interface a datagram arrived on, which
    uses `filter=False`). A link-local address means DHCP did not answer —
    RFC 3927 §1.5 does not assign those by DHCP. Name one explicitly in
    `listen` to bind it anyway.
  - **`REUSE_ADDRESS`** (class var, `False`) — whether to set `SO_REUSEADDR`.
    Off, because a second listener binding a port the first already holds then
    *succeeds silently* and receives nothing while the first gets every
    datagram (Windows, and Linux for UDP when both sockets set it). On Windows
    the default bind sets `SO_EXCLUSIVEADDRUSE` instead, without which a later
    `SO_REUSEADDR` socket can still take the address. A class attribute, so
    every subclass inherits it and a subclass or instance can opt back in.
  - `.bind() -> None` — open/refresh sockets for `self._listen`; raises
    `PermissionError` for privileged ports (<1024 without rights) and
    `OSError` for `EADDRINUSE`, both with an actionable message. **Idempotent,
    port 0 included**: an open socket is matched against the address it was
    *asked* for, so a re-bind keeps the ephemeral port it already has rather
    than closing that socket and taking a new port. A Windows `WSAEACCES` is
    reported as in-use, not as a privilege problem — that platform has no
    privileged ports, and the address is simply held exclusively elsewhere.
  - `.listen() -> None` — blocking receive loop; decodes each datagram,
    resolves the receiving `NetworkInterface`, builds a `RequestContext`, and
    calls `self.handle(msg, context)`. Receive, decode and `handle()` failures
    are caught and reported separately (never `KeyboardInterrupt`) so one bad
    packet never kills the loop; only the `handle()` one carries a traceback.
    A datagram larger than `max_packet_size` is **dropped, not decoded from its
    truncated half**. The loop rechecks the cancellation token between sockets,
    so a handler that calls `.stop()` is not called again for the rest of the
    ready set. **`.listen()` closes the sockets on its way out**, so `.stop()`
    plus joining the thread actually releases the ports.
  - `.start(cancellation_token=None) -> Thread | None` — runs `.listen()` on a
    **daemon** thread named `pydhcp-listener` (nothing in the loop ends by
    itself, so a non-daemon one meant a process that forgot to stop never
    exited) and installs a `SIGINT` handler that calls `.stop()`; returns
    `None` if already started. That handler is given back by `.close()` **on
    the main thread only** — `signal.signal` raises anywhere else, so the
    receive thread's own teardown deliberately leaves it installed for a later
    `.close()` to restore.
  - `.stop() -> None` / `.wait() -> None` — signal and block on the
    cancellation `threading.Event`. `.stop()` only asks the loop to exit; the
    close happens on the receive thread, up to `select_timeout` later.
  - **`.bound_addresses -> tuple[SocketAddress, ...]`** — what this listener is
    actually bound to, read from the sockets rather than from the requested
    spec. Empty before `.bind()` and after `.close()` — and after `.stop()`
    *once the receive loop has actually exited*, which is why a caller that
    cares should join the thread `.start()` returned. This is how a caller that
    passed port 0 learns the ephemeral port it was given.
  - **`.packets_dropped_truncated`** / **`.packets_dropped_error`** (ints) —
    datagrams that did not fit `max_packet_size`, and datagrams lost to an
    error anywhere in receive/decode/handle. Plain attributes on the listener,
    not `DhcpMetrics` fields, so `.snapshot()` does not report them.
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
  - **`.stop()` is safe to call from a handler**, which runs on the worker
    thread rather than on the loop: it hands the close back to the loop with
    `call_soon_threadsafe` instead of running it inline. Nothing it touches is
    thread-safe — `remove_reader`, `transport.close()` and `Event.set()` all
    finish through `loop.call_soon`, which queues a callback *without* waking
    the loop. Measured with a handler calling `stop()` on its worker: Linux's
    selector loop never woke and `await wait()` blocked forever, while
    Windows' proactor loop returned in 7 ms. The close is therefore not
    synchronous when called this way — `bound_addresses` empties on the loop's
    next turn, not before `stop()` returns.
  - Handlers run on a single worker thread, not on the event loop: `.handle()`
    is ordinary blocking code, so running it inline stalled every other
    coroutine in the host application. One worker, so handlers still run one
    at a time and in arrival order — which is also what keeps a caller's
    compound lease operation ("free? then allocate") atomic, since the
    backend's own lock does not span two calls.
  - `.bound_addresses`, `.REUSE_ADDRESS`, `.packets_dropped_truncated` and
    `.packets_dropped_error` — as on `DhcpListener`, including the oversized
    -datagram drop.
  - `await .wait() -> None` — returns when `.stop()` is called; returns
    immediately if never started. `.listen()` raises `NotImplementedError`
    (there is no blocking loop to enter — use `start()` then `wait()`).
  - On loops without socket readability (Windows' default proactor loop) it
    falls back to a `DatagramProtocol` endpoint per socket. That path cannot
    carry `IP_PKTINFO`, which is absent on those platforms anyway.
- **`Transport`** — abstract `.send(data, dest: IPv4, port: int, client_mac:
  bytes) -> int`; base raises `NotImplementedError`.
- **`UdpTransport(socket)`** — plain UDP send. A destination of `0.0.0.0`
  ("this client has no address yet") is sent to `255.255.255.255`, per
  RFC 2131 §4.1. A failed **unicast** retries as a broadcast (logged as a
  warning); a failed **broadcast** raises, since the retry would be the
  identical syscall.
  - **Caveat**: that retry does not know whether broadcast was an acceptable
    delivery for this particular reply. It is right for a client with no
    address yet and wrong for one the server deliberately unicast to (a
    RENEWING client at its own `ciaddr`, a relay at `giaddr`), where it puts
    the reply's `yiaddr`, `chaddr`, lease options and echoed
    `RELAY_AGENT_INFORMATION` in front of the whole segment. Deciding this
    properly needs a signal from the caller that `Transport.send` does not
    currently carry.
- **`PktInfoUdpTransport(socket)`** — POSIX `IP_PKTINFO`-aware transport for
  wildcard sockets. Falls back to `UdpTransport.send` when `ifindex`/
  `local_ip` aren't set or the platform lacks `sendmsg`/`IP_PKTINFO`. If the
  pinned `sendmsg` itself **fails** (a stale `ifindex`, a `local_ip` no longer
  on that adapter) it retries once, unpinned, **to the same destination** — it
  does not go through `UdpTransport.send`, so a failed unicast is never
  escalated into a broadcast here; the error propagates instead.
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
    `None` when nothing can be allocated (silently drops the message), which
    includes any address outside the served network — so a relayed client on
    another subnet is refused rather than answered with values that do not
    apply there.
    - **Default options: `SUBNET_MASK` and `BROADCAST_ADDRESS` only**, both
      taken from the receiving interface. It deliberately does **not** send
      `ROUTER` or `DNS`: this host is not known to route or resolve, and
      naming it as both told clients to send off-link traffic and name lookups
      into a black hole. Supply the real ones by overriding this method.
  - `.lease_seconds(msg) -> float` — how long a lease to grant, applying this
    server's policy to the client's requested time. RFC 2131 §4.3.1 honours
    that request only "if acceptable to local policy", so it is clamped to
    `[MIN_LEASE_SECONDS, MAX_LEASE_SECONDS]` (60 s … 1 day), defaulting to
    `DEFAULT_LEASE_SECONDS` (1 h) when the client asks for none. The
    RFC 2132 §3.3 infinity sentinel (`0xFFFFFFFF`) yields `math.inf` when
    **`ALLOW_INFINITE_LEASE`** is set, and the maximum when it is not — never
    a finite 136-year lease. Override the method or the four attributes; this
    is the base allocator's policy only, so an `.acquire_lease()` override
    that builds its own lease is unaffected.
  - `.release_lease(client_id, server_id, msg) -> bool` — override point,
    releases via the lease backend; returns whether a binding actually went
    away. It does **not** touch metrics: an orderly `DHCPRELEASE`, a
    `DHCPDECLINE` reporting an address conflict, and a reclaim after the client
    chose another server all arrive here, and only the caller knows which, so
    the caller counts. An override that wants the counters moved should return
    the bool faithfully rather than incrementing anything itself.
  - `.handle_release()` releases only when the binding matches: RFC 2131 §4.4.6
    puts the address being given up in `ciaddr`, and a `DHCPRELEASE` naming a
    *different* address than the client holds is ignored and counted in
    `releases_ignored`. Releasing on client identifier alone let a late or
    duplicated RELEASE for an old address delete the client's current binding.
  - `.get_inform_options(server_id, msg) -> DhcpOptions` — override point for
    DHCPINFORM-only option sets (no address allocated). Same default set, and
    the same omission of `ROUTER`/`DNS`, as `.acquire_lease()`.
  - **"Which host interface holds `server_id`" is memoised until the next
    `.bind()`.** Both the allocating path and the DHCPINFORM path need it, and
    both enumerated every host adapter per packet — 1181 µs of a 1539 µs
    `handle()` on one measured box, now 148 µs. The consequence to know: an
    address this host gains or loses **without re-binding** is not noticed,
    exactly as for the listener's own interface-resolution cache.
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
    fresh `UdpTransport`, and tracks the message's `(xid, chaddr)` in
    `self._pending_keys` so `.handle()` only queues matching replies. A reply
    carrying a seen `xid` but another client's `chaddr` is ignored — the xid
    is in cleartext in a broadcast DISCOVER, so anyone on the segment can
    read one (same key as `DhcpRelay._pending_key`).
  - `.discover_offer(chaddr, *, timeout=2.0, retries=2, destination=...,
    port=..., **discover_kwargs) -> DhcpMessage | None` — broadcasts
    DHCPDISCOVER (with retries) and returns the first DHCPOFFER, or `None`.
    **`timeout` is the *initial* retransmission interval, not a fixed one**:
    each retransmission waits roughly twice as long as the last, randomized,
    capped at `RETRANSMIT_MAX_INTERVAL` (RFC 2131 §4.1). With the defaults the
    call is bounded at about 2+4+8 s rather than 3×2 s. Each transmission
    carries a real `secs` — seconds since the exchange began (§2) — which was
    previously hardcoded to 0.
  - `.dora(chaddr, *, timeout=2.0, retries=2, destination=..., port=...,
    broadcast=True, **discover_kwargs) -> DhcpMessage | None` — full
    DISCOVER→OFFER→REQUEST→ACK exchange; returns the DHCPACK or `None`.
    **`broadcast` forwards to both the DISCOVER and the follow-up REQUEST**,
    as do `client_identifier` and `parameter_request_list` — RFC 2131 §4.2
    and §4.4.1 require the same values in every subsequent message, and the
    identifier is what the server keys the lease on. Returns `None` (with a
    warning) if the OFFER carries no `SERVER_IDENTIFIER`, since a SELECTING
    REQUEST must echo it (§4.3.2). `secs` counts from the DISCOVER across both
    halves — §2 defines it as time since *acquisition* began, so the REQUEST
    does not restart the clock.
  - `.next_reply(timeout=None) -> tuple[DhcpMessage, RequestContext] | None`
    / `.drain_replies() -> list[...]` — pull queued BOOTREPLY messages.
    A reply belonging to an exchange currently running in
    `.discover_offer()`/`.dora()` goes to that exchange and does **not** reach
    these; everything else accepted does. That routing is what lets two
    exchanges with different `chaddr`s run concurrently on one client without
    consuming each other's replies.
  - `.on_reply(msg, context) -> None` — override hook called after a
    BOOTREPLY is accepted and queued (no-op by default).
  - **`MAX_QUEUED_REPLIES`** (class var, 1024) — cap on undrained replies. An
    idle client (nothing sent yet) accepts every BOOTREPLY on the segment, so
    that `start()` + `.on_reply()` works as an observer; past the cap the
    oldest is discarded and counted in `metrics.replies_dropped_overflow`.
  - **`RETRANSMIT_MAX_INTERVAL`** (64.0) and
    **`RETRANSMIT_JITTER_SECONDS`** (1.0), class vars — RFC 2131 §4.1's ceiling
    and randomization amplitude. The jitter is the smaller of this and a
    quarter of the interval, so a sub-second `timeout` in a test cannot be
    jittered negative.

**Gotcha**: `.dora()`/`.discover_offer()` require the listener's receive loop
to actually be running (`client.start()`) — replies only reach the internal
queue via `.handle()`, which the background thread calls. A `DhcpClient`
that's never started will always time out waiting for a reply.

## Relay (`relay.py`)

- **`DhcpRelay(listen=None, server_addresses=(), max_hops=4,
  insert_relay_agent_info=False, circuit_id=None, remote_id=None,
  select_timeout=None, max_packet_size=None, per_interface=None)`**
  (`DhcpListener` subclass) — RFC 1542 / RFC 2131 §4.1 / RFC 3046 relay
  agent. `server_addresses` is required and non-empty (each entry an `IPv4`,
  a string, or a `(host, port)` tuple; bare entries default to port 67) —
  raises `ValueError` otherwise. `insert_relay_agent_info=True` adds option
  82 with `circuit_id`/`remote_id` sub-options (skipped, with a warning, if
  the request already carries one). **`max_hops` defaults to 4**, the RFC 1542
  §4.1.1 default, and must be 0..16 -- that clause's hard ceiling -- or the
  constructor raises `ValueError`. It was previously 16: the ceiling used as
  though it were the default.
  - `.handle(msg, context) -> None` — forwards `BOOTREQUEST` to every
    configured server (stamping `giaddr` and incrementing `hops`; drops and
    counts in `metrics.packets_dropped_hop_limit` when the *received* `hops`
    exceeds `max_hops`, so a request at exactly the threshold is still
    forwarded -- RFC 1542 §4.1.1) and
    forwards `BOOTREPLY` back to the original client.

- **`AsyncDhcpRelay(listen=None, server_addresses=(), max_hops=4,
  insert_relay_agent_info=False, circuit_id=None, remote_id=None,
  trust_client_relay_agent_info=False, max_packet_size=None,
  per_interface=None)`** — the same forwarding policy running on
  `AsyncDhcpListener`, the way `AsyncDhcpServer` relates to `DhcpServer`.
  `isinstance(x, DhcpRelay)` holds. Identical arguments minus `select_timeout`
  (the sync receive loop's poll interval, which asyncio has no use for), and
  both constructors share `_init_relay_state()`, so the `server_addresses` and
  `max_hops` validation cannot be enforced on one and not the other. Drive it
  with `await .start()` / `await .wait()` / `.stop()`.
  - `_pending_clients` is unguarded on both. What keeps it safe here is that
    `AsyncDhcpListener` runs handlers on **one** worker thread, so `handle()`
    is still serialised and in arrival order — the same guarantee the lease
    backends rely on. A handler pool would make this a data race.

- **`ServerAddress`** (`pydhcp.relay`, not re-exported from the top level) —
  the type of each `server_addresses` entry: `IPv4 | str | tuple[IPv4 | str,
  int]`. A bare entry defaults to port 67.

**Gotcha**: a relay reply must not assume the client listens on well-known
port 68 — DHCPOFFER/ACK never carries the original client's UDP source port.
`DhcpRelay` tracks `(xid, chaddr) -> PendingClient` in `self._pending_clients`,
recorded on forward and read on reply, so clients on non-standard ports still
get routed correctly; it falls back to port 68 when the exchange was never
observed by this relay instance.

- **Keyed by client as well as transaction.** An xid alone is not an identity:
  it is cleartext in a broadcast DISCOVER, so any host on the segment can read
  one and send its own request carrying it. Keyed by xid alone that overwrote
  the victim's entry and the reply went to the attacker's port. An entry is
  also never replaced by a request from a *different* source address.
- **Read, not consumed.** Every configured server sends its own reply, and they
  all belong to the same client, so the entry stays until
  `DhcpRelay.PENDING_TTL_SECONDS` (60) rather than being popped by whichever
  arrives first.
- **The entry is not only a port.** It also carries the ingress interface
  (`ifindex`/`local_ip`), which is what pins the reply back onto the client's
  segment on a wildcard bind — so a client on port 68 is recorded too, even
  though its port needs no lookup.
- Bounded at `DhcpRelay.MAX_PENDING_CLIENTS` (1024), oldest evicted first, so
  exchanges whose replies never arrive cannot grow it without limit. An evicted
  entry costs the port-68 fallback and the interface pin. Raise either class
  attribute for a deployment with more exchanges genuinely in flight.

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
  `{format}` placeholders (each value filesystem-sanitized). It is called per
  packet, from inside the receive handler — check the pattern once at startup
  with `validate_filename_pattern` rather than letting it raise there.
- **`FILENAME_FIELDS`** — the five names above, in order; the only placeholders
  `format_filename` can fill.
- **`UNIQUE_FILENAME_FIELDS`** — `{"timestamp", "xid"}`, the subset that
  differs between two packets of one capture. A pattern naming none of them
  resolves to the same filename for packets that agree on the rest, so each
  record overwrites the last.
- **`validate_filename_pattern(pattern) -> frozenset[str]`** — returns the
  fields `pattern` names; raises `ValueError` for a malformed pattern or a
  placeholder that is not in `FILENAME_FIELDS`. Format specs are fine
  (`{client_id:>12}`), including one level of nesting; positional (`{}`,
  `{0}`) and attribute/index access (`{xid.real}`) are not, because
  `format_filename` formats against a plain dict of the five values. Intersect
  the result with `UNIQUE_FILENAME_FIELDS` to tell whether records will
  overwrite. Not re-exported from the top-level package — import it from
  `pydhcp.capture`.
- **`compile_capture_filter(text) -> Callable[[CaptureEvent], bool]`** —
  `None`/blank → always-true. Otherwise parses `and`-joined `key=value`
  clauses (`or` unsupported, raises `ValueError`). Both keywords are matched
  **case-insensitively**: `AND`/`And` join clauses, `OR`/`Or`/`or` raise.
  Keys: `op`, `msg_type`, `xid` (int, any base), `client_id`, `chaddr`,
  `src`, `src_port`, `dst`, `dst_port`, `interface`, or
  `option.<NAME_OR_CODE>` (compares the option's decoded/enum-name or string
  value). `client_id` and `chaddr` compare as separator-free hex, so
  `00:11:22:33:44:55`, `00-11-22-33-44-55` and `001122334455` are all the same
  filter. Unknown keys **and unparseable values** raise `ValueError` eagerly,
  at compile time: `xid`, `src_port` and `dst_port` must parse as integers and
  `src`/`dst` as IPv4 addresses, so a typo is one startup error instead of one
  per packet — or, for `src`/`dst`, instead of a filter that matches nothing.

**Gotcha**: `CaptureEvent.destination` casts `context.interface.ip` to `IPv4`
to satisfy `SocketAddress`; an IPv6-only interface isn't actually handled
(`NetworkInterface.ip` is `ipaddress.IPv4Address | ipaddress.IPv6Address`
— spelled out because `pydhcp.IPv4Address` is a *different* thing, see the
name-collision note at the top) — capture on an
IPv6-only interface can break at runtime.

- **`AsyncDhcpCapture(listen=None, packet_filter=None, sink=None, hook=None,
  hook_fail_fast=False, max_packet_size=None, per_interface=None)`** — the same
  filter/sink/hook policy running on `AsyncDhcpListener`.
  `isinstance(x, DhcpCapture)` holds. Identical arguments minus
  `select_timeout`, and both constructors share `_init_capture_state()`. Drive
  it with `await .start()` / `await .wait()` / `.stop()` rather than
  `.listen()`, and check `.hook_error` after `.wait()` returns.
  - `accepted_count`, `hook_error` and whatever a `sink` keeps are unguarded on
    both, and the single handler worker is again the whole guarantee — the sink
    runs on it too, so a per-run budget such as the CLI's `--count` needs no
    lock and no library-side state of its own.
  - `hook_fail_fast` stops the capture through `AsyncDhcpListener.stop()`,
    called from that worker thread; see the `.stop()` note under
    `AsyncDhcpListener` for why the close is deferred to the loop and is not
    complete by the time `handle()` re-raises.

- **Type aliases** (`pydhcp.capture`, not re-exported from the top level, so
  import them from the module): **`CaptureSink = Callable[[CaptureEvent],
  None]`**, **`CaptureHook = Callable[[CaptureEvent], None]`**, and
  **`CapturePredicate = Callable[[CaptureEvent], bool]`** — the three callable
  shapes `DhcpCapture`/`AsyncDhcpCapture` accept. A `packet_filter` string is
  compiled to a `CapturePredicate`; passing one directly skips the parser.

## Leases (`lease.py`)

- **`DhcpLease`** (`NamedTuple`) — `ip: IPv4 | None`, `expires: datetime |
  float` (`math.inf` for an infinite lease), `options: DhcpOptions`.
- **`LeaseBackend`** (`Protocol`) — `.allocate(client_id, ip, ttl,
  options=None) -> DhcpLease | None`, `.lookup(client_id) -> DhcpLease |
  None`, `.release(client_id) -> bool`, `.renew(client_id, ttl) -> DhcpLease
  | None`. **`ttl: float`** — seconds, or `math.inf` for an infinite lease.
  It is `float` rather than `int` because that is what `math.inf` is and what
  the implementations have always accepted; an `int` still satisfies it.
- **`InMemoryLeaseBackend()`** — dict-backed reference implementation;
  `.lookup()` evicts (and returns `None` for) expired leases lazily. Each
  method is atomic against the others (an `RLock` on `self._lock`), so one
  backend can be shared by a threaded server and an async one. A **caller's**
  compound operation is not — "is this address free, then allocate it" is two
  calls; hold `self._lock` across such a sequence if it matters.
  - **`MAX_LEASES`** (class var, 10 000) — cap on stored leases. A client
    identifier is unauthenticated, so an unbounded store is an unbounded
    allocation driven from the network. At the cap, expired entries are
    reclaimed and a **new** client is then refused (`.allocate()` returns
    `None`); an established binding is never evicted to make room, since
    least-recently-used would drop the long-lived real clients and keep the
    newest forged ones.
  - **`.refused_while_full`** (int) — how many new clients were turned away
    at the cap. The accompanying warning is rate-limited to one per
    `FULL_LOG_INTERVAL_SECONDS` (60), so a flood cannot also flood the log;
    this counter is the exact figure.
  - `.lookup_by_ip(ip) -> str | None` — who holds an address. An optional
    extension, deliberately **not** on the `LeaseBackend` Protocol: a backend
    without it just skips the allocator's already-in-use check.
- **`FileLeaseBackend(filepath="leases.json")`** (`InMemoryLeaseBackend`
  subclass) — persists to JSON after every allocate/release/renew.
  - Writes are **atomic**: a temporary file in the same directory, renamed
    over the target, so a reader sees the whole file or the previous one and
    an interrupted write cannot truncate it. The rename retries briefly on
    `PermissionError` (on Windows an indexer or antivirus holding the file
    looks exactly like that).
  - A missing file starts empty and says nothing. An **unreadable** one is
    logged at ERROR and moved aside to `<filepath>.corrupt` — it is the only
    copy of that state, so it is kept for recovery rather than overwritten by
    the next save.
  - A save that fails is logged at ERROR and does **not** raise: a lease store
    that cannot be written must not take the server down mid-exchange. So it
    is best-effort persistence — but no longer a silent one.
  - **`SAVE_INTERVAL_SECONDS`** (class var, `0.0`) — `0` writes on every
    mutation, which is the default. Above zero, writes are coalesced to at
    most one per interval; **`.flush()`** forces a pending write and
    **`.close()`** flushes (the backend is also a context manager). Measured
    over 4,000 allocations: 115.76 s at the default, 0.02 s at a one-second
    interval. It is opt-in because it trades up to an interval of leases on a
    crash — which an operator cannot see going wrong — for throughput they
    can already measure and that `MAX_LEASES` already bounds.

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
    `leases_renewed`, `leases_released`, `leases_declined`, `releases_ignored`,
    `packets_dropped_hop_limit`, `packets_dropped_untrusted`,
    `packets_dropped_truncated`, `packets_dropped_error`,
    `replies_dropped_overflow`.
  - `leases_declined` counts `DHCPDECLINE`, which used to land in
    `leases_released` though it means the opposite — the client found the
    address already in use. An address-conflict storm read as orderly
    shutdowns. `releases_ignored` counts releases refused for naming an address
    the client does not hold.

## Constants (`constants.py`)

Not re-exported from the top-level package — import from `pydhcp.constants`.

- **`BOOTP_MIN_PACKET_SIZE`** (300) — the minimal BOOTP message (RFC 951's
  fixed header plus its 64-octet vend field). `DhcpMessage.encode()` pads to
  it: RFC 1542 §2.1 has a relay agent check a datagram can hold this and
  "silently discard" it otherwise, so a shorter message is droppable, not
  merely unusual.
- **`DHCP_MIN_LEGAL_PACKET_SIZE`** (576) — the smallest message every client
  must accept (RFC 2131 §2), and `encode()`'s default `max_packetsize` — its
  default, not its minimum: `encode()` accepts anything from 269 up.
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

## Logging (`log.py`)

- **`LOGGER`** — the package logger, `logging.getLogger("pydhcp")`. Every
  module logs through its own `getLogger(__name__)` child, so an embedder can
  raise or silence one component (`pydhcp.listener`, `pydhcp.server`) without
  touching the others; they all propagate to `pydhcp`.
- The package installs a `NullHandler` on `pydhcp`, per the stdlib guidance for
  libraries. One consequence worth knowing: with logging otherwise
  unconfigured, `logging.lastResort` would print WARNING and above to stderr,
  and a `NullHandler` counts as a handler, so those lines go silent instead.
  Configure a handler to see them. The CLI is unaffected — it installs its own.

## Config loading (`config.py`)

- **`load_config(filepath: str) -> dict[str, Any]`** — dispatches on the
  file extension: `.ini` (via `configparser`, one dict per section), `.yaml`/
  `.yml`, `.toml` (raises `NotImplementedError` with an actionable message on
  Python <3.11 without `tomli` installed), else JSON. Used by the `server`/
  `relay` CLI subcommands' `--config` flag.

## CLI (`cli.py`)

Invoked as **`pydhcp`** (the console script) or **`python -m pydhcp`** — both
reach `cli.main()`, and both report themselves as `pydhcp` in usage and error
lines. The program name comes from `App._parsername_`, not the class name,
which duho would otherwise use.

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
- Each `--server` value is split by **`listener._split_host_port`**, the same
  parser the `--listen` specs go through, and reaches `DhcpRelay` as a
  `(host, port)` tuple with port 67 supplied when the argument names none.
  The CLI used to carry its own splitter, which disagreed with the listener's
  on anything with more than one colon. One difference from `--listen`: an
  empty host is **rejected** here rather than defaulted to `0.0.0.0` — the
  wildcard is a place to listen, not an upstream to forward to. This is not
  IPv6 support: `relay._normalize_server_address` still calls `IPv4()` on
  whatever it receives, so an IPv6 upstream now fails with a clearer message
  rather than a different one.
- **`capture --output-mode per-capture` validates its filename pattern before
  binding**, via `capture.validate_filename_pattern`: an unknown placeholder
  is a startup `ValueError`, and a pattern naming neither `{timestamp}` nor
  `{xid}` gets a warning that records will overwrite each other. Both are
  invisible otherwise — the pattern is expanded per packet inside the receive
  handler, where the listener logs the exception and carries on, so
  `--output "cap_{mac}.json"` recorded nothing while logging once per packet.
  The overwrite case is a **warning, not an error, deliberately** — see
  `MAX_PER_CAPTURE_FILES` next.
- **`MAX_PER_CAPTURE_FILES`** (1000) — how many *distinct* files one
  `per-capture` run may create. The pattern interpolates values the client
  chooses, so without a bound one unauthenticated sender decides how much of
  the operator's disk to use (measured: 5,000 forged identifiers, 5,000
  files). Past the cap, new paths are refused, with the reason logged once.
  Rewriting an already-seen path is always free, which is what leaves a
  pattern the client cannot influence unlimited — so the overwrite case above
  must stay a warning: refusing it, or minting a suffixed new path per packet,
  would make a long run reach the cap and silently stop recording.

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
