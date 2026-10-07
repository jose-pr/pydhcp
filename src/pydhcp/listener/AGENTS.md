# `pydhcp.listener` — public API header

Header-file-style reference for `pydhcp.listener`: the listeners every role is built on, the `listen` forms, the
transports and the request context. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; the top header is
`pydhcp/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

## Listeners (`pydhcp.listener`)

A package split by responsibility into private modules (`_transport`,
`_spec`, `_interfaces`, `_receive`, `_binding`, `_sync`, `_asyncio`); import
everything below from `pydhcp.listener` itself.

```python
DHCPListener(listen=None, *, poll_interval=None, max_packet_size=None, per_interface=None,
    reuse_address=None, receive_buffer_size=None)
DHCPListener.bind() -> None
DHCPListener.serve_forever() -> None
DHCPListener.start() -> None
DHCPListener.shutdown() -> None
DHCPListener.wait_closed(timeout=None) -> bool
DHCPListener.close() -> None
DHCPListener.handle(msg, context) -> None
AsyncDHCPListener(listen=None, *, max_packet_size=None, per_interface=None, reuse_address=None,
    receive_buffer_size=None, max_queued=None)
async AsyncDHCPListener.serve_forever() -> None
AsyncDHCPListener.shutdown() -> None
async AsyncDHCPListener.wait_closed(timeout=None) -> bool
async AsyncDHCPListener.aclose() -> None
```

- **`DHCPListener`** —
  synchronous, thread-based receive loop. **Only `listen` is positional**, on
  every listener and role; the rest are keywords. **A constructor performs no
  I/O**: no socket is opened, no adapter listed and no file read until
  `.bind()` (the packet-info probe and the wildcard expansion included).
  `listen` is **a binding or a sequence of bindings**, read by one parser
  (the constructors, `pydhcp server|relay|capture --listen` and the `listen`
  key of a configuration file). `None` is the wildcard on the default ports. A
  binding is: text — `"host"`, `"host:port"`, `"*"`, `"*:port"`, `":port"`, several
  joined by commas; an `IPv4Address`, or `None` (the wildcard); a
  `netimps.Interface` or `netimps.MACAddress` (an interface, below); or a **pair
  `(host, ports)` as a tuple or a list** (a JSON, YAML or TOML file only has
  lists, so `["127.0.0.1", 6767]` is one binding). In a pair the host is
  `None`, blank text, `"*"`, text, an `IPv4Address`, an `Interface` or a
  `MACAddress`, and the ports are an
  `int`, digit text, `None` (the default ports) or a sequence of those
  (`("127.0.0.1", [6767, 6768])`); the pair is read by
  `netimps.split_host`, so a type, a range (0-65535) and a port written twice
  that disagrees (`("*:67", 68)`) are checked. A sequence of two items is a pair
  when the second is port-like (`None`, an `int`, digit text, a list of those),
  else two bindings (`["127.0.0.1", "127.0.0.2"]`). **`None` as a host is the
  wildcard everywhere**, `(None, 6767)` included. Refused at construction with
  nothing bound: a `bool` or a bare number (`True`, `6767`) as an address or
  a port (`TypeError`), an empty result (`""`, `" , "`, `[]`, a pair with no port;
  `ValueError`), a bad or out-of-range port, and an IPv6 address
  (`ipaddress.AddressValueError`). **Any wildcard spelling** — `"*"`, `"0.0.0.0"`,
  `"*:67"`, `"0.0.0.0:67"`, `("0.0.0.0", 67)` — binds one wildcard socket and
  learns each datagram's arrival interface through `netimps.UDPEndpoint`
  (packet info), on Linux, macOS and Windows and on every supported CPython.
  `poll_interval` (seconds, default 1) is how often a wait for a datagram looks
  at the shutdown flag again; `.shutdown()` wakes it at once, so it matters only
  where Windows delivers Ctrl-C between waits. `max_packet_size`
  defaults to `UDP_MAX_PACKET_SIZE` (65535). `per_interface=True` disables
  wildcard routing and binds one socket per interface address instead.
  **A socket bound to an address hears no broadcast on Linux** (measured: 0 of
  3 limited and 0 of 3 subnet broadcasts, against 3 of 3 for the wildcard;
  macOS and the BSDs are expected to match, unmeasured; Windows delivers it),
  so `per_interface=True` and any `listen` naming a non-loopback address serve
  only unicast there, and an unconfigured client is served through the
  wildcard alone. `.bind()` logs a WARNING once per process when it binds such
  an address. Every instance
  owns `self.metrics: DHCPMetrics` — there is no global metrics singleton.
  - **Listening on an interface.** Text that is not an IPv4 address names an
    interface, read in this order so that no name is looked up as a host name (a
    host name is **never resolved**): the wildcard forms; an IPv4 address; a MAC
    in any spelling (`aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`,
    `aa.bb.cc.dd.ee.ff`, `aabbccddeeff`); otherwise an adapter name (`eth1`,
    `Wi-Fi 2`, `eth0.100`). So `"eth1"` and `"localhost"` are both adapters, and an
    adapter whose name is also an address or a MAC is given as a
    `netimps.Interface`. The port follows the last colon (`"eth1:67"`,
    `"aa-bb-cc-dd-ee-ff:67"`), so `eth0:1` is `eth0` on port 1: the colon spelling
    of a MAC takes its port in a pair (`("aa:bb:cc:dd:ee:ff", 67)`) and an adapter
    name that holds a colon is given as an `Interface`. A `/` in a name is
    refused. **The adapter is looked up by `.bind()`**, not by the constructor
    (`netimps.iter_interfaces`: a name names one adapter, a MAC every adapter
    carrying it, an `Interface` itself); one that matches nothing raises
    `ValueError` ("no interface matches ...") with nothing bound. The listener
    binds **one wildcard socket** (so a broadcast is heard) and **drops, before
    decoding, a datagram that arrived on another interface**, counting it in
    `metrics.packets_dropped_other_interface` (and writing a DEBUG line through
    the log limit). **On Linux** (`netimps.has_device_binding()`) a socket that
    serves exactly one adapter is also **bound to that device**, so the kernel
    delivers nothing from another interface, a broadcast included, and the count
    stays 0 in normal operation; the drop stays as a second check. Elsewhere
    (Windows, macOS, FreeBSD have no such option) the drop is the whole limit.
    A socket serving several adapters (a MAC several carry, or several
    interfaces on one port) is limited by the drop alone. If the kernel refuses
    the device (`DeviceBindingUnsupportedError`, or `PermissionError` where the
    option needs a capability) the socket is bound without it and one WARNING
    says so through the log limit: the listener then behaves as it does
    elsewhere. The class attribute `USE_DEVICE_BINDING = False` forces the drop
    alone. Several interfaces on one port share the socket; naming the
    wildcard plainly on that port (`"*:67"`, `"0.0.0.0:67"`) takes precedence and
    removes the limit. It needs packet info (`ValueError` at `.bind()` where the
    socket reports none) and cannot be combined with `per_interface=True`
    (`ValueError` at construction). Every listener, role and the client take it.
  - **`host:port` text is read strictly** (netimps' `split_host`): the port is
    ASCII digits only, and square brackets may enclose only an IPv6 literal.
    `"127.0.0.1:+6767"`, `"127.0.0.1: 6767"`, `"127.0.0.1:8_0"` and
    `"[127.0.0.1]:6767"` raise `ValueError` (netimps' `NetimpsValueError`),
    the message naming the port or the brackets. The same rule applies to
    each `--listen` and `--server` value. A host name is not an address:
    `listen` takes IPv4 addresses and interfaces, a name is read as an adapter name
    and never resolved, and IPv6 raises `ipaddress.AddressValueError`.
  - **Wildcard expansion uses the APIPA-filtered address list.** A wildcard on
    a platform without packet info (or with `per_interface=True`) becomes one
    socket per `host_ip_interfaces()` address, read when `.bind()` runs and not when the listener is constructed, which
    excludes 169.254/16: binding is *selection* (which addresses this process
    answers on), not *resolution* (which interface a datagram arrived on, which
    uses `filter=False`). A link-local address means DHCP did not answer —
    RFC 3927 §1.5 does not assign those by DHCP. Name one explicitly in
    `listen` to bind it anyway.
  - **`REUSE_ADDRESS`** (class var, `False`) — whether a listener may share or
    take over its port (`netimps.bind(allow_address_takeover=True)`, i.e.
    `SO_REUSEADDR`). Off, because a second listener binding a port the first
    already holds then *succeeds silently* and receives nothing while the first
    gets every datagram. With it off the bind is exclusive on every platform
    (`SO_EXCLUSIVEADDRUSE` on Windows, where a more specific `SO_REUSEADDR`
    bind could otherwise take the traffic). The constructor's `reuse_address`
    (default `None`) overrides it for one instance; `None` takes this class
    attribute, which a subclass can set.
  - **`RECEIVE_BUFFER_SIZE`** (class var, `1 << 20`) — the receive buffer
    asked of the OS for every listening socket; `0` keeps the OS default. The
    constructor's `receive_buffer_size` overrides it for one instance.
    A segment powering up sends its DISCOVERs together: Windows' 64 KiB
    default holds about 220 typical datagrams, and a 1000-datagram burst delivers 220 at the default and all 1000 at 1 MiB (measured). The kernel may
    grant less (Linux caps at `net.core.rmem_max`); a shortfall is logged at
    INFO by pydhcp, naming the address, and by netimps at WARNING (once per
    process for each distinct request and grant). A failure to grow is logged at
    WARNING, never raised.
  - **`DEFAULT_PORTS`** (class attribute) — the ports a binding with no port
    of its own binds, the wildcard (`None`) included: `(67, 68)` on the two
    listeners and on `DHCPCapture`/`AsyncDHCPCapture`, `(67,)` on the servers
    and the relays, `(68,)` on the clients. A subclass sets its own.
  - **`.bind()`** — open/refresh sockets for `self._listen`; raises
    `PermissionError` for privileged ports (<1024 without rights) and
    **`netimps.AddressInUseError`** (an `OSError`, never a `PermissionError`)
    when the port is taken — including a Windows `WSAEACCES` against an
    exclusive holder, since that platform has no privileged ports — both with
    an actionable message. **Idempotent, port 0 included**: an open socket is
    matched against the address it was *asked* for, so a re-bind keeps the
    ephemeral port it already has rather than closing that socket and taking a
    new port. Sockets are bound with `connreset=False`, so on Windows an ICMP
    error from an earlier reply does not surface on a later receive.
  - **Lifecycle** — one state machine on the thread-based listener and on every
    role built on it (`DHCPServer`, `DHCPRelay`, `DHCPCapture`, `DHCPClient`):
    - **`.serve_forever()`** — binds, then receives on the **calling**
      thread until `.shutdown()`. Decodes each datagram, resolves the receiving
      `NetworkInterface`, builds a `DHCPRequestContext` and calls
      `self.handle(msg, context)`. Receive, decode and `handle()` failures are
      caught and reported separately (never `KeyboardInterrupt`) so one bad
      packet never kills the loop; only the `handle()` one carries a traceback.
      A datagram larger than `max_packet_size` is **dropped, not decoded from
      its truncated half**. The loop rechecks for shutdown between sockets, so a
      handler that calls `.shutdown()` is not called again for the rest of the
      ready set. The sockets stay open on return: `.close()` releases them.
      Raises what `.bind()` raised, and `RuntimeError` when already serving or
      closed.
    - **`.start()`** — **binds on the caller's thread**, then runs the same
      loop on a **daemon** thread named `pydhcp-listener` (nothing in the loop ends by itself, so a non-daemon thread would keep a process that forgot to close alive). An address that cannot be bound raises what `.bind()`
      raised (`AddressInUseError`, `PermissionError`, ...) out of `.start()`,
      with nothing bound and the listener unstarted. `RuntimeError` when
      already serving or closed: a second `.start()` is an error, never a second
      thread. `.bind()` itself, when it fails partway, closes the sockets that
      call opened and keeps the ones an earlier call bound.
    - **`.shutdown()`** — asks the loop to end. **Never blocks and is safe
      from any thread and from a handler**; a wake-up socket ends the wait at
      once, so it does not wait for a poll. A no-op when nothing is serving.
      Shut down is not closed: `.serve_forever()` or `.start()` may run again.
    - **`.wait_closed()`** — blocks until the loop has ended and
      its thread is joined; `False` if `timeout` seconds passed first. Returns
      at once when nothing is serving. `RuntimeError` on the receive thread
      itself, which would wait for itself.
    - **`.close()`** — `.shutdown()`, `.wait_closed()` (up to five seconds),
      then release every socket. **Final and repeatable**: `.bind()`,
      `.start()`, `.serve_forever()` and `with` afterwards raise `RuntimeError`.
      On the receive thread (a handler calling it) it shuts down and returns
      without joining; the loop releases the sockets as it ends. An exception
      or interrupt that ends `.serve_forever()` or `.start()` at any point,
      before the loop runs included, leaves the listener idle: `.close()` returns
      at once.
    - `with listener:` binds on entry (it does not serve) and calls `.close()` on
      exit.
    - The library installs **no signal handler**: Ctrl-C reaches
      `.serve_forever()` as `KeyboardInterrupt`, which the `pydhcp` commands turn
      into `.shutdown()`. `poll_interval` bounds one wait for a datagram because
      Windows delivers the interrupt to the main thread between waits.
  - **`.bound_addresses -> tuple[SocketAddress, ...]`** — what this listener is
    actually bound to, read from the sockets rather than from the requested
    spec. Empty before `.bind()` and after `.close()`; a listener that was only
    shut down keeps its sockets. This is how a caller that passed port 0 learns
    the ephemeral port it was given. Each socket logs `Listening on: <asked>` before
    its bind and `Bound: <bound>` (INFO, the bound address) after it.
  - **`metrics.packets_dropped_truncated`** / **`metrics.packets_dropped_error`**
    — datagrams that did not fit `max_packet_size`, and datagrams lost to an
    error anywhere in receive/decode/handle. They are `DHCPMetrics` fields, so
    `.snapshot()` reports them: `DHCPMetrics.FIELDS` is the one list, so a counter cannot be incremented and absent from the snapshot.
  - **`.handle()`** — override point; base implementation is
    a no-op. Called for every successfully decoded packet.

- **`AsyncDHCPListener`** — `asyncio` counterpart, with the same receive path,
  the same packet-info wildcard routing and the same `listen` forms as
  `DHCPListener`. Same `.handle()` override point and per-instance
  `self.metrics`. The lifecycle mirrors the thread-based one with coroutines
  where it blocks, on `AsyncDHCPServer`, `AsyncDHCPRelay` and `AsyncDHCPCapture`
  too:
  - **`await .serve_forever()`** — binds, then receives in the **calling**
    task until `.shutdown()`; the sockets stay open on return. `await .start()
    -> None` binds and receives in background tasks, one per socket, and returns
    once receiving. Both raise what `.bind()` raised (with nothing bound, no task
    and no worker left behind) and `RuntimeError` when already serving or closed:
    a second `await .start()` is an error and adds no task.
  - **`.shutdown()`** — not a coroutine; never blocks; safe from any
    thread and from a handler, which runs on the worker thread: it queues
    `Event.set` with `call_soon_threadsafe`, because a plain `Event.set()`
    queues a callback *without* waking a selector loop. Measured with a handler
    calling it on its worker: Linux's selector loop never woke and
    `await .wait_closed()` blocked forever, while Windows' proactor loop returned
    in 7 ms. It closes nothing: the receive tasks end on the loop's next turn and
    `await .aclose()` releases the sockets.
  - **`await .wait_closed()`** — returns once the receive tasks
    have ended and the worker is aborted; `False` if `timeout` seconds passed
    first. Returns at once when nothing is serving.
  - **`await .aclose()`** — `.shutdown()`, `.wait_closed()`, then release the
    sockets. **Final and repeatable**; a task ending `serve_forever()` this way
    sees it return quietly. `async with listener:` binds on entry (it does not
    serve) and awaits `.aclose()` on exit. There is no `.close()`, `with`,
    `.listen()`, `.stop()` or `.wait()`.
  - The library installs no signal handler (see `DHCPListener`).
  - Handlers run on a single worker thread, not on the event loop: `.handle()`
    is ordinary blocking code, so running it inline would stall every other coroutine in the host application. One worker, so handlers still run one
    at a time and in arrival order — which is also what keeps a caller's
    compound lease operation ("free? then allocate") atomic, since the
    backend's own lock does not span two calls.
  - **The hand-off to that worker is bounded.** At most `max_queued`
    datagrams (default `MAX_QUEUED_DATAGRAMS`, 1024: about 3 MiB) wait for
    or are in the handler; a positive `int`, else `ValueError`. The datagram
    that finds the backlog full is **dropped**, counted in
    `metrics.packets_dropped_backlog` and reported at WARNING at most once
    per `BACKLOG_LOG_INTERVAL_SECONDS` (60), the report carrying the count.
    **Shutting down aborts, it does not drain**: queued datagrams are discarded,
    counted in the same counter and reported once at INFO; only the handler
    already running finishes. `AsyncDHCPServer`, `AsyncDHCPRelay` and
    `AsyncDHCPCapture` take the same `max_queued`.
  - `.bound_addresses`, `.REUSE_ADDRESS`, `.bind()` and the handling of one
    datagram — as on `DHCPListener`, including the oversized-datagram drop; both
    listeners share one private base for them, and neither is a subclass of the
    other. The counters are on `.metrics` only.
  - Receives with one `netimps.UDPEndpoint.arecv()` task per socket, so packet
    info works on **every** loop type, Windows' default proactor loop included.
    A socket retired by a re-`bind()` whose listen list shrank ends its task
    without an error.
    Serving ends by cancelling those tasks *before* the sockets are closed, the
    order netimps documents for a clean shutdown.

## Transports and the request context (`pydhcp.listener`)

```python
DHCPTransport.send(data, dst, *, port, client_mac) -> int
UDPTransport(socket)
PktInfoUDPTransport(socket, endpoint=None)
DHCPRequestContext(transport, interface, client, client_mac, ifindex=None, local_ip=None,
    received_at=None, received_monotonic=None, destination=None, is_unicast=None, payload=None)
```

- **`DHCPTransport`** (`typing.Protocol`) — `.send()`, which returns the octets sent and raises `OSError`
  when the send failed. Anything with that method is a transport; `UDPTransport`
  is the one that sends on a socket.

- **`UDPTransport`** — plain UDP send. It does not own the socket and
  never closes it: the listener that bound the socket closes it. A destination of `0.0.0.0`
  ("this client has no address yet") is sent to `255.255.255.255`, per
  RFC 2131 §4.1. A failed send raises `OSError`; **it is never escalated to a
  broadcast**, which would put a reply the caller deliberately unicast (a
  RENEWING client at its own `ciaddr`, a relay at `giaddr`) with its `yiaddr`,
  `chaddr`, lease options and echoed `RELAY_AGENT_INFORMATION` in front of the
  whole segment. Whether to broadcast is the caller's decision.
  - **A full send buffer is waited out.** The asyncio listener makes its sockets
    non-blocking and replies from its worker thread, so a full buffer raises
    `BlockingIOError` there. The send waits for the socket to be writable and is
    repeated as it was, for at most `SEND_WAIT_SECONDS` (class attribute, 1.0), and
    then raises the `BlockingIOError`. It holds the worker thread for that long at
    most. On a blocking socket nothing changes.

- **`PktInfoUDPTransport`** — a transport (which, like
  `UDPTransport`, never closes the socket or the endpoint) that sends
  from the address the request arrived on, for wildcard sockets: `local_ip` is the
  source address and `ifindex` the interface (0/`None`: none known). Pinning goes
  through `netimps.UDPEndpoint.send(src=...)` (`endpoint`, or one wrapping
  `socket`), which builds the control message for Linux, macOS and Windows alike.
  Plain `UDPTransport.send` when `local_ip` isn't set or the endpoint reports no
  source pinning. What is pinned depends on where the reply goes:
  - **A unicast is pinned to the address alone.** With the arrival interface's
    index the kernel puts it on that interface even when its route is through
    another one, ARPs there for an address nobody answers for and loses the reply
    without an error (measured on Linux). The routing table picks the interface. A
    failed pin is retried **unpinned**, to the same destination, never as a
    broadcast.
  - **A broadcast** (`255.255.255.255`, so also a destination of `0.0.0.0`) is
    pinned to the address **and** the interface index, where the platform takes
    both (FreeBSD IPv4 has no index pin: netimps pins the interface's address).
    If that fails it is tried once more **with the address alone**, which on Linux
    and Windows still keeps a limited broadcast on the interface that owns the
    address. If that fails too the reply is **dropped**: `OSError` is raised,
    `replies_dropped_pin` is counted and one WARNING per interval says why. It is
    never sent unpinned, because a broadcast leaves by whichever interface the
    routing table picks and reaches a segment the client is not on.
  - A full send buffer is neither: see `UDPTransport`.
  - `.limit` is the listener's log limit and `.metrics` its `DHCPMetrics` (both
    `None` on a transport made by hand, which then shares one process-wide limit
    and counts nothing).

- **`DHCPRequestContext`** (`NamedTuple`) — `transport: DHCPTransport`, `interface:
  NetworkInterface`, `client: SocketAddress`, `client_mac: bytes`,
  `ifindex: int | None = None`, `local_ip: IPv4 | None = None`,
  `received_at: datetime | None = None` (timezone-aware UTC),
  `received_monotonic: float | None = None` (`time.monotonic()` seconds),
  `destination: IPv4 | None = None`, `is_unicast: bool | None = None` and
  `payload: bytes | None = None`.
  - `payload` is the datagram as it arrived, one reference to the received
    `bytes` (no copy); `None` on a context built by hand. A decoded message cannot
    give it back: `encode` pads to 300 octets and a decode ignores what follows
    the end option. A capture file is written from it.
  - `received_at` and `received_monotonic`: the listener stamps both when the
    datagram arrives, and the server, relay and capture read the time of an
    exchange from them. A context built by hand has `None` for both and the hooks
    use the driver's clock instead.
  - `destination` is the address the datagram was **sent to**: `255.255.255.255`
    or a subnet broadcast for a client with no address (or one rebinding), this
    host's own address for a unicast. `is_unicast` says whether it names one host
    (not a broadcast, a multicast group or `0.0.0.0`). RFC 2131 s4.3.2 tells a
    RENEWING client (unicast) from a REBINDING one (broadcast) by it. Both are
    `None` when the socket reports no packet info (a socket bound to one address)
    and on a context built by hand.
  - `local_ip` is the address a reply leaves from. For a unicast it is the
    destination, **including an address the adapter does not list** (the rest of
    127/8, a virtual address held on `lo`): the reply comes from the address the
    client used, while `interface` (and so `SERVER_IDENTIFIER` and the pool) stays
    an entry the adapter lists. For a broadcast, a multicast group or the
    wildcard it is the receiving interface's own primary address.
  - `interface` comes from the adapter that arrived with the datagram, with no
    lookup of its own; a socket bound to one address (no packet info) resolves it
    from the bound address.
  Handlers use `context.transport`/`context.interface` to reply out the same
  interface a request arrived on.

- **`ListenLike`** — type alias for the `listen` argument accepted above: `None`, one
  binding (text, an `IPv4Address`, a `netimps.Interface`, a `netimps.MACAddress`, or a
  `(host, ports)` pair as tuple or list), or a sequence of bindings.

- **`BROADCAST_ADDRESS`** (`"255.255.255.255"`) — the all-ones address every DHCP client can be
  reached at before it has one of its own (RFC 2131 §4.1).

**Gotcha**: a socket bound to a specific loopback address (`127.0.0.1`, not
`0.0.0.0`) cannot originate a UDP broadcast send on POSIX (Windows is lenient
and silently allows it). Any test/deployment that binds to a specific loopback
IP and needs a broadcast reply path should pass `broadcast=False` through the client's build helpers (`pydhcp/client/AGENTS.md`) to keep the exchange unicast.

## Host interface enumeration (`pydhcp._network`)

```python
host_ip_interfaces(filter=True, family=4, *, cache=False) -> Iterator[NetworkInterface]
```

- **`host_ip_interfaces`** — one entry **per address**, not per adapter,
  backed by `netimps.iter_addresses()`. `cache` is netimps' enumeration cache:
  `False` enumerates now, `True` reuses an enumeration up to
  `netimps.INTERFACE_CACHE_TTL` (1 s) old, a number is that TTL in seconds.
  Per-packet callers pass `True`; `DHCPListener.bind()` clears the cache.
  `filter=True` (default) excludes `netimps.LINK_LOCAL_V4` (APIPA) addresses;
  `filter=False` (falsy) includes everything; or pass a
  `Callable[[NetworkInterface], bool]` predicate. Used by `DHCPListener`
  wildcard binding, the `pydhcp interfaces` CLI subcommand, and
  `DHCPServer`'s subnet lookup in `acquire_lease`/`get_inform_options`.
  - `family` is `4` or `AF_INET`, `6` or `AF_INET6`, or `None`; anything else
    raises `ValueError`.
  - **`family=4` by default.** This is a DHCPv4 implementation, so yielding
    IPv6 would silently change what a caller iterates over. Pass `family=None`
    for both families.
  - Adapter names are the platform's **human-readable** name (`"Wi-Fi"`), and
    **loopback is included**, with its true `/8`.
