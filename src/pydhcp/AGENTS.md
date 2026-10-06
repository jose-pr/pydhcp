# `pydhcp` — public API header

Header-file-style reference for the top-level `pydhcp` package: every
`pydhcp/__init__.py` export with its signature, arguments, contract, and
gotchas, so this module can be consumed without reading its source. For the
project overview, install, and CLI, see <https://github.com/jose-pr/pydhcp>. The
private `_network` package and the `options` and `packet` subpackages have
their own headers (they ship as `pydhcp/{_network,options,packet}/AGENTS.md`).

**What the root holds** (`pydhcp.__all__`, 54 names, `__version__` among them:
the installed distribution's version, read from its metadata): the main
classes of each role (`DHCPServer`, `DHCPClient`, `DHCPRelay`, `DHCPCapture`
and their async twins, the listeners and transports), `DHCPMessage` and the
enums a caller passes (`DHCPMessageType`, `DHCPOpcode`, `DHCPFlags`,
`DHCPPort`), the option container and its generic codecs, the lease backends,
`SocketAddress`, `NetworkInterface` and `IPv4AddressLike` (what a function
accepts for an IPv4 address: the address or its dotted text), and the exceptions. Everything else
is imported from the module that owns it:

| Name | Home |
| --- | --- |
| `CCC*`, `MoS*`, `VI*` codecs, `IPv4AddressOption`, `List`, `Bytes`, `String`, `Boolean`, `BaseDHCPOptionCode` | `pydhcp.options` |
| `HardwareAddressType` | `pydhcp.packet` |
| `loads`, `dumps` (the four structured formats, as mappings) | `pydhcp.packet.structured` |
| `DHCPMetrics`, `ListenLike`, `BROADCAST_ADDRESS` | `pydhcp.listener` |
| `ServerAddressLike`, `DEFAULT_MAX_HOPS` | `pydhcp.relay` |
| `ClientIdentifierLike` | `pydhcp.client` |
| `PacketFilterLike` | `pydhcp.capture` |
| `validate_filename_pattern`, `FILENAME_FIELDS` | `pydhcp.capture` |
| `main`, `App` | `pydhcp.cli` |

A name outside a module's `__all__` is not API. The address and MAC types are
not re-exported: `IPv4Address`, `IPv4Network` and `IPv4Interface` come from
`ipaddress`, `MACAddress` from `netimps`. `load_config` and the size
constants are in private modules and are not importable from a public one.

## Exceptions (`pydhcp.exceptions`, also at the root)

- **`DHCPError(Exception)`** — the base of everything pydhcp raises on its
  own account.
- **`DHCPDecodeError(DHCPError, ValueError)`** — octets that are not the
  message or option they were read as. Every decoder (`DHCPMessage.decode`,
  each option codec, `DHCPOptions.get`) raises it, and nothing else, for
  malformed input.
- **`DHCPValueError(DHCPError, ValueError)`** — a value a codec or message
  field cannot represent (an entry past 255 octets, a header field out of
  range).
- **`DHCPConfigError(msg, path=None, lineno=None, colno=None)`** (a `DHCPError` and a
  `ValueError`) — a configuration file that cannot be used: it does not parse, its
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
- **`DHCPRefusedError(message, nak)`** (a `DHCPError`) — the server answered the DHCPREQUEST with a
  DHCPNAK. `.nak` is the DHCPNAK `DHCPMessage` (its `DHCP_MESSAGE` option, when
  present, says why); it copies and pickles with its NAK.

A caller's own mistake (a wrong argument type, a bad option code, a bad
`max_packetsize`) stays a plain `TypeError` or `ValueError`.

## Listener / transport (`listener/`)

A package split by responsibility into private modules (`_transport`,
`_spec`, `_interfaces`, `_receive`, `_binding`, `_sync`, `_asyncio`); import
everything below from `pydhcp.listener` itself.


- **`DHCPListener(listen=None, *, poll_interval=None, max_packet_size=None,
  per_interface=None, reuse_address=None, receive_buffer_size=None)`** —
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
    default holds about 220 typical datagrams, and measured, a 1000-datagram
    burst delivered 220 at the default and all 1000 at 1 MiB. The kernel may
    grant less (Linux caps at `net.core.rmem_max`); a shortfall is logged at
    INFO by pydhcp, naming the address, and by netimps at WARNING (once per
    process for each distinct request and grant). A failure to grow is logged at
    WARNING, never raised.
  - `.bind() -> None` — open/refresh sockets for `self._listen`; raises
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
    - `.serve_forever() -> None` — binds, then receives on the **calling**
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
    - `.start() -> None` — **binds on the caller's thread**, then runs the same
      loop on a **daemon** thread named `pydhcp-listener` (nothing in the loop
      ends by itself, so a non-daemon one meant a process that forgot to close
      never exited). An address that cannot be bound raises what `.bind()`
      raised (`AddressInUseError`, `PermissionError`, ...) out of `.start()`,
      with nothing bound and the listener unstarted. `RuntimeError` when
      already serving or closed: a second `.start()` is an error, never a second
      thread. `.bind()` itself, when it fails partway, closes the sockets that
      call opened and keeps the ones an earlier call bound.
    - `.shutdown() -> None` — asks the loop to end. **Never blocks and is safe
      from any thread and from a handler**; a wake-up socket ends the wait at
      once, so it does not wait for a poll. A no-op when nothing is serving.
      Shut down is not closed: `.serve_forever()` or `.start()` may run again.
    - `.wait_closed(timeout=None) -> bool` — blocks until the loop has ended and
      its thread is joined; `False` if `timeout` seconds passed first. Returns
      at once when nothing is serving. `RuntimeError` on the receive thread
      itself, which would wait for itself.
    - `.close() -> None` — `.shutdown()`, `.wait_closed()` (up to five seconds),
      then release every socket. **Final and repeatable**: `.bind()`,
      `.start()`, `.serve_forever()` and `with` afterwards raise `RuntimeError`.
      On the receive thread (a handler calling it) it shuts down and returns
      without joining; the loop releases the sockets as it ends.
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
    the ephemeral port it was given.
  - **`metrics.packets_dropped_truncated`** / **`metrics.packets_dropped_error`**
    — datagrams that did not fit `max_packet_size`, and datagrams lost to an
    error anywhere in receive/decode/handle. They are `DHCPMetrics` fields, so
    `.snapshot()` reports them: they briefly landed as plain listener
    attributes, which is the exact failure `DHCPMetrics.FIELDS` exists to
    prevent — a counter incremented but absent from the snapshot.
  - `.handle(msg, context) -> None` — override point; base implementation is
    a no-op. Called for every successfully decoded packet.
- **`AsyncDHCPListener(listen=None, *, max_packet_size=None,
  per_interface=None, reuse_address=None, receive_buffer_size=None,
  max_queued=None)`** — `asyncio` counterpart, with the same receive path,
  the same packet-info wildcard routing and the same `listen` forms as
  `DHCPListener`. Same `.handle()` override point and per-instance
  `self.metrics`. The lifecycle mirrors the thread-based one with coroutines
  where it blocks, on `AsyncDHCPServer`, `AsyncDHCPRelay` and `AsyncDHCPCapture`
  too:
  - `await .serve_forever() -> None` — binds, then receives in the **calling**
    task until `.shutdown()`; the sockets stay open on return. `await .start()
    -> None` binds and receives in background tasks, one per socket, and returns
    once receiving. Both raise what `.bind()` raised (with nothing bound, no task
    and no worker left behind) and `RuntimeError` when already serving or closed:
    a second `await .start()` is an error and adds no task.
  - **`.shutdown() -> None`** — not a coroutine; never blocks; safe from any
    thread and from a handler, which runs on the worker thread: it queues
    `Event.set` with `call_soon_threadsafe`, because a plain `Event.set()`
    queues a callback *without* waking a selector loop. Measured with a handler
    calling it on its worker: Linux's selector loop never woke and
    `await .wait_closed()` blocked forever, while Windows' proactor loop returned
    in 7 ms. It closes nothing: the receive tasks end on the loop's next turn and
    `await .aclose()` releases the sockets.
  - `await .wait_closed(timeout=None) -> bool` — returns once the receive tasks
    have ended and the worker is aborted; `False` if `timeout` seconds passed
    first. Returns at once when nothing is serving.
  - `await .aclose() -> None` — `.shutdown()`, `.wait_closed()`, then release the
    sockets. **Final and repeatable**; a task ending `serve_forever()` this way
    sees it return quietly. `async with listener:` binds on entry (it does not
    serve) and awaits `.aclose()` on exit. There is no `.close()`, `with`,
    `.listen()`, `.stop()` or `.wait()`.
  - The library installs no signal handler (see `DHCPListener`).
  - Handlers run on a single worker thread, not on the event loop: `.handle()`
    is ordinary blocking code, so running it inline stalled every other
    coroutine in the host application. One worker, so handlers still run one
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
- **`DHCPTransport`** (`typing.Protocol`) — `.send(data, dst: IPv4, *, port: int,
  client_mac: bytes) -> int`, which returns the octets sent and raises `OSError`
  when the send failed. Anything with that method is a transport; `UDPTransport`
  is the one that sends on a socket.
- **`UDPTransport(socket)`** — plain UDP send. It does not own the socket and
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
- **`PktInfoUDPTransport(socket, endpoint=None)`** — a transport (which, like
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
  `destination: IPv4 | None = None` and `is_unicast: bool | None = None`.
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

**Gotcha**: a socket bound to a specific loopback address (`127.0.0.1`, not
`0.0.0.0`) cannot originate a UDP broadcast send on POSIX (Windows is lenient
and silently allows it). Any test/deployment that binds to a specific loopback
IP and needs a broadcast reply path should pass `broadcast=False` through the
client build helpers below to keep the exchange unicast.

## Server (`server/`)

A package. The server's rules live in a private core that owns no socket,
thread or clock; `DHCPServer` (thread-based) and `AsyncDHCPServer` (asyncio) are
two sibling drivers composing that core with their own listener, and neither is a
subclass of the other. Import from `pydhcp.server` and override on your subclass
of either driver: **every hook below is an ordinary blocking method that runs on
the one handler thread** — the receive thread of `DHCPServer`, the single worker
thread of `AsyncDHCPServer` — so handlers are serialised and in arrival order.
A test that patches a module global patches it in the private module that reads it.

- **`DHCPServer(listen=None, *, poll_interval=None, max_packet_size=None,
  lease_backend=None, per_interface=None, reuse_address=None,
  receive_buffer_size=None)`** (`DHCPListener` subclass) —
  `lease_backend` defaults, when it is `None`, to a fresh `InMemoryLeaseBackend()`.
  A backend that is falsy when empty (one that defines `__len__`) is kept: the test
  is `is None`. **The caller owns a backend it passed in**: `close()` (and
  `aclose()`) leave it open, so flush or close it yourself; a backend the server
  created is closed with the server.
  - **Hook contract.** Every hook below is an ordinary method, called on the one
    handler thread (the receive thread of `DHCPServer`, the single worker thread
    of `AsyncDHCPServer`), so hooks of one server never run at the same time and
    are never called from the event loop. A hook may block, but while it does
    that thread handles nothing else: datagrams wait (the async server drops past
    `max_queued`). A `handle_*` hook replies with `context.transport.send`; the
    others return a value and send nothing. A hook that raises answers nothing and
    is logged with its traceback by the listener (counted in
    `packets_dropped_error`); the next datagram is handled. What each is told:
    `handle(msg, context)` and the five `handle_*(msg, context)` get the decoded
    message and the arrival context (`handle` is where the guards run, so an
    override of one `handle_*` sees only messages that passed them);
    `acquire_lease(client_id, server_id, msg, *, commit=True)` gets the receiving
    interface''s address as `server_id`; `lookup_lease(client_id)` the identity;
    `release_lease(client_id, server_id, msg)` **always this server''s address** as
    `server_id` (another server named in option 54 is in `msg`);
    `get_inform_options(server_id, msg)`; `get_lease_seconds(msg)`;
    `quarantine_address(ip, *, now=None)` and `is_quarantined(ip, *, now=None)`
    (`now` is `time.monotonic()` seconds, omitted when the caller has none).
    **An override that stores leases must `offer` when `commit=False` and
    `commit` (or `allocate`) when `commit=True`**: a bound lease stored on the
    probe call lets a client that never accepts the OFFER keep the address. The
    options of a lease it returns are read-only. An override that keeps leases
    elsewhere also overrides `lookup_lease` and, if the release must reach its
    store, `release_lease`: INIT-REBOOT (through `acquire_lease`), RELEASE,
    DECLINE and a REQUEST naming another server learn what the sender holds from
    those and from nothing else.  - `.acquire_lease(client_id, server_id, msg, *, commit=True) -> DHCPLease | None` —
    override point. **Runs on the server itself** (not a copy), on the handler
    thread (the one worker thread on the async server), so an attribute an
    override keeps — a counter for the next free host — is the server's own.
    **`commit` says what kind of call it is**: a DHCPDISCOVER makes one call
    with `commit=False`; a DHCPREQUEST makes **two**, `commit=False` to decide
    what to ACK and then `commit=True` if it is ACKed. An override must accept
    the keyword (one that does not raises `TypeError` on every DISCOVER), and
    one that writes to a store of its own, or extends a binding, does so only
    when `commit` is true: `self.lease_backend` is the real backend on both
    calls. An override that keeps its leases in the backend answers a
    `commit=False` call with `offer` (the address is held for a short time and a
    client that never REQUESTs it loses it) and a `commit=True` call with
    `commit` or `allocate`; one that returns a `DHCPLease` and stores nothing
    is answered for every shape of request.
    Base impl, for a client **with a record**: on `commit=False` returns it as it
    stands, on `commit=True` commits an **offered** lease and renews a bound one.
    For a client **with none**: only a DHCPDISCOVER makes a record. With
    `REQUESTED_IP` (or a non-wildcard `ciaddr`) it **holds the address as an
    offer** for `OFFER_HOLD_SECONDS` on `commit=False` and allocates it on
    `commit=True`; a DHCPREQUEST from a client with no record gets `None`.
    Returns `None` when nothing can be offered (silently drops the message),
    which includes an address outside the served network and **any message whose
    `giaddr` is outside the served network** (the base allocator has the one
    network to give: it does not answer a client behind a relay on another
    network with this network's mask; an override that serves relayed
    networks supplies its own). Both refusals count in `addresses_refused`.
    - **`OFFER_HOLD_SECONDS`** (class attribute, `120.0`) — how long an offered
      address is held for the client it was offered to. A forged DHCPDISCOVER
      therefore holds an address for this long and no longer; the OFFER
      itself advertises the lease the ACK would grant (`get_lease_seconds`),
      not the hold.
    - **Default options: `SUBNET_MASK` and `BROADCAST_ADDRESS` only**, both
      taken from the receiving interface. It deliberately does **not** send
      `ROUTER` or `DNS`: this host is not known to route or resolve, and
      naming it as both told clients to send off-link traffic and name lookups
      into a black hole. Supply the real ones by overriding this method.
  - `.get_lease_seconds(msg) -> float` — how long a lease to grant, applying this
    server's policy to the client's requested time. RFC 2131 §4.3.1 honours
    that request only "if acceptable to local policy", so it is clamped to
    `[MIN_LEASE_SECONDS, MAX_LEASE_SECONDS]` (60 s … 1 day), defaulting to
    `DEFAULT_LEASE_SECONDS` (1 h) when the client asks for none. The
    RFC 2132 §3.3 infinity sentinel (`0xFFFFFFFF`) yields `math.inf` when
    **`ALLOW_INFINITE_LEASE`** is set, and the maximum when it is not — never
    a finite 136-year lease. Override the method or the four attributes; this
    is the base allocator's policy only, so an `.acquire_lease()` override
    that builds its own lease is unaffected.
  - `.quarantine_address(ip, *, now=None)` — stops offering `ip` for
    `DECLINE_QUARANTINE_SECONDS`; `now` is `time.monotonic()` seconds, and when
    omitted (as `handle_decline` calls it, so an override taking only `ip` keeps
    working) the driver's reading is used. The map holds at most
    **`MAX_DECLINED_ADDRESSES`** (1024): at the bound the entries that have run
    out are dropped and, if none has, a **new** address is refused and counted in
    `quarantines_refused` — never the oldest evicted, which would let a flood of
    reports push a genuine one out.
  - `.is_quarantined(ip, *, now=None) -> bool` — whether `ip` is out of the pool.
    The server asks it of **every lease a hook returns**: an `acquire_lease`
    override is not offered a declined address again, and does not have to check.
    A DISCOVER whose lease is quarantined gets no OFFER, a REQUEST gets a NAK
    (`addresses_refused` counts both).
  - `.lookup_lease(client_id) -> DHCPLease | None` — override point: the lease
    this server holds for the client, in either state (`lease.offered`), `None`
    for none. The default reads `lease_backend`. A DHCPDECLINE, a DHCPRELEASE and a
    REQUEST naming another server ask it to learn what the sender holds; a server
    that keeps its leases elsewhere overrides this one method.
  - **`.handle_decline()` quarantines only an address the sender holds**: the
    address option 50 names (else `ciaddr`, else the one the sender holds) must be
    the sender's own binding or outstanding offer according to `lookup_lease`,
    lie in the served network, and option 54, when present, must name this server.
    The sender's lease is then released and the address quarantined
    (`leases_declined`). Any other DECLINE changes nothing and is counted in
    `declines_ignored`: client identifiers are unauthenticated, so a DECLINE from
    another client for a held address, for an address nobody was offered, for one
    outside the network or for the server's own would otherwise take addresses
    out of the pool at one packet each.
  - **Options 50, 51, 54 and 57 are decoded once, at the top of `.handle()`**,
    inside one guard: a wrong-length option 50 or 54 (the message cannot say which
    address or which server) drops the message, counted in
    `packets_dropped_malformed_option`; a wrong-length 51 or 57 is removed from the
    message, so every reader sees it absent (`options_ignored_malformed`). Each is
    logged once per interval with the XID and the client, never raised.
  - `.release_lease(client_id, server_id, msg) -> bool` — override point,
    releases via the lease backend; `server_id` is **always this server's own
    address** (the receiving interface's), on every path; returns whether a binding actually went
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
  - `.get_inform_options(server_id, msg) -> DHCPOptions` — override point for
    DHCPINFORM-only option sets (no address allocated, and no `DHCPLease` built:
    the ACK carries these options, no `yiaddr` and no lease time). Same default set, and
    the same omission of `ROUTER`/`DNS`, as `.acquire_lease()`.
  - **Host-address lookups use netimps' enumeration cache** (`cache=True`, a
    one-second TTL), and `.bind()` clears it. "Which interface holds
    `server_id`", "do we hold this address" and the listener's arrival-interface
    resolution all need it per packet, and an uncached enumeration costs about
    1 ms (35–42 ms with many adapters) — 1181 µs of a 1539 µs `handle()` on one
    measured box before any cache. The cost is now at most one enumeration per
    second whatever the packet rate, and an address the host gains or loses is
    noticed within a second without a re-bind.
  - `.handle_discover/.handle_request/.handle_decline/.handle_release/
    .handle_inform(msg, context) -> None` — per-message-type handlers called
    from `.handle()`; each is independently overridable.
  - **`.handle_request()` answers each shape of RFC 2131 §4.3.2 from the lease
    `.acquire_lease()` returns for the client**, told apart by Table 4:
    **SELECTING** (option 54 names this server) is ACKed for the address it asks
    for and NAKed when it cannot be satisfied (the address is held by another
    client or off the network, the offer lapsed, another address was offered) —
    never left unanswered, never allocated on the spot. **INIT-REBOOT**
    (option 50, no option 54, `ciaddr` 0), **RENEWING** (`ciaddr`, unicast to
    this server: `context.is_unicast`) and **REBINDING** (`ciaddr`, broadcast)
    are ACKed for the address the client holds, NAKed for another, and answered
    with silence when `acquire_lease` returns nothing: the client may belong to
    another server on the same wire, and nothing is allocated for it. A RENEWING
    and a REBINDING request are answered alike; the log line names which. A
    request with no option 54, no option 50 and no `ciaddr` is dropped.
  - **The DHCPNAK carries what RFC 2131 Table 3 gives it**: the server
    identifier, the message type, a `DHCP_MESSAGE` text saying why, the relay
    agent information when the request had it, and the **client identifier
    exactly as the client sent it, and none when it sent none** (RFC 6842 §3).
    `yiaddr`, `ciaddr`, `siaddr`, `sname` and `file` are empty; `flags`,
    `giaddr`, `chaddr` and `xid` are the request's, and through a relay
    (`giaddr` set) the broadcast bit is set as well (§4.3.2). No lease time,
    and none of the options the client asked for.
  - **`.handle_inform()` answers only a `ciaddr` that is the datagram's source
    address or lies in the served network** (RFC 2131 §4.3.5 sends the ACK to
    `ciaddr`); any other, and an INFORM with no `ciaddr`, is dropped and
    counted in `informs_ignored`.
  - **Echoed option 82 is the last option of the reply** (RFC 3046 §2.2) and is
    never placed in the overloaded `sname` or `file`: a reply that would need
    them (or does not fit at all) is sent without the option and counted in
    `relay_info_omitted`, with one rate-limited warning.
  - `.handle(msg, context) -> None` — dispatches on `DHCP_MESSAGE_TYPE`;
    ignores non-`BOOTREQUEST` messages and messages addressed to a different
    `SERVER_IDENTIFIER` than this interface's IP (a DHCPREQUEST first gives
    back an address held for the client by an *offer*, counted in
    `offers_withdrawn`; a binding is kept).
  - Reply destination: unicasts to `giaddr` when a relay is in play (RFC 2131
    §4.1); otherwise uses `ciaddr`, then broadcasts if the client's `BROADCAST`
    flag is set, else `yiaddr`, falling back to `255.255.255.255`. **The UDP
    destination port comes from where the reply goes, never from the request's
    source port** (RFC 1542 §5.4, three MUSTs): **`REPLY_TO_RELAY_PORT`** (class
    attribute, `67`) for a reply sent to `giaddr`, a DHCPNAK through a relay
    included, and **`REPLY_TO_CLIENT_PORT`** (`68`) for every other reply. The
    source port is the sender's to choose, so honouring it let one unauthenticated
    datagram send a reply to any port on any host. A harness that runs a relay or
    a client on another port sets the attribute (on the class, the instance, or
    per request from `handle`); a real deployment never does.
    `RELAY_AGENT_INFORMATION` (option 82) on the request is echoed back
    unmodified on the reply, per RFC 3046 §2.2.
  - The reply is built from `lease.options.copy()`, never the lease's own
    container: the response pipeline injects bookkeeping options and the
    `PARAMETER_REQUEST_LIST` filter deletes everything the client did not
    ask for — all of which used to write through to the lease backend. An
    `.acquire_lease()` override returning a lease whose options it also keeps
    a reference to is therefore safe.
- **`AsyncDHCPServer(listen=None, *, max_packet_size=None, lease_backend=None,
  per_interface=None, reuse_address=None, receive_buffer_size=None,
  max_queued=None)`** — the same rules and hooks as
  `DHCPServer`, running on `AsyncDHCPListener`: `async with`, `await .aclose()`,
  `await .serve_forever()` and `.shutdown()` as there, and no `with` or `.close()`.

## Client (`client/`)

- **`DHCPClient(listen=None, *, poll_interval=None, max_packet_size=None,
  per_interface=None, reuse_address=None, receive_buffer_size=None)`** (`DHCPListener` subclass) — packet-level client for
  tests/troubleshooting; does **not** configure OS network interfaces. The
  message builders, the reply matching and the retransmission schedule are one
  private core (`client/_core.py`) shared with the asyncio client; `DHCPClient`
  adds the socket, the receive thread and the blocking waits.
  - The five builders construct a message without sending it. `chaddr` is
    required positional bytes and `xid` defaults to a random 32-bit value on
    all five, but **the rest of the signature differs per message type** — they
    were previously documented as one signature, which was wrong for three of
    them. Three take a **required keyword-only** argument, and only the first
    two accept `broadcast`:
    - `.build_discover(chaddr, *, xid=None, client_identifier=None,
      parameter_request_list=None, broadcast=True) -> DHCPMessage`
    - `.build_request(chaddr, *, xid=None, requested_ip=None,
      server_identifier=None, ciaddr=None, client_identifier=None,
      parameter_request_list=None, broadcast=True) -> DHCPMessage`
    - `.build_inform(chaddr, *, ciaddr, xid=None, client_identifier=None,
      parameter_request_list=None) -> DHCPMessage` — **`ciaddr` required**
    - `.build_release(chaddr, *, ciaddr, server_identifier=None, xid=None,
      client_identifier=None) -> DHCPMessage` — **`ciaddr` required**
    - `.build_decline(chaddr, *, requested_ip, server_identifier=None,
      xid=None, client_identifier=None) -> DHCPMessage` —
      **`requested_ip` required**

    The asymmetry is RFC 2131, not an oversight: INFORM and RELEASE come from a
    client that already holds its address, so `ciaddr` is the whole point of
    the message; DECLINE names the address being refused. None of the three is
    sent by a client with no address, so none has a broadcast flag to set.
    `parameter_request_list` is accepted only where a reply carries options.
  - `.send(message, *, dst=IPv4("255.255.255.255"),
    port=DHCPPort.SERVER) -> int` — binds lazily on first call, sends via a
    fresh `UDPTransport`. It sends and registers nothing: an exchange
    (`.discover_offer()`, `.dora()`) registers its own `(xid, chaddr)` in
    `self._pending_keys` for as long as it runs, so `.handle()` queues only the
    matching replies while one is pending. A reply carrying a seen `xid` but
    another client's `chaddr` is ignored — the xid is in cleartext in a
    broadcast DISCOVER, so anyone on the segment can read one (same key as
    `DHCPRelay._pending_key`). A message sent with `.send()` alone is therefore
    not awaited: its reply is queued only while no exchange is pending.
  - `.discover_offer(chaddr, *, timeout=2.0, retries=2, deadline=None,
    destination=..., port=..., xid=None, client_identifier=None,
    parameter_request_list=None, broadcast=True) -> DHCPMessage` — broadcasts
    DHCPDISCOVER (with retries) and returns the first usable DHCPOFFER: one that
    offers an address (`yiaddr`) and carries `SERVER_IDENTIFIER`, since a
    SELECTING REQUEST must echo it (§4.3.2); others are ignored, with a limited
    warning. **Raises `DHCPTimeoutError`** (also a `TimeoutError`) when none
    arrives.
    **`timeout` is the *initial* retransmission interval, not a fixed one**:
    each retransmission waits twice as long as the last, randomized by ±1 s,
    the doubling capped at `RETRANSMIT_MAX_INTERVAL` (RFC 2131 §4.1); a
    `timeout` above the cap starts at the cap. With the
    defaults the call is bounded at about 2+4+8 s (±1 s each) rather than 3×2 s.
    **`deadline`** (seconds, `None` for none) bounds the whole call, whatever the
    schedule: no transmission starts after it and the last wait is cut to what
    it leaves; a value that is not positive is a `ValueError`. Each transmission
    carries a real `secs` — seconds since the exchange began (§2).
  - `.dora(chaddr, *, timeout=2.0, retries=2, deadline=None, destination=...,
    port=..., xid=None, client_identifier=None, parameter_request_list=None,
    broadcast=True) -> DHCPMessage` — full
    DISCOVER→OFFER→REQUEST→ACK exchange; returns the DHCPACK. Raises
    `DHCPTimeoutError` when no usable OFFER or ACK arrives and
    **`DHCPRefusedError`** (carrying the NAK) when the server answers the
    REQUEST with a DHCPNAK, which ends the exchange at once instead of being
    retransmitted against (§3.1 step 5). An ACK is usable when its option 54
    is the server the REQUEST selected (§4.4.1); a NAK naming another server is
    ignored. `deadline` counts across both halves.
    **`broadcast` forwards to both the DISCOVER and the follow-up REQUEST**,
    as do `client_identifier` and `parameter_request_list` — RFC 2131 §4.2
    and §4.4.1 require the same values in every subsequent message, and the
    identifier is what the server keys the lease on. `secs` counts from the
    DISCOVER across both halves — §2 defines it as time since *acquisition*
    began, so the REQUEST does not restart the clock.
  - `.next_reply(timeout=None) -> tuple[DHCPMessage, DHCPRequestContext] | None`
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
    **`RETRANSMIT_JITTER_SECONDS`** (1.0), class vars — RFC 2131 §4.1's cap on
    the doubling and its randomization amplitude, passed to
    `netimps.backoff_delays(jitter_seconds=...)`. The jitter is symmetric and
    applied **after** the cap, as the RFC does, so a backed-off wait falls in
    63–65 s rather than being clamped one-sidedly under 64. The amplitude is
    capped at the current delay, so a sub-second `timeout` in a test cannot be
    jittered negative.

- **`AsyncDHCPClient(listen=None, *, max_packet_size=None, per_interface=None,
  reuse_address=None, receive_buffer_size=None)`** (`AsyncDHCPListener`
  subclass, **not** a subclass of `DHCPClient`) — the same client on an event
  loop, over the same core: the same builders, matching, schedule and defaults.
  - Lifecycle as on the other asyncio classes: `await .start()` /
    `await .serve_forever()`, `.shutdown()`, `await .wait_closed(timeout=None)`,
    `await .aclose()`, `async with` (which binds, and does not serve).
  - `await .send(message, *, dst=..., port=...) -> int`,
    `await .discover_offer(chaddr, *, ...) -> DHCPMessage` and
    `await .dora(chaddr, *, ...) -> DHCPMessage` take the keywords of
    the synchronous methods (`deadline` included) and return and raise what
    they do. `send` works before
    serving starts (it binds); an exchange needs the receive tasks running or it
    times out. `await .next_reply(timeout=None)` waits for a queued reply and
    returns `None` on timeout; `.drain_replies()` is not a coroutine, it never
    waits.
  - **Cancelling an exchange abandons it**: its transaction stops being
    accepted and nothing stays behind. Any number of exchanges may be pending on
    one client at once, each on its own `(xid, chaddr)`.
  - **`handle()` and `.on_reply()` run on the event loop**, not on a worker
    thread (the client has none): `.on_reply()` must not block. A server's hooks
    run on the handler thread; this is the one asyncio role whose hook does not.
  - Waiting is on loop-owned queues, one per exchange, with the same bound
    (`MAX_QUEUED_REPLIES`) and the same oldest-first discard as the synchronous
    client; the receive path is the listener's `arecv` loop, so netimps' rule of
    one awaiting receive per endpoint holds.

**Gotcha**: `.dora()`/`.discover_offer()` require the listener's receive loop
to actually be running (`client.start()`, and `client.close()` when done) —
replies only reach the internal queue via `.handle()`, which the background
thread calls (the asyncio client's receive tasks, after `await start()`). A
client that is never started will always time out waiting for a reply.

## Relay (`relay/`)

- **`DHCPRelay(listen=None, server_addresses=(), *, max_hops=4,
  insert_relay_agent_info=False, circuit_id=None, remote_id=None,
  trust_client_relay_agent_info=False, poll_interval=None,
  max_packet_size=None, per_interface=None, reuse_address=None,
  receive_buffer_size=None)`**
  (`DHCPListener` subclass) — RFC 1542 / RFC 2131 §4.1 / RFC 3046 relay
  agent. `server_addresses` is required and non-empty (each entry an `IPv4`,
  a string, or a `(host, port)` tuple; bare entries default to port 67) —
  raises `ValueError` otherwise. `insert_relay_agent_info=True` adds option
  82 with `circuit_id`/`remote_id` sub-options to a request that arrives with
  `giaddr` 0 and no option 82 (RFC 3046 s2.1.1: a request another relay already
  stamped goes on without it). The flag needs `circuit_id` or `remote_id`, and
  either id needs the flag: any other combination is a `ValueError` from the
  constructor. The option goes last in the options field, never through option
  52 or `sname`/`file`; a request it would not fit (the limit is the relay's own
  `max_packet_size`, not the client's option 57, which says what the client can
  receive) is forwarded without it and counted in `metrics.relay_info_omitted`.
  A request whose `giaddr` is one of the relay's own addresses (the receiving
  interface's or any host address) is dropped and counted in
  `metrics.packets_dropped_relay_loop`, whether or not insertion is on. **`max_hops`
  defaults to 4**, the RFC 1542
  §4.1.1 default, and must be 0..16 -- that clause's hard ceiling -- or the
  constructor raises `ValueError`.
  **`trust_client_relay_agent_info=False`**: a request
  with `giaddr` 0 (straight from a client) that already carries option 82 is
  **dropped** and counted in `metrics.packets_dropped_untrusted`, since the
  option is forged (RFC 3046 s2.1, s5); `True` forwards it, for an access layer
  that is trusted to set it. Keyword-only, so a stray positional argument cannot
  turn the trust on.
  - `.handle(msg, context) -> None` — forwards `BOOTREQUEST` to every
    configured server (stamping `giaddr` and incrementing `hops`; drops and
    counts in `metrics.packets_dropped_hop_limit` when the *received* `hops`
    exceeds `max_hops`, so a request at exactly the threshold is still
    forwarded -- RFC 1542 §4.1.1) and
    forwards `BOOTREPLY` back to the original client. A reply's option 82 is
    removed only when it is the one this relay adds (RFC 3046 s2.1: the element
    that added the option removes it): the octets are compared with the option
    the constructor built, so an option a trusted downstream element added
    reaches that element.

- **`AsyncDHCPRelay(listen=None, server_addresses=(), *, max_hops=4,
  insert_relay_agent_info=False, circuit_id=None, remote_id=None,
  trust_client_relay_agent_info=False, max_packet_size=None,
  per_interface=None, reuse_address=None, receive_buffer_size=None,
  max_queued=None)`** — the same forwarding rules running on
  `AsyncDHCPListener`: a sibling of `DHCPRelay` over one private core, the way
  `AsyncDHCPServer` relates to `DHCPServer`. Identical arguments minus
  `poll_interval` (the sync receive loop's poll interval, which asyncio has no
  use for), and both constructors share the core's state setup, so the
  `server_addresses` and `max_hops` validation cannot be enforced on one and not
  the other. Drive it with `await .serve_forever()` or `await .start()`, `.shutdown()`,
  `await .wait_closed()` and `await .aclose()`.
  - `_pending_clients` is unguarded on both. What keeps it safe here is that
    `AsyncDHCPListener` runs handlers on **one** worker thread, so `handle()`
    is still serialised and in arrival order — the same guarantee the lease
    backends rely on. A handler pool would make this a data race.

- **`ServerAddressLike`** (`pydhcp.relay`, not re-exported from the top level) —
  the type of each `server_addresses` entry: `IPv4AddressLike |
  tuple[IPv4AddressLike, int]`. A bare entry defaults to port 67.

**Where a reply goes.** A reply is sent from the address in its `giaddr`, out of
the interface that holds it (`netimps.get_interface(giaddr, cache=True)`; RFC
1542 §4.1.2: "The 'giaddr' field can be used to identify the logical interface
from which the reply must be sent"), so the relay remembers nothing per exchange
to choose the interface. The relay stamped `giaddr` with the ingress address and
the server echoes it. A reply whose `giaddr` is not an address of the relay (0
included) is **dropped** and counted in `metrics.packets_dropped_unknown_giaddr`
(§4.1.2: "MUST be silently discarded"). A reply goes to port 68 unless the
exchange has an entry in the pending table.

- **The pending table holds only the port of a client that is not on port 68.**
  `DHCPRelay` keeps `(xid, chaddr) -> PendingClient` in `self._pending_clients`,
  recorded on forward and read on reply, so a client on a non-standard port (a
  test harness, an unusual deployment) is answered there; a request from port 68
  records nothing, so a flood from port 68 occupies no entry.
- **Keyed by client as well as transaction.** An xid alone is not an identity:
  it is cleartext in a broadcast DISCOVER, so any host on the segment can read
  one and send its own request carrying it. A request that reuses the
  transaction of a live entry from a *different* source address is dropped (not
  forwarded) and counted in `metrics.packets_dropped_reused_transaction`; one from
  the same address with another port replaces the entry (an unconfigured client's
  address is 0.0.0.0, so the address is all that can be compared).
- **Read, not consumed.** Every configured server sends its own reply, and they
  all belong to the same client, so the entry stays until
  `DHCPRelay.PENDING_TTL_SECONDS` (60) rather than being popped by whichever
  arrives first.
- **At the cap the oldest entry is evicted.** `DHCPRelay.MAX_PENDING_CLIENTS`
  (1024) bounds the table, so exchanges whose replies never arrive cannot grow it
  without limit; an evicted entry costs that client's reply the port (it goes to
  68), and nothing else, because the interface comes from `giaddr`. Expiry pops
  from the front of the table, which is in the order written, and costs the same
  whatever a flood left in it.

## Capture (`capture/`)

- **`DHCPCapture(listen=None, *, packet_filter=None, sink=None, hook=None,
  hook_fail_fast=False, poll_interval=None, max_packet_size=None,
  per_interface=None, reuse_address=None, receive_buffer_size=None)`** (`DHCPListener` subclass) — `packet_filter` is
  either a filter-expression string (compiled via `compile_capture_filter`)
  or a `Callable[[CaptureEvent], bool]`; `sink` gets every accepted event;
  `hook` also gets every accepted event but exceptions are only logged
  unless `hook_fail_fast=True`, in which case the failure is re-raised, stored
  on `self.hook_error` and the receive loop is shut down. Check `hook_error`
  after `serve_forever()` returns to tell a hook failure from an ordinary shutdown --
  re-raising alone does not reach the caller, because `handle()` runs inside
  the listener's per-packet exception handler. `self.accepted_count` tracks
  how many events passed the filter.
- **`CaptureEvent`** (frozen dataclass) — `message: DHCPMessage`, `context:
  DHCPRequestContext`, `captured_at: datetime`. Properties: `.source` /
  `.destination` (`SocketAddress`: where the datagram was sent, so the broadcast
  address for a client with no address, and the port it arrived on),
  `.message_type` (str name or `"UNKNOWN"`),
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
- **`command_hook(command, *, packet_format="json", timeout=HOOK_TIMEOUT_SECONDS,
  fail_fast=False) -> CaptureHook`** — a hook that runs a program once per
  captured packet. `command` is found when the hook is made: a name with a
  directory part (`./hook`, `/opt/hook`) is that file, taken relative to the
  working directory then, and a bare name is looked up on `PATH`; `ValueError`
  when it does not exist, is not a file or (POSIX) is not executable. It is run by
  its absolute path with **no arguments and no shell**. It reads the packet on
  standard input (`packet_format` `json` is one compact line, `yaml`/`toml`/`ini`
  are `DHCPMessage.to_text`) and its environment is a copy of this process's
  plus `PYDHCP_CAPTURE_CLIENT_ID`, `PYDHCP_CAPTURE_MSG_TYPE`, `PYDHCP_CAPTURE_XID`
  and `PYDHCP_CAPTURE_FORMAT`. Its output is decoded as UTF-8 with
  `errors="replace"`. Each run is bounded by `timeout` seconds (`ValueError`
  unless above 0): past it the program **and the processes it started** are
  killed (`taskkill /T` on Windows, the process group elsewhere) and the hook
  raises **`DHCPTimeoutError`**. A non-zero exit is logged at ERROR, at most once
  a minute whatever its frequency, with the status and the last 400 characters of
  standard error; with `fail_fast` it also raises **`DHCPHookError`**. The sizes
  of the two streams are logged at DEBUG, never their contents. Pass it as
  `DHCPCapture(hook=...)`; `hook_fail_fast=True` there stops the capture on the
  first error.
- **`HOOK_TIMEOUT_SECONDS`** (`10.0`) — the default `timeout` of `command_hook`.
  The hook runs on the receive thread, so without a bound a hanging program would
  stop packets being read at all.
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

**Gotcha**: without packet info (a socket bound to one address)
`CaptureEvent.destination` falls back to the address replies leave from, which it
takes from `context.interface.ip` and casts to `IPv4` to satisfy `SocketAddress`;
an IPv6-only interface isn't actually handled
(`NetworkInterface.ip` is `ipaddress.IPv4Address | ipaddress.IPv6Address`
— spelled out because the codec `IPv4AddressOption` is a *different* thing, see the
name-collision note at the top) — capture on an
IPv6-only interface can break at runtime. The `dst` filter key compares with
`.destination`, so `dst=255.255.255.255` selects the broadcasts and
`dst=<server address>` the unicasts.

- **`AsyncDHCPCapture(listen=None, *, packet_filter=None, sink=None, hook=None,
  hook_fail_fast=False, max_packet_size=None, per_interface=None,
  reuse_address=None, receive_buffer_size=None, max_queued=None)`** — the same
  filter/sink/hook rules running on `AsyncDHCPListener`: a sibling of
  `DHCPCapture` over one private core, not a subclass. Identical arguments minus
  `poll_interval`, and both constructors share the core's state setup. Drive
  it with `await .serve_forever()` or `await .start()`, `.shutdown()`,
  `await .wait_closed()` and `await .aclose()`, and check `.hook_error` after
  `.wait_closed()` returns.
  - `accepted_count`, `hook_error` and whatever a `sink` keeps are unguarded on
    both, and the single handler worker is again the whole guarantee — the sink
    runs on it too, so a per-run budget such as the CLI's `--count` needs no
    lock and no library-side state of its own.
  - `hook_fail_fast` shuts the capture down through
    `AsyncDHCPListener.shutdown()`, called from that worker thread; see the
    `.shutdown()` note under `AsyncDHCPListener` for why the sockets are still
    open when `handle()` re-raises: `await .aclose()` releases them.

- **Type aliases** (`pydhcp.capture`, not re-exported from the top level, so
  import them from the module): **`CaptureSink = Callable[[CaptureEvent],
  None]`**, **`CaptureHook = Callable[[CaptureEvent], None]`**, and
  **`CapturePredicate = Callable[[CaptureEvent], bool]`** — the three callable
  shapes `DHCPCapture`/`AsyncDHCPCapture` accept. A `packet_filter` string is
  compiled to a `CapturePredicate`; passing one directly skips the parser.

## Leases (`lease.py`)

- **`DHCPLease(ip, expires=None, options=None, *, offered=False)`** — one address held by one
  client, as a **value**: read-only (assigning raises `AttributeError`),
  hashable, equal when the address, expiry and option payloads are.
  - `ip: IPv4Address` is required. `None` raises `TypeError` and `0.0.0.0`
    raises `DHCPValueError`: a lease has an address.
  - `expires: datetime | None` is the instant the lease ends, **timezone-aware**
    (held in UTC), or `None` for a lease that never ends. A naive `datetime`
    raises `DHCPValueError` (use `datetime.now(timezone.utc)`); a `float` or
    anything else raises `TypeError`. `math.inf` is no longer an expiry.
  - `options: DHCPOptions` is **copied in** and read-only: the bag you passed
    stays yours, and `lease.options[...] = x`, `del`, `clear()`, `update()` and
    `append()` raise `TypeError`. Payloads read back as `bytes`.
    `lease.options.copy()` is an ordinary bag to change. A lease is the reply's
    source, never its scratch space.
  - `offered: bool` is the lease's state: `True` for an address held for a
    client that was offered it and has not accepted (`expires` is then the end
    of the hold), `False` for a binding. It takes part in equality and hash.
  - Copies, deep-copies and pickles to an equal lease, across a process
    boundary too, so a `LeaseBackend` kept in another process can return one.
- **`LeaseBackend`** (`Protocol`) — six methods, each atomic against the
  others, each treating a record whose `expires` has passed as absent:
  - `.offer(client_id, ip, hold_seconds, options=None) -> DHCPLease | None` —
    hold `ip` for the client for `hold_seconds` and return the **offered**
    lease (`offered` true, `expires` the end of the hold). `None` when another
    client holds `ip` in either state, when the store is full and the client is
    new, or when the client holds a *bound* lease on a different address (an
    offer never replaces a binding). A client that holds a bound lease on `ip`
    gets it back unchanged; an outstanding offer is replaced. `hold_seconds`
    is finite and positive (`ValueError` otherwise).
  - `.commit(client_id, ttl) -> DHCPLease | None` — turn the client's offered
    lease into a bound one lasting `ttl`; `None` when it has none (absent,
    lapsed, or already bound).
  - `.lookup(client_id) -> DHCPLease | None` — the client's lease in either
    state; `lease.offered` tells which.
  - `.renew(client_id, ttl) -> DHCPLease | None` — extend a **bound** lease to
    `ttl` from now; `None` for no lease or only an offer.
  - `.release(client_id) -> bool` — drop the record in either state.
  - `.allocate(client_id, ip, ttl, options=None) -> DHCPLease | None` — an
    offer and its commit in one call, a bound lease; replaces whatever the
    client held; `None` when another client holds `ip` or the store is full.
  - **`ttl: float`** — seconds, or `math.inf` for an infinite lease. It is
    `float` rather than `int` because that is what `math.inf` is and what the
    implementations have always accepted; an `int` still satisfies it.
  - A server refuses a backend that lacks any of the six at construction:
    `TypeError: lease_backend X does not implement LeaseBackend: it has no
    offer, commit`. A backend with only `allocate`, `lookup`, `release` and `renew` is refused
    that way and works once it gains `offer` and `commit`.
  - A backend that also has `lookup_by_ip(ip) -> str | None` (who holds the
    address, in either state) lets the stock allocator say why it refused an
    address; without it only `offer` and `allocate` refuse a held address.
- **`InMemoryLeaseBackend()`** — dict-backed reference implementation;
  `.lookup()` evicts (and returns `None` for) expired leases lazily; `ttl` of
  `math.inf` stores a lease whose `expires` is `None`. Each
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
  - `.lookup_by_ip(ip) -> str | None` — who holds an address, offered or
    bound. An optional extension, deliberately **not** on the `LeaseBackend`
    Protocol: a backend without it just skips the allocator's already-in-use
    check. Answered from an address index kept by offer, commit, allocate,
    renew, release and expiry, so its cost does not grow with the store.
- **`FileLeaseBackend(filepath)`** (`InMemoryLeaseBackend`
  subclass) — persists to JSON after every allocate/release/renew. `filepath`
  is required. **Construction reads nothing and touches no file**: `.open()`
  reads the file (once; idempotent), and the first lease operation or `with`
  calls it if the caller has not.
  - Writes are **atomic**: a temporary file in the same directory, renamed
    over the target, so a reader sees the whole file or the previous one and
    an interrupted write cannot truncate it. The rename retries briefly on
    `PermissionError` (on Windows an indexer or antivirus holding the file
    looks exactly like that).
  - The file maps each client identifier to `{"ip", "expires", "state",
    "options"}` (option payloads as hex). `state` is `"offered"` or `"bound"`;
    an entry with no `state`, as older files hold, is bound. `expires` is an
    ISO-8601 instant with an offset (written in UTC, `+00:00`: an expiry is an
    instant, so a clock change or a different time zone does not move it), or
    `"inf"` for no expiry. The file is UTF-8 with LF line endings on every
    platform. A time without an offset, as older files hold, is read as local
    time of the same instant, once, on load, and written back in UTC; an
    entry with no `ip` is skipped with a warning. An offer is not saved by
    itself (it is short and means nothing after a restart, and a rewrite per
    forged DISCOVER would cost what the sender chooses): the next save writes
    the offers still held, and one that has lapsed by the time the file is read
    is gone.
  - A missing file starts empty and says nothing. **A file is read whole or not
    at all**: a bad entry (a malformed address, an unknown `state`, bad option
    hex), an address held by two clients, or more live leases than `MAX_LEASES`
    leaves the store **empty** and is logged at ERROR (the count and the bound,
    for the last). The file is moved aside to `<filepath>.corrupt`, or
    `.corrupt.1`, `.corrupt.2`, … when that name is taken — it is the only copy
    of that state, so it is kept byte for byte, never overwritten, and never
    replaced by a save of a half-loaded store. A lease that has run out when the
    file is read is not loaded and does not count toward `MAX_LEASES`.
  - A save that fails is logged at ERROR and does **not** raise: a lease store
    that cannot be written must not take the server down mid-exchange. So it
    is best-effort persistence — but no longer a silent one.
  - **`SAVE_INTERVAL_SECONDS`** (class var, `0.0`) — `0` writes on every
    mutation, which is the default, and starts no thread. Above zero, writes are
    coalesced to at most one per interval: a change after a quiet interval is
    written at once, and one that comes sooner is written by **a daemon timer
    thread** (`pydhcp-lease-save`) at the end of the interval, so **a change is on
    disk within `SAVE_INTERVAL_SECONDS` of being made**, with no further change or
    call needed. **`.flush()`** writes a pending change now and cancels the timer;
    **`.close()`** flushes (the backend is also a context manager). A server does
    not close a backend it was given: call `.close()` yourself on the way out. Measured
    over 4,000 allocations: 115.76 s at the default, 0.02 s at a one-second
    interval. It is opt-in because it trades up to an interval of leases on a
    crash — which an operator cannot see going wrong — for throughput they
    can already measure and that `MAX_LEASES` already bounds.

## Metrics (`pydhcp.listener.DHCPMetrics`)

- **`DHCPMetrics()`** — plain counters, one instance per listener/server/
  client/relay/capture (`self.metrics`), never a module-level singleton.
  `.reset() -> None` zeroes all counters; `.snapshot() -> dict[str, int]`
  returns a plain dict copy.
  - **`DHCPMetrics.FIELDS`** (class var) — the counter names, in snapshot
    order, and the single source `__init__`/`.reset()`/`.snapshot()` all read.
    Add a counter here and it is initialised, reset and reported; the three
    used to repeat the list, which is how one gets incremented but never
    reported.
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
  - `leases_declined` counts `DHCPDECLINE`, which used to land in
    `leases_released` though it means the opposite — the client found the
    address already in use. An address-conflict storm read as orderly
    shutdowns. `releases_ignored` counts releases refused for naming an address
    the client does not hold.

## Constants (private)

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

## NVT text (private)

The fields RFC 2131/2132 call NVT ASCII — `sname`, `file`, and the `String`
options — carry other encodings in practice. Three helpers keep such a value
lossless on the wire and safe on a screen; use them rather than calling
`bytes.decode`/`str.encode` on these fields directly.

- **`decode(raw: bytes, what="text") -> str`** — UTF-8, with undecodable octets
  preserved via `surrogateescape` (logged at DEBUG, naming `what`, and counted by
  the listener that is decoding). Replacing them
  meant a relay forwarded a *different* boot filename than it received.
- **`encode(text: str) -> bytes`** — restores those octets exactly. Valid UTF-8
  is unaffected in both directions.
- **`display(text: str) -> str`** — the lossy step, at the boundary where a
  value is shown rather than parsed: surrogates become U+FFFD, so the result is
  safe for a terminal, a log, or a strict serializer.

**Gotcha**: a string from `decode()` may hold surrogates, so
`str.encode("utf-8")` on it raises and `json.dumps(..., ensure_ascii=False)`
fails at write time. Anything rendering one must call `display()` first —
`DHCPMessage.summary()`, `.to_mapping()` and `String.to_json()` already do.

## Logging

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
- The package installs a `NullHandler` on `pydhcp`, per the stdlib guidance for
  libraries. One consequence worth knowing: with logging otherwise
  unconfigured, `logging.lastResort` would print WARNING and above to stderr,
  and a `NullHandler` counts as a handler, so those lines go silent instead.
  Configure a handler to see them. The CLI is unaffected — it installs its own.

## Config loading (private)

- **`load_config(source, format=None) -> dict[str, Any]`** — one configuration
  file as a mapping of sections. `source` is a path or `-` (standard input,
  which has no name and so needs `format`). The format is `format` (`json`,
  `yaml`, `toml` or `ini`, any case) or else the file name's suffix (`.json`,
  `.yaml`, `.yml`, `.toml`, `.ini`, any case); any other suffix is refused,
  content is never sniffed. The text is UTF-8, with or without a byte-order
  mark. An empty YAML file is `{}`. INI values are read without interpolation
  (a `%` is text) and a duplicate section or key is an error; YAML is
  `safe_load`. `.toml` needs Python 3.11+ or `tomli`
  (`NotImplementedError` otherwise).
- A file that cannot be read raises the `OSError`. A document that does not parse,
  whose top level is not a mapping, or whose format cannot be told raises
  **`DHCPConfigError`** with `path`, `lineno` and `colno` (1-based, `None` when the
  parser gave none) and `msg`; the message and the exception chain carry no text from
  the document.

## CLI (`cli/`)

A package: `App` and `main()` are in `pydhcp.cli` itself, and each subcommand
has its own private module (`cli._interfaces`, `cli._server`, `cli._relay`,
`cli._packet`, `cli._capture`, with `cli._capture_hook` for `--hook` loading (a command
is `capture.command_hook`) and
`cli._common` for the shared base). `pydhcp.cli` exports `App`, `main`, the five
command classes and the format and limit constants named in its `__all__`; patch a
name where the command module looks it up (`pydhcp.cli._server.DHCPServer`).


Invoked as **`pydhcp`** (the console script) or **`python -m pydhcp`** — both
reach `cli.main()` and exit with its status, and both report themselves as `pydhcp` in usage and error
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
`_logger_name_ = "pydhcp"`, so `self._logger_` resolves the package logger
every module logger is a child of (`logging.getLogger("pydhcp")`), and `-v`/`-q`
change that logger's level. The attribute has to live on the subcommand: duho
resolves the logger on the *parsed* instance, so setting it only on `App` left
`-v` raising the level of a logger named after the subcommand while `pydhcp`
stayed at the root level and the library's output never appeared.

- **`main(argv: Sequence[str] | None = None) -> int`** — the `pydhcp`
  console-script entry point (`[project.scripts]` in `pyproject.toml`);
  `argv` is the arguments after the program name (default `sys.argv[1:]`).
  It never exits by itself and returns the **exit status**: **0** success
  (including `--help`, `--version` and a run ended with Ctrl-C), **1** a run
  that failed (an address in use, a file that cannot be written, a hook that
  failed under `--hook-fail-fast`, a packet that does not decode), **2** a wrong
  invocation (a bad option, a malformed `--listen`, `relay` without `--server`,
  a configuration file that cannot be used). An error is one line on stderr,
  `pydhcp: error: ...`; results go to stdout and logging to stderr. A closed
  stdout ends the command quietly, with status 1. Nothing is logged as
  "starting" before the arguments are accepted. The root sets `_mcp_ = False`:
  `PYDHCP_MCP` is not read and no command is served as a tool.
  Subcommands:
  `interfaces` (`--format text|json`: text is one tab-separated line per
  address, name, address, MAC or `-`, network; json is one array of objects
  `name`, `ip`, `mac`, `network`), `server` (`--config`, `--listen`,
  `--per-interface`, `--lease-file`), `relay` (`--listen`,
  `--server` repeatable or comma-separated and **required**, `--max-hops`,
  `--insert-relay-agent-info`, `--circuit-id`, `--remote-id`), `packet`
  (`--decode`/`--encode` mutually exclusive+required, `--input`/`--output`
  accepting `-` for stdio, `--format json|yaml|toml|ini|summary`; `summary` is
  decode-only, its first line is the op and XID), `capture` (`--listen`,
  `--filter`, `--format`, `--output` file/pattern/`-`, `--output-mode
  stream|single|per-capture`, `--max-files`, `--count`, `--hook` `module:function` or an
  executable (a name with a directory is that file, resolved against the working
  directory when the capture starts and run by its absolute path; a bare name is
  looked up on `PATH`; a non-executable file is refused at start-up), `--hook-fail-fast`, `--per-interface`). Also gets
  `--version` (via `App._version_ = duho.AUTO`, resolved from installed
  package metadata) for free. Every option has one line of help, with its
  default.
- **Settings** come, highest first, from the option, the environment variable,
  the configuration file and the field's default, and duho applies that order
  to every field of every command (see "Environment variables" below for the
  names). `server`, `relay` and `capture` take `--config FILE` (or
  `PYDHCP_CONFIG`) and `--config-format json|yaml|toml|ini`; `FILE` is `-` for
  standard input, which needs the format. **There is no default location**: a
  daemon does not pick up a file nobody named. The file has one section per
  command, named for it, and its keys are the command's field names
  (`listen`, `per_interface`, `lease_file`; `server`, `max_hops`,
  `insert_relay_agent_info`, `circuit_id`, `remote_id`; `packet_filter`,
  `packet_format`, `output`, `output_mode`, `count`, `hook`, `hook_fail_fast`):

  ```yaml
  server:
    listen: 127.0.0.1:6767
    lease_file: /var/lib/pydhcp/leases.json
  ```

  A list is a list (`server: [192.0.2.1, 192.0.2.2]`); `listen` also takes
  the listener's pair, list and null-host forms (`listen: [127.0.0.1, 6767]`).
  A file that does not parse, a top-level key that is not a command, a section
  that is not a mapping, a key the command does not have, and a section of
  *another* command than the one run are each refused by name, status 2, one
  line with the file's path and, where the parser gives one, the position:
  `pydhcp: error: server.yaml:12:5: expected ',' or ']'`.
- A `Cmd` returns `None` (status 0) or a status; a wrong invocation is a
  `ValueError` out of `__call__`, a failed run is an `OSError` or the private
  `_Failed`, and `main` is the one place that prints and maps them. Tests drive a
  command through `main([...])` against sockets on port 0.
- Each `--server` value is split by **`listener._split_host_port`**, the same
  parser the `--listen` specs go through, and reaches `DHCPRelay` as a
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
- **`MAX_PER_CAPTURE_FILES`** (1000; `--max-files N` sets the bound) — how many
  *distinct* files one `per-capture` run may create. The pattern interpolates
  values the client chooses, so without a bound one unauthenticated sender
  decides how much of the operator's disk to use (measured: 5,000 forged
  identifiers, 5,000 files). **A record that needs a file past the bound ends the
  capture**: status 1 and a last line, `pydhcp: error: capture stopped: N files
  written, the limit of --max-files; M records refused ...`. Rewriting an
  already-seen path is always free, which is what leaves a pattern the client
  cannot influence unlimited. `--max-files` with any other `--output-mode`, or
  below 1, is a wrong invocation (status 2). Each value interpolated into a
  filename is at most 64 characters: a longer one is cut and ends in an
  eight-digit hash of the whole, so two long client identifiers still name two
  files.
- **A record that cannot be written ends the capture**: the first one that
  fails (a directory the pattern names is a file, a full or read-only disk, a
  path that is a directory) stops the capture with status 1 and one line,
  `pydhcp: error: capture stopped: cannot write <path>: <reason>`, as
  `--hook-fail-fast` does for a hook. A single output file is opened for append
  **before anything is bound** (and created when absent), and a target that
  cannot be written, such as a directory or a read-only file, is a wrong
  invocation (status 2).

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
  use `message.to_text("json")` directly only for single structured packet
  files where pretty JSON is acceptable.

## Environment variables

Read when the command starts, by the command line only: `import pydhcp` reads
none of them. A boolean accepts `1`, `true`, `yes`, `on` and `0`, `false`, `no`,
`off`, in any case; empty counts as unset; any other text is an error naming the
variable (status 2).

| Variable | Sets |
| --- | --- |
| `PYDHCP_CONFIG` | the configuration file, as `--config`; `-` is standard input. Default: none |
| `PYDHCP_CONFIG_FORMAT` | `json`, `yaml`, `toml` or `ini`, as `--config-format`. Default: from the file's extension |
| `PYDHCP_TRACEBACK` | a boolean: when on, an error is raised with its traceback (status 1) instead of one `pydhcp: error:` line. Default: off; `0` is off |
| `PYDHCP_MCP` | not read: the root disables the tool server, and the variable is left untouched |
| `PYDHCP_SERVER_LISTEN`, `PYDHCP_SERVER_PER_INTERFACE`, `PYDHCP_SERVER_LEASE_FILE` | `server --listen`, `--per-interface`, `--lease-file` |
| `PYDHCP_RELAY_LISTEN`, `PYDHCP_RELAY_SERVER` (comma-separated), `PYDHCP_RELAY_MAX_HOPS`, `PYDHCP_RELAY_INSERT_RELAY_AGENT_INFO`, `PYDHCP_RELAY_CIRCUIT_ID`, `PYDHCP_RELAY_REMOTE_ID`, `PYDHCP_RELAY_PER_INTERFACE` | `relay --listen`, `--server`, `--max-hops`, `--insert-relay-agent-info`, `--circuit-id`, `--remote-id`, `--per-interface` |
| `PYDHCP_CAPTURE_LISTEN`, `PYDHCP_CAPTURE_FILTER`, `PYDHCP_CAPTURE_RECORD_FORMAT`, `PYDHCP_CAPTURE_OUTPUT`, `PYDHCP_CAPTURE_OUTPUT_MODE`, `PYDHCP_CAPTURE_MAX_FILES`, `PYDHCP_CAPTURE_COUNT`, `PYDHCP_CAPTURE_HOOK`, `PYDHCP_CAPTURE_HOOK_FAIL_FAST`, `PYDHCP_CAPTURE_PER_INTERFACE` | `capture --listen`, `--filter`, `--format`, `--output`, `--output-mode`, `--max-files`, `--count`, `--hook`, `--hook-fail-fast`, `--per-interface` |
| `PYDHCP_PACKET_INPUT`, `PYDHCP_PACKET_OUTPUT`, `PYDHCP_PACKET_FORMAT` | `packet --input`, `--output`, `--format` (`--decode` and `--encode` choose a mode and are not settings) |
| `PYDHCP_INTERFACES_FORMAT` | `interfaces --format` |
| `PYDHCP_CAPTURE_CLIENT_ID`, `PYDHCP_CAPTURE_MSG_TYPE`, `PYDHCP_CAPTURE_XID`, `PYDHCP_CAPTURE_FORMAT` | **set for a command hook**, not read: the client identifier (colon-separated upper-case hex, or `UNKNOWN`), the message type's name (`DHCPDISCOVER`), the transaction id (eight upper-case hex digits) and the record format of the packet the hook is given on standard input |
