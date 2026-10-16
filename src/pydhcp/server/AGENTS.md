# `pydhcp.server` — public API header

Header-file-style reference for `pydhcp.server`: the servers and the hooks you override; the
leases they hand out and the stores that keep them are in `pydhcp/lease/AGENTS.md`. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; the top header is
`pydhcp/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

## Server (`pydhcp.server`)

A package. The server's rules live in a private core that owns no socket,
thread or clock; `DHCPServer` (thread-based) and `AsyncDHCPServer` (asyncio) are
two sibling drivers composing that core with their own listener, and neither is a
subclass of the other. Import from `pydhcp.server` and override on your subclass
of either driver: **every hook below is an ordinary blocking method that runs on
the one handler thread** — the receive thread of `DHCPServer`, the single worker
thread of `AsyncDHCPServer` — so handlers are serialised and in arrival order.
A test that patches a module global patches it in the private module that reads it.

```python
DHCPServer(listen=None, *, poll_interval=None, max_packet_size=None, lease_backend=None,
    per_interface=None, reuse_address=None, receive_buffer_size=None)
DHCPServer.acquire_lease(client_id, server_id, msg, *, commit=True) -> DHCPLease | None
DHCPServer.get_lease_seconds(msg) -> float
DHCPServer.quarantine_address(ip, *, now=None)
DHCPServer.is_quarantined(ip, *, now=None) -> bool
DHCPServer.lookup_lease(client_id) -> DHCPLease | None
DHCPServer.release_lease(client_id, server_id, msg) -> bool
DHCPServer.get_inform_options(server_id, msg) -> DHCPOptions
DHCPServer.handle(msg, context) -> None
DHCPServer.handle_discover(msg, context) -> None
DHCPServer.handle_request(msg, context) -> None
DHCPServer.handle_decline(msg, context) -> None
DHCPServer.handle_release(msg, context) -> None
DHCPServer.handle_inform(msg, context) -> None
AsyncDHCPServer(listen=None, *, max_packet_size=None, lease_backend=None, per_interface=None,
    reuse_address=None, receive_buffer_size=None, max_queued=None)
```

- **`DHCPServer`** (`DHCPListener` subclass) —
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
    those and from nothing else.
  - **`.acquire_lease()`** —
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
  - **`.get_lease_seconds()`** — how long a lease to grant, applying this
    server's policy to the client's requested time. RFC 2131 §4.3.1 honours
    that request only "if acceptable to local policy", so it is clamped to
    `[MIN_LEASE_SECONDS, MAX_LEASE_SECONDS]` (60 s … 1 day), defaulting to
    `DEFAULT_LEASE_SECONDS` (1 h) when the client asks for none. The
    RFC 2132 §3.3 infinity sentinel (`0xFFFFFFFF`) yields `math.inf` when
    **`ALLOW_INFINITE_LEASE`** is set, and the maximum when it is not — never
    a finite 136-year lease. Override the method or the four attributes; this
    is the base allocator's policy only, so an `.acquire_lease()` override
    that builds its own lease is unaffected.
  - **`RENEWAL_TIMES`** (class attribute, `True`) — a reply that carries a finite lease
    time (an OFFER or ACK, not the ACK to a DHCPINFORM, not an infinite lease) also
    carries option 58 as half and option 59 as seven eighths of it, rounded down
    (RFC 2131 s4.4.5): 150 and 262 for 300 s, 50 and 87 for a renewal with 100 s left.
    An option the lease's options hold is kept, and a request list does not remove
    them. They are exact, with none of the RFC's random fuzz: a subclass wanting it
    puts 58 and 59 in the options `acquire_lease` returns. `False` sends only those.
  - **`.quarantine_address()`** — stops offering `ip` for
    **`DECLINE_QUARANTINE_SECONDS`** (class attribute, `600.0`); `now` is `time.monotonic()` seconds, and when
    omitted (as `handle_decline` calls it, so an override taking only `ip` keeps
    working) the driver's reading is used. The map holds at most
    **`MAX_DECLINED_ADDRESSES`** (1024): at the bound the entries that have run
    out are dropped and, if none has, a **new** address is refused and counted in
    `quarantines_refused` — never the oldest evicted, which would let a flood of
    reports push a genuine one out.
  - **`.is_quarantined()`** — whether `ip` is out of the pool.
    The server asks it of **every lease a hook returns**: an `acquire_lease`
    override is not offered a declined address again, and does not have to check.
    A DISCOVER whose lease is quarantined gets no OFFER, a REQUEST gets a NAK
    (`addresses_refused` counts both).
  - **`.lookup_lease()`** — override point: the lease
    this server holds for the client, in either state (`lease.offered`), `None`
    for none. The default reads `lease_backend`. A DHCPDECLINE, a DHCPRELEASE and a
    REQUEST naming another server ask it to learn what the sender holds; a server
    that keeps its leases elsewhere overrides this one method.
  - **`.handle_decline()`** quarantines the address option 50 names (else `ciaddr`, else
    the one the sender holds), **whoever sent it** (RFC 2131 §4.3.3: "MUST mark the
    network address as not available"): it must lie in the served network, not be this
    host's own (unless the sender holds a lease on it), and option 54, when present, must
    name this server. A record the sender holds for it, as a binding or an offer, is
    released too (`leases_declined`); any other DECLINE changes nothing and is counted
    in `declines_ignored`. A forged one costs the address's holder a DHCPNAK at its next
    renewal, for at most `MAX_DECLINED_ADDRESSES` addresses and `DECLINE_QUARANTINE_SECONDS`
    each. **`DECLINE_REQUIRES_LEASE`** (class attribute, `False`) is the stricter rule,
    which departs from that MUST: only an address the sender holds is marked.
  - **Options 50, 51, 54 and 57 are decoded once, at the top of `.handle()`**,
    inside one guard: a wrong-length option 50 or 54 (the message cannot say which
    address or which server) drops the message, counted in
    `packets_dropped_malformed_option`; a wrong-length 51 or 57 is removed from the
    message, so every reader sees it absent (`options_ignored_malformed`). Each is
    logged once per interval with the XID and the client, never raised.
  - **`.release_lease()`** — override point,
    releases via the lease backend; `server_id` is **always this server's own
    address** (the receiving interface's), on every path; returns whether a binding actually went
    away. It does **not** touch metrics: an orderly `DHCPRELEASE`, a
    `DHCPDECLINE` reporting an address conflict, and a reclaim after the client
    chose another server all arrive here, and only the caller knows which, so
    the caller counts. An override that wants the counters moved should return
    the bool faithfully rather than incrementing anything itself.
  - **`.handle_release()`** releases only when the binding matches: RFC 2131 §4.4.6
    puts the address being given up in `ciaddr`, and a `DHCPRELEASE` naming a
    *different* address than the client holds is ignored and counted in
    `releases_ignored`: a late or duplicated RELEASE cannot delete the current binding.
  - **`.get_inform_options()`** — override point for
    DHCPINFORM-only option sets (no address allocated, and no `DHCPLease` built:
    the ACK carries these options, no `yiaddr` and no lease time). Same default set, and
    the same omission of `ROUTER`/`DNS`, as `.acquire_lease()`.
  - **Host-address lookups use netimps' enumeration cache** (`cache=True`, a
    one-second TTL), and `.bind()` clears it. "Which interface holds `server_id`",
    "do we hold this address" and the arrival-interface resolution ask it per
    packet; uncached an enumeration costs about 1 ms (35-42 ms with many adapters),
    1181 µs of a 1539 µs `handle()` on one measured box. Cached it is at most one a
    second, and an address the host gains or loses is noticed within a second.
  - **`.handle_request()`** answers each shape of RFC 2131 §4.3.2 from the lease
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
  - **`.handle_inform()`** answers only a `ciaddr` that is the datagram's source
    address or lies in the served network** (RFC 2131 §4.3.5 sends the ACK to
    `ciaddr`); any other, and an INFORM with no `ciaddr`, is dropped and
    counted in `informs_ignored`.
  - **Echoed option 82 is the last option of the reply** (RFC 3046 §2.2) and is
    never placed in the overloaded `sname` or `file`: a reply that would need
    them (or does not fit at all) is sent without the option and counted in
    `relay_info_omitted`, with one rate-limited warning.
  - **`.handle()`** — dispatches on `DHCP_MESSAGE_TYPE`;
    ignores non-`BOOTREQUEST` messages and messages addressed to a different
    `SERVER_IDENTIFIER` than this interface's IP (a DHCPREQUEST first gives
    back an address held for the client by an *offer*, counted in
    `offers_withdrawn`; a binding is kept).
  - Reply destination: unicasts to `giaddr` when a relay is in play (RFC 2131
    §4.1); otherwise to `ciaddr` when the client has one, else to
    `255.255.255.255`: the client's `BROADCAST` flag asks for that, and a
    client with no address yet is answered the same way with the flag clear,
    because a plain UDP socket cannot deliver to a `yiaddr` the client does
    not own (it cannot answer ARP for it). The reply goes to `yiaddr` only
    over loopback, where there is no ARP and POSIX refuses the broadcast, or
    when **`UNICAST_TO_UNCONFIGURED_CLIENT`** (class attribute, `False`) is
    set for a transport that can address the client's hardware address. A
    DHCPNAK with `giaddr` 0 is always broadcast. **The UDP destination port
    comes from where the reply goes** (RFC 1542 §5.4, three MUSTs):
    **`REPLY_TO_RELAY_PORT`** (class attribute, `67`) for a reply sent to
    `giaddr`, a DHCPNAK through a relay included, and **`REPLY_TO_CLIENT_PORT`**
    (`68`) for every other reply. A harness that runs a relay or a client on
    another port sets them (on the class, the instance, or per request from
    `handle`); a real deployment never does. **`STRICT_REPLY_PORTS`** (class
    attribute, `True`) holds that rule; `False` answers the port the request
    came from (`giaddr` at that port, at 67 when it is 68), and **gives up the
    protection**: the source port is the sender's to choose, so one
    unauthenticated datagram can send a reply to any port on any host.
    `pydhcp server --lenient-reply-ports` sets it.
    `RELAY_AGENT_INFORMATION` (option 82) on the request is echoed back
    unmodified on the reply, per RFC 3046 §2.2.
  - The reply is built from `lease.options.copy()`, never the lease's own
    container: the response pipeline injects bookkeeping options and the
    `PARAMETER_REQUEST_LIST` filter deletes everything the client did not
    ask for — all of which would write through to the lease backend. An
    `.acquire_lease()` override returning a lease whose options it also keeps
    a reference to is therefore safe.

- **`AsyncDHCPServer`** — the same rules and hooks as
  `DHCPServer`, running on `AsyncDHCPListener`: `async with`, `await .aclose()`,
  `await .serve_forever()` and `.shutdown()` as there, and no `with` or `.close()`.
