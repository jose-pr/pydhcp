# `pydhcp.client` — public API header

Header-file-style reference for `pydhcp.client`: the packet-level client, blocking and asyncio. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; the top header is
`pydhcp/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

## Client (`pydhcp.client`)

```python
DHCPClient(listen=None, *, poll_interval=None, max_packet_size=None, per_interface=None,
    reuse_address=None, receive_buffer_size=None)
DHCPClient.build_discover(chaddr, *, xid=None, client_identifier=None,
    parameter_request_list=None, broadcast=True) -> DHCPMessage
DHCPClient.build_request(chaddr, *, xid=None, requested_ip=None, server_identifier=None,
    ciaddr=None, client_identifier=None, parameter_request_list=None, broadcast=True) ->
    DHCPMessage
DHCPClient.build_inform(chaddr, *, ciaddr, xid=None, client_identifier=None,
    parameter_request_list=None) -> DHCPMessage
DHCPClient.build_release(chaddr, *, ciaddr, server_identifier=None, xid=None,
    client_identifier=None) -> DHCPMessage
DHCPClient.build_decline(chaddr, *, requested_ip, server_identifier=None, xid=None,
    client_identifier=None) -> DHCPMessage
DHCPClient.send(message, *, dst=IPv4Address("255.255.255.255"), port=DHCPPort.SERVER) -> int
DHCPClient.discover_offer(chaddr, *, timeout=2.0, retries=2, deadline=None,
    destination=IPv4Address("255.255.255.255"), port=DHCPPort.SERVER, xid=None,
    client_identifier=None, parameter_request_list=None, broadcast=True) -> DHCPMessage
DHCPClient.dora(chaddr, *, timeout=2.0, retries=2, deadline=None,
    destination=IPv4Address("255.255.255.255"), port=DHCPPort.SERVER, xid=None,
    client_identifier=None, parameter_request_list=None, broadcast=True) -> DHCPMessage
DHCPClient.next_reply(timeout=None) -> tuple[DHCPMessage, DHCPRequestContext] | None
DHCPClient.on_reply(msg, context) -> None
DHCPClient.drain_replies() -> list[tuple[DHCPMessage, DHCPRequestContext]]
```

- **`DHCPClient`** (`DHCPListener` subclass) — packet-level client for
  tests/troubleshooting; does **not** configure OS network interfaces. The
  message builders, the reply matching and the retransmission schedule are one
  private core (`client/_core.py`) shared with the asyncio client; `DHCPClient`
  adds the socket, the receive thread and the blocking waits.
  - The five builders construct a message without sending it. `chaddr` is
    required positional bytes and `xid` defaults to a random 32-bit value on
    all five, but **the rest of the signature differs per message type**. Three take a **required keyword-only** argument, and only the first
    two accept `broadcast`:
    - **`.build_discover()`**
    - **`.build_request()`**
    - **`.build_inform()`** — **`ciaddr` required**
    - **`.build_release()`** — **`ciaddr` required**
    - **`.build_decline()`** —
      **`requested_ip` required**

    The asymmetry is RFC 2131, not an oversight: INFORM and RELEASE come from a
    client that already holds its address, so `ciaddr` is the whole point of
    the message; DECLINE names the address being refused. None of the three is
    sent by a client with no address, so none has a broadcast flag to set.
    `parameter_request_list` is accepted only where a reply carries options.
  - **`.send()`** — binds lazily on first call, sends via a
    fresh `UDPTransport`. It sends and registers nothing: an exchange
    (`.discover_offer()`, `.dora()`) registers its own `(xid, chaddr)` in
    `self._pending_keys` for as long as it runs, so `.handle()` queues only the
    matching replies while one is pending. A reply carrying a seen `xid` but
    another client's `chaddr` is ignored — the xid is in cleartext in a
    broadcast DISCOVER, so anyone on the segment can read one (same key as
    `DHCPRelay._pending_key`). A message sent with `.send()` alone is therefore
    not awaited: its reply is queued only while no exchange is pending.
  - **`.discover_offer()`** — broadcasts
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
    it leaves, and nothing is sent after that wait whatever the clock then shows;
    a value that is not positive is a `ValueError`. Each transmission
    carries a real `secs` — seconds since the exchange began (§2).
  - **`.dora()`** — full
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
  - **`.next_reply()`**
    / `.drain_replies()` — pull queued BOOTREPLY messages.
    A reply belonging to an exchange currently running in
    `.discover_offer()`/`.dora()` goes to that exchange and does **not** reach
    these; everything else accepted does. That routing is what lets two
    exchanges with different `chaddr`s run concurrently on one client without
    consuming each other's replies.
  - **`.on_reply()`** — override hook called after a
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

```python
AsyncDHCPClient(listen=None, *, max_packet_size=None, per_interface=None, reuse_address=None,
    receive_buffer_size=None)
async AsyncDHCPClient.send(message, *, dst=IPv4Address("255.255.255.255"), port=DHCPPort.SERVER)
    -> int
async AsyncDHCPClient.next_reply(timeout=None)
AsyncDHCPClient.drain_replies()
```

- **`AsyncDHCPClient`** (`AsyncDHCPListener`
  subclass, **not** a subclass of `DHCPClient`) — the same client on an event
  loop, over the same core: the same builders, matching, schedule and defaults.
  - Lifecycle as on the other asyncio classes: `await .start()` /
    `await .serve_forever()`, `.shutdown()`, `await .wait_closed(timeout=None)`,
    `await .aclose()`, `async with` (which binds, and does not serve).
  - **`await .send()`**, `await .discover_offer()` and `await .dora()` take the keywords of
    the synchronous methods (`deadline` included) and return and raise what
    they do. `send` works before
    serving starts (it binds); an exchange needs the receive tasks running or it
    times out. `await .next_reply()` waits for a queued reply and
    returns `None` on timeout; `.drain_replies()` is not a coroutine, it never
    waits.
  - **Cancelling an exchange abandons it**: its transaction stops being
    accepted and nothing stays behind. Any number of exchanges may be pending on
    one client at once, each on its own `(xid, chaddr)`.
  - **`handle`** and `.on_reply()` run on the event loop**, not on a worker
    thread (the client has none): `.on_reply()` must not block. A server's hooks
    run on the handler thread; this is the one asyncio role whose hook does not.
  - Waiting is on loop-owned queues, one per exchange, with the same bound
    (`MAX_QUEUED_REPLIES`) and the same oldest-first discard as the synchronous
    client; the receive path is the listener's `arecv` loop, so netimps' rule of
    one awaiting receive per endpoint holds.

- **`ClientIdentifierLike`** (`Union[bytes, bytearray]`) — what a function accepts as a client
  identifier: the octets of option 61 (`client_identifier=` of the builders and the exchanges).

**Gotcha**: `.dora()`/`.discover_offer()` require the listener's receive loop
to actually be running (`client.start()`, and `client.close()` when done) —
replies only reach the internal queue via `.handle()`, which the background
thread calls (the asyncio client's receive tasks, after `await start()`). A
client that is never started will always time out waiting for a reply.
