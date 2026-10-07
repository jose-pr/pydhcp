# `pydhcp.relay` — public API header

Header-file-style reference for `pydhcp.relay`: the RFC 1542 relay agent, blocking and asyncio. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; the top header is
`pydhcp/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

## Relay (`pydhcp.relay`)

```python
DHCPRelay(listen=None, server_addresses=(), *, max_hops=4, insert_relay_agent_info=False,
    circuit_id=None, remote_id=None, trust_client_relay_agent_info=False, poll_interval=None,
    max_packet_size=None, per_interface=None, reuse_address=None, receive_buffer_size=None)
DHCPRelay.handle(msg, context) -> None
```

- **`DHCPRelay`**
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
  defaults to 4** (`pydhcp.relay.DEFAULT_MAX_HOPS`), the RFC 1542
  §4.1.1 default, and must be 0..16 (`pydhcp.relay.RFC1542_MAX_HOPS`) -- that
  clause's hard ceiling -- or the constructor raises `ValueError`.
  **`trust_client_relay_agent_info=False`**: a request
  with `giaddr` 0 (straight from a client) that already carries option 82 is
  **dropped** and counted in `metrics.packets_dropped_untrusted`, since the
  option is forged (RFC 3046 s2.1, s5); `True` forwards it, for an access layer
  that is trusted to set it. Keyword-only, so a stray positional argument cannot
  turn the trust on.
  - **`.handle()`** — forwards `BOOTREQUEST` to every
    configured server (stamping `giaddr` and incrementing `hops`; drops and
    counts in `metrics.packets_dropped_hop_limit` when the *received* `hops`
    exceeds `max_hops`, so a request at exactly the threshold is still
    forwarded -- RFC 1542 §4.1.1) and
    forwards `BOOTREPLY` back to the original client. A reply's option 82 is
    removed only when it is the one this relay adds (RFC 3046 s2.1: the element
    that added the option removes it): the octets are compared with the option
    the constructor built, so an option a trusted downstream element added
    reaches that element.

```python
AsyncDHCPRelay(listen=None, server_addresses=(), *, max_hops=4, insert_relay_agent_info=False,
    circuit_id=None, remote_id=None, trust_client_relay_agent_info=False, max_packet_size=None,
    per_interface=None, reuse_address=None, receive_buffer_size=None, max_queued=None)
```

- **`AsyncDHCPRelay`** — the same forwarding rules running on
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
