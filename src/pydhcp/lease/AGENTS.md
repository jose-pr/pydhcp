# `pydhcp.lease` — public API header

Header-file-style reference for `pydhcp.lease`: the lease value a server hands out and the
stores that keep leases. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; the top header is
`pydhcp/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

## Leases (`pydhcp.lease`)

```python
DHCPLease(ip, expires=None, options=None, *, offered=False)
DHCPLease.replace(*, ip=..., expires=..., options=..., offered=...) -> DHCPLease
DHCPLease.to_mapping() -> dict[str, Any]
DHCPLease.from_mapping(data: Mapping[str, Any], *, codemap=None) -> DHCPLease
DHCPLease.to_text(format: str) -> str
DHCPLease.from_text(text: str, format: str, *, codemap=None) -> DHCPLease
LeaseBackend.offer(client_id, ip, hold_seconds, options=None) -> DHCPLease | None
LeaseBackend.commit(client_id, ttl) -> DHCPLease | None
LeaseBackend.lookup(client_id) -> DHCPLease | None
LeaseBackend.renew(client_id, ttl) -> DHCPLease | None
LeaseBackend.release(client_id) -> bool
LeaseBackend.allocate(client_id, ip, ttl, options=None) -> DHCPLease | None
InMemoryLeaseBackend()
InMemoryLeaseBackend.lookup_by_ip(ip) -> str | None
FileLeaseBackend(filepath)
FileLeaseBackend.flush()
FileLeaseBackend.close()
```

- **`DHCPLease`** — one address held by one
  client, as a **value**: read-only (assigning raises `AttributeError`),
  hashable, equal when the address, expiry and option payloads are.
  - `ip: IPv4Address` is required. `None` raises `TypeError` and `0.0.0.0`
    raises `DHCPValueError`: a lease has an address.
  - `expires: datetime | None` is the instant the lease ends, **timezone-aware**
    (held in UTC), or `None` for a lease that never ends. A naive `datetime`
    raises `DHCPValueError` (use `datetime.now(timezone.utc)`); a `float` or
    anything else raises `TypeError`. `math.inf` is not an expiry.
  - `options: DHCPOptions` is **copied in** and read-only: the bag you passed
    stays yours, and `lease.options[...] = x`, `del`, `clear()`, `update()` and
    `append()` raise `TypeError`. Payloads read back as `bytes`.
    `lease.options.copy()` is an ordinary bag to change. A lease is the reply's
    source, never its scratch space.
  - `offered: bool` is the lease's state: `True` for an address held for a
    client that was offered it and has not accepted (`expires` is then the end
    of the hold), `False` for a binding. It takes part in equality and hash.
  - **`.replace(*, ip, expires, options, offered)`** returns a new lease with
    the named fields changed and the rest carried over (`options` as the same
    object); a given field is checked as the constructor checks it, and
    `expires=None` is a lease that never ends. The original is unchanged.
  - **`.to_mapping()`** / **`DHCPLease.from_mapping()`** — the lease as plain
    data and back, to an equal lease: `{"ip": "10.0.0.5", "expires":
    "2100-01-01T12:00:00+00:00", "offered": false, "options": {"ROUTER":
    ["10.0.0.1"]}}`. `expires` is ISO 8601 in UTC and is **left out** for a
    lease that never ends (TOML has no null); `options` is
    `DHCPOptions.to_mapping`'s form, named with the lease's code map, so pass
    the same `codemap` to read it back. Reading is lenient: **only `ip` is
    required** (a missing one is a `ValueError` naming it; it has no default,
    since a lease always has an address); `expires` missing or null never
    ends, `offered` defaults to `False`, `options` to none, other keys are
    ignored. `expires` takes ISO 8601 text with an offset, `Z` included, or an
    aware `datetime`; `offered` must be a bool (`TypeError`). Every value is
    then checked as the constructor checks it.
  - **`.to_text(format)`** / **`DHCPLease.from_text(text, format)`** — the
    same written by `pydhcp.packet.structured` as `"json"`, `"yaml"`, `"toml"`
    or `"ini"`, with that module's extras and errors (in TOML an option held
    as `{"hex": ...}` or a record must come after the plain ones).
    `FileLeaseBackend` keeps its own file format; this is not it.
  - Copies, deep-copies and pickles to an equal lease, across a process
    boundary too, so a `LeaseBackend` kept in another process can return one.

- **`LeaseBackend`** (`Protocol`) — six methods, each atomic against the
  others, each treating a record whose `expires` has passed as absent:
  - **`.offer()`** —
    hold `ip` for the client for `hold_seconds` and return the **offered**
    lease (`offered` true, `expires` the end of the hold). `None` when another
    client holds `ip` in either state, when the store is full and the client is
    new, or when the client holds a *bound* lease on a different address (an
    offer never replaces a binding). A client that holds a bound lease on `ip`
    gets it back unchanged; an outstanding offer is replaced. `hold_seconds`
    is finite and positive (`ValueError` otherwise).
  - **`.commit()`** — turn the client's offered
    lease into a bound one lasting `ttl`; `None` when it has none (absent,
    lapsed, or already bound).
  - **`.lookup()`** — the client's lease in either
    state; `lease.offered` tells which.
  - **`.renew()`** — extend a **bound** lease to
    `ttl` from now; `None` for no lease or only an offer.
  - **`.release()`** — drop the record in either state.
  - **`.allocate()`** — an
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

- **`InMemoryLeaseBackend`** — dict-backed reference implementation;
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
  - **`.lookup_by_ip()`** — who holds an address, offered or
    bound. An optional extension, deliberately **not** on the `LeaseBackend`
    Protocol: a backend without it just skips the allocator's already-in-use
    check. Answered from an address index kept by offer, commit, allocate,
    renew, release and expiry, so its cost does not grow with the store.

- **`FileLeaseBackend`** (`InMemoryLeaseBackend`
  subclass) — persists to JSON after every allocate/release/renew. `filepath`
  is required. **Construction reads nothing and touches no file**: `.open()`
  reads the file (once; idempotent), and the first lease operation or `with`
  calls it if the caller has not.
  - Writes are **atomic**: a temporary file in the same directory, renamed
    over the target, so a reader sees the whole file or the previous one and
    an interrupted write cannot truncate it. The rename retries briefly on
    `PermissionError` (on Windows an indexer or antivirus holding the file
    looks exactly like that): **`REPLACE_ATTEMPTS`** (class attribute, `5`)
    tries, waiting **`REPLACE_BACKOFF_SECONDS`** (`0.02`) times the attempt
    number between them.
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
    is best-effort persistence, and not a silent one.
  - **`SAVE_INTERVAL_SECONDS`** (class var, `0.0`) — `0` writes on every
    mutation, which is the default, and starts no thread. Above zero, writes are
    coalesced to at most one per interval: a change after a quiet interval is
    written at once, and one that comes sooner is written by **a daemon timer
    thread** (`pydhcp-lease-save`) at the end of the interval, so **a change is on
    disk within `SAVE_INTERVAL_SECONDS` of being made**, with no further change or
    call needed. **`.flush()`** writes a pending change at once and cancels the timer;
    **`.close()`** flushes (the backend is also a context manager). A server does
    not close a backend it was given: call `.close()` yourself on the way out. Measured
    over 4,000 allocations: 115.76 s at the default, 0.02 s at a one-second
    interval. It is opt-in because it trades up to an interval of leases on a
    crash — which an operator cannot see going wrong — for throughput they
    can already measure and that `MAX_LEASES` already bounds.
