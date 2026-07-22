# `pydhcp.network` — public API header

Header-file-style reference for `pydhcp.network`: network address types and
host interface discovery. All exports are also re-exported from the
top-level `pydhcp` package. See the repo-root `AGENTS.md` for the project
overview and `src/pydhcp/AGENTS.md` for the top-level package header.

## Address types

- **`IPv4`** — alias for `ipaddress.IPv4Address`. **`IPv6`** — alias for
  `ipaddress.IPv6Address`. **`IP`** — `IPv4 | IPv6`. **`IPv4Network`** /
  **`IPv6Network`** / **`IPNetwork`** — `ipaddress` network types.
  **`IPv4Interface`** — alias for `ipaddress.IPv4Interface`.
- **`WILDCARD_IPv4`** — `IPv4("0.0.0.0")` constant.
- **`APIPA`** — `169.254.0.0/16`, re-exported from `netimps`; the default
  `host_ip_interfaces()` filter excludes addresses in this range.
- **`MACAddress(src=None)`** — a `netimps.MACAddress` subclass. Accepts colon,
  hyphen, dot/Cisco or bare hex text, a 48-bit `int`, 6 raw bytes, or another
  MAC; raises `ValueError` if the result isn't exactly 6 bytes. `str()` renders
  uppercase hyphen-separated (`"AA-BB-CC-DD-EE-FF"`), which is the only thing
  this subclass changes.
  - **Not a `bytes` subclass** (the base type is a value object) — use
    `.packed` for the raw bytes. `.hex()` is kept as a passthrough.
  - Inherits `.oui`, `.is_multicast`, `.is_local` and ordering, and compares
    equal to a base `netimps.MACAddress` with the same bytes.
  - **A display type.** The wire hardware address (`chaddr`, option 61) is raw
    `bytes` throughout `packet/` and never passes through here — `chaddr`
    permits `hlen` up to 16 for non-Ethernet `htype`, while a MAC is exactly 6.
- **`SocketAddress(ip, port=None)`** (`NamedTuple[ip: IPv4, port: int]`) —
  `ip` may be a `str`, an `IPv4`, or a bound `socket.socket` (reads
  `getsockname()`, in which case `port` must be omitted); passing a
  non-socket `ip` with `port=None` raises `ValueError`.
  - `.compat() -> tuple[str, int]` — plain `(str, int)` pair for stdlib socket
    calls.
  - `.listen(family=AF_INET, kind=SOCK_DGRAM, proto=0, fileno=None,
    options=()) -> socket.socket` — create, `setsockopt` each
    `SocketOption`, bind to `(ip, port)`, and return the socket. Delegates to
    `netimps.bind()`, which closes the socket before any exception propagates,
    so a failed bind leaks nothing. `SO_REUSEADDR` is **not** set implicitly —
    pass it in `options` if wanted. An explicit `fileno` takes the direct path.
- **`SocketOption`** (`NamedTuple[level: int, name: int, value: int]`) — one
  `setsockopt` call, as passed to `SocketAddress.listen(options=...)`.
- **`SocketSession`** (`NamedTuple[socket, client: SocketAddress]`) —
  `.server` property resolves the bound local `SocketAddress`; `.respond(data,
  to=None) -> int` sends back to `to` (defaults to `.client`); a wildcard
  destination (`WILDCARD_IPv4`) resends as a broadcast automatically.
- **`NetworkInterface`** (`NamedTuple[name: str, ip_interface:
  IPv4Interface | IPv6Interface, mac: MACAddress | None = None]`) — `.ip`
  and `.network` properties delegate to `ip_interface`.

## Interface discovery

- **`host_ip_interfaces(filter=True, family=4) -> Iterator[NetworkInterface]`**
  — one entry **per address**, not per adapter, backed by
  `netimps.iter_addresses()`.
  `filter=True` (default) excludes `APIPA` (link-local) addresses;
  `filter=False` (falsy) includes everything; or pass a
  `Callable[[NetworkInterface], bool]` predicate. Used by `DhcpListener`
  wildcard binding, the `pydhcp interfaces` CLI subcommand, and
  `DhcpServer`'s subnet lookup in `acquire_lease`/`get_inform_options`.
  - **`family=4` by default.** This is a DHCPv4 implementation and the previous
    enumerator was IPv4-only, so yielding IPv6 would silently change what
    existing callers iterate over. Pass `family=None` for both families.
  - Adapter names are the platform's **human-readable** name (`"Wi-Fi"`), not a
    Windows GUID as before, and **loopback is now included** — so a
    loopback-bound socket resolves to a real interface with its true `/8`
    rather than a synthetic `/32`.
