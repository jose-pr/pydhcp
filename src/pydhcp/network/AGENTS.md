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
- **`APIPA`** — `ipaddress.ip_network("169.254.0.0/16")`; the default
  `host_ip_interfaces()` filter excludes addresses in this range.
- **`MACAddress(src=None)`** (`bytes` subclass) — `src` is a `str` (with or
  without `-` separators, e.g. `"AA-BB-CC-DD-EE-FF"` or hex), or 6 raw bytes.
  Raises `ValueError` if the resulting length isn't exactly 6. `str()`
  renders as uppercase hyphen-separated hex.
- **`SocketAddress(ip, port=None)`** (`NamedTuple[ip: IPv4, port: int]`) —
  `ip` may be a `str`, an `IPv4`, or a bound `socket.socket` (reads
  `getsockname()`, in which case `port` must be omitted); passing a
  non-socket `ip` with `port=None` raises `ValueError`.
  - `.compat() -> tuple[str, int]` — plain `(str, int)` pair for stdlib socket
    calls.
  - `.listen(family=AF_INET, kind=SOCK_DGRAM, proto=0, fileno=None,
    options=()) -> socket.socket` — create, `setsockopt` each
    `SocketOption`, bind to `(ip, port)`, and return the socket.
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

- **`host_ip_interfaces(filter=True) -> Iterator[NetworkInterface]`** — the
  cross-platform interface enumerator (backed by `network/platform.py`).
  `filter=True` (default) excludes `APIPA` (link-local) addresses;
  `filter=False` (falsy) includes everything; or pass a
  `Callable[[NetworkInterface], bool]` predicate. Used by `DhcpListener`
  wildcard binding, the `pydhcp interfaces` CLI subcommand, and
  `DhcpServer`'s subnet lookup in `acquire_lease`/`get_inform_options`.
