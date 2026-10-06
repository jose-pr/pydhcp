# `pydhcp.network` — public API header

Header-file-style reference for `pydhcp.network`: network address types and
host interface discovery. All exports are also re-exported from the
top-level `pydhcp` package. The top-level package header ships beside this
one as `pydhcp/AGENTS.md`; for the project overview, install and CLI, see
<https://github.com/jose-pr/pydhcp> (the repo-root `AGENTS.md` is contributor orientation and is not part
of the installed package).

## Address types

- **`IPv4`** — alias for `ipaddress.IPv4Address`. **`IPv6`** — alias for
  `ipaddress.IPv6Address`. **`IP`** — `IPv4 | IPv6`. **`IPv4Network`** /
  **`IPv6Network`** / **`IPNetwork`** — `ipaddress` network types.
  **`IPv4Interface`** — alias for `ipaddress.IPv4Interface`.
- **`WILDCARD_IPv4`** — `IPv4("0.0.0.0")` constant.
- **`LINK_LOCAL_V4`** — `169.254.0.0/16` as an `IPv4Network`, re-exported from
  `netimps` under the same name; the default `host_ip_interfaces()` filter
  excludes addresses in this range.
- **`MACAddress(src=None)`** — a `netimps.MACAddress` subclass. Accepts colon,
  hyphen, dot/Cisco or bare hex text, a 48-bit `int`, 6 raw bytes, or another
  MAC; raises `ValueError` if the result isn't exactly 6 bytes. `str()` renders
  uppercase hyphen-separated (`"AA-BB-CC-DD-EE-FF"`), which is the only thing
  this subclass changes. `f"{mac}"` and `"%s" % mac` agree with `str()`;
  `format(mac, spec)` with a non-empty spec is netimps' (`MACAddress.format`).
  - **Not a `bytes` subclass** (the base type is a value object) — use
    `.packed` for the raw bytes.
  - Inherits `.hex(sep=None, bytes_per_sep=1)` (exactly `bytes.hex`),
    `.format(sep=":", *, upper=False)`, `.oui`, `.is_multicast`, `.is_local`,
    `parse`/`try_parse`/`is_valid` and ordering from netimps, and compares
    equal to a base `netimps.MACAddress` with the same bytes. Instances are
    read-only, `copy`/`pickle` keep the subclass, a bad value raises
    `netimps.NetimpsValueError` (a `ValueError`), and `try_parse` raises
    `TypeError` for a non-`str`. `as_str()` is gone: use `.format()`.
  - **A display type.** The wire hardware address (`chaddr`, option 61) is raw
    `bytes` throughout `packet/` and never passes through here — `chaddr`
    permits `hlen` up to 16 for non-Ethernet `htype`, while a MAC is exactly 6.
- **`HardwareAddressType`** (`IntEnum`) — the IANA ARP hardware types used by
  DHCP (the BOOTP `htype` field), `NONE` (0) through `HFI` (37), including
  `INFINIBAND` (32) for RFC 4390 IPoIB. Any other octet 0–255 becomes a cached
  **unnamed** pseudo-member, so a value a client sent is never rewritten.
  - `.label() -> str` — the member name, or `HTYPE_<n>` for an unnamed one.
    Use this, not `.name`, which is `None` for unnamed members;
    `to_mapping()` emits it and `HardwareAddressType("HTYPE_<n>")` reads it
    back.
  - `.dumps(address: bytes) -> str` renders colon-hex for `ETHERNET`, else
    `repr(address)`.
  - Also re-exported as `pydhcp.packet.HardwareAddressType`, which is where
    the rest of the message-header enums live and the spelling most code
    uses. It is *defined* here, beside `MACAddress`, because
    `pydhcp.options.type` needs it to name a client identifier's type octet
    and `pydhcp.packet.enums` imports `pydhcp.options.type` — defining it
    there made that a cycle.
- **`SocketAddress(ip, port=None)`** (`NamedTuple[ip: IPv4, port: int]`) —
  `ip` may be a `str`, an `IPv4`, or a bound `socket.socket` (reads
  `getsockname()`, in which case `port` must be omitted); passing a
  non-socket `ip` with `port=None` raises `ValueError`.
  - `.compat() -> tuple[str, int]` — plain `(str, int)` pair for stdlib socket
    calls.
  - `.listen(family=AF_INET, kind=SOCK_DGRAM, proto=0, fileno=None,
    options=(), *, broadcast=False, allow_address_takeover=False,
    connreset=True) -> socket.socket` — create, apply `options`, bind to
    `(ip, port)`, and return the socket. Delegates to `netimps.bind()`, which
    closes the socket before any exception propagates (a failed bind leaks
    nothing) and raises **`netimps.AddressInUseError`** (an `OSError`, never a
    `PermissionError`) for every "the port is taken" shape. The keyword-only
    arguments are `netimps.bind()`'s own. The address is **exclusive** unless
    `allow_address_takeover=True`: `SO_EXCLUSIVEADDRUSE` on Windows, no
    `SO_REUSEADDR` on POSIX. An explicit `fileno` takes the direct path.
- **`SocketOption`** — `netimps.SocketOption` (`NamedTuple[level, name,
  value]`), re-exported: one `setsockopt` call, as passed to
  `SocketAddress.listen(options=...)`.
- **`NetworkInterface`** (`NamedTuple[name: str, ip_interface:
  IPv4Interface | IPv6Interface, mac: MACAddress | None = None]`) — `.ip`
  and `.network` properties delegate to `ip_interface`.

## Interface discovery

- **`host_ip_interfaces(filter=True, family=4, *, cache=False) ->
  Iterator[NetworkInterface]`** — one entry **per address**, not per adapter,
  backed by `netimps.iter_addresses()`. `cache` is netimps' enumeration cache:
  `False` enumerates now, `True` reuses an enumeration up to
  `netimps.INTERFACE_CACHE_TTL` (1 s) old, a number is that TTL in seconds.
  Per-packet callers pass `True`; `DHCPListener.bind()` clears the cache.
  `filter=True` (default) excludes `LINK_LOCAL_V4` (APIPA) addresses;
  `filter=False` (falsy) includes everything; or pass a
  `Callable[[NetworkInterface], bool]` predicate. Used by `DHCPListener`
  wildcard binding, the `pydhcp interfaces` CLI subcommand, and
  `DHCPServer`'s subnet lookup in `acquire_lease`/`get_inform_options`.
  - `family` is `4` or `AF_INET`, `6` or `AF_INET6`, or `None`; anything else
    raises `ValueError`.
  - **`family=4` by default.** This is a DHCPv4 implementation and the previous
    enumerator was IPv4-only, so yielding IPv6 would silently change what
    existing callers iterate over. Pass `family=None` for both families.
  - Adapter names are the platform's **human-readable** name (`"Wi-Fi"`), not a
    Windows GUID as before, and **loopback is now included** — so a
    loopback-bound socket resolves to a real interface with its true `/8`
    rather than a synthetic `/32`.
