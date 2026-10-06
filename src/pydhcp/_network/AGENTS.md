# `pydhcp._network` — public API header

Header-file-style reference for `pydhcp._network`: pydhcp's own address and
interface types. Nothing here is an alias of a `netimps` or `ipaddress` object:
those are imported from `netimps` and `ipaddress`. `SocketAddress` and
`NetworkInterface` are also re-exported from the top-level `pydhcp` package. The top-level package header ships beside this
one as `pydhcp/AGENTS.md`; for the project overview, install and CLI, see
<https://github.com/jose-pr/pydhcp> (the repo-root `AGENTS.md` is contributor orientation and is not part
of the installed package).

## Types

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
    uses. It is *defined* here because `pydhcp.options._codecs` needs it to name a
    client identifier's type octet and `pydhcp.packet._enums` imports
    `pydhcp.options._codecs` — defining it there made that a cycle.
- **`SocketAddress(ip, port=None)`** (`NamedTuple[ip: IPv4Address, port: int]`) —
  `ip` may be a `str`, an `ipaddress.IPv4Address`, or a bound `socket.socket`
  (reads `getsockname()`, in which case `port` must be omitted); passing a
  non-socket `ip` with `port=None` raises `ValueError`. `str()` is
  `"host:port"`.
  - `.compat() -> tuple[str, int]` — plain `(str, int)` pair for stdlib socket
    calls.
  - It does not bind: the listener calls `netimps.bind()`, which raises
    **`netimps.AddressInUseError`** for every "the port is taken" shape and
    whose message is what the caller sees. It is a different thing from
    `netimps.SocketAddress`, which is a `(host, port)` tuple alias.
- **`NetworkInterface`** (`NamedTuple[name: str, ip_interface:
  IPv4Interface | IPv6Interface, mac: netimps.MACAddress | None = None]`) —
  `.ip` and `.network` properties delegate to `ip_interface`. A hardware
  address prints with `mac.format("-", upper=True)` where the form
  `AA-BB-CC-DD-EE-FF` is wanted (`pydhcp interfaces` does); `str(mac)` is
  netimps' own, lowercase and colon-separated.

## Interface discovery

- **`host_ip_interfaces(filter=True, family=4, *, cache=False) ->
  Iterator[NetworkInterface]`** — one entry **per address**, not per adapter,
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
