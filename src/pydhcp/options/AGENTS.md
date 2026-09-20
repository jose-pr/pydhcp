# `pydhcp.options` — public API header

Header-file-style reference for `pydhcp.options`: the DHCP options
container, the option-code registry, and the option payload codecs
(`pydhcp.options.type`). All exports are also re-exported from the
top-level `pydhcp` package. See the repo-root `AGENTS.md` for the project
overview and `src/pydhcp/AGENTS.md` for the top-level package header.

## Container (`__init__.py`)

- **`DhcpOptions(codemap=None)`** (`MutableMapping[int, bytearray]`) — the
  option bag carried by `DhcpMessage.options`.
  - **`get()` decodes; `[]` does not.** `options[53]` is
    `bytearray(b"\x05")` while `options.get(53)` is
    `DhcpMessageType.DHCPACK` — deliberately, and the only asymmetry in the
    container. Everything inherited from `MutableMapping` goes through
    `__getitem__`, so `dict(options)`, `.values()`, `.pop()`, `.setdefault()`
    and `.popitem()` all yield **raw `bytearray`s**, like `[]` and not like
    `.get()`. Write `get(code, decode=False)` when you want the bytes.
    `.items()` is the other deviation: see below. `codemap` defaults to
  `DhcpOptionCode`; pass a custom `BaseDhcpOptionCode` subclass to change
  code→type resolution. `__setitem__`/`__getitem__` key on the raw `int`
  code; values may be set as a `DhcpOptionType`, `bytes`/`bytearray`/
  `memoryview`, or any value the registered codec's constructor accepts.
  `__setitem__` is **atomic** — a codec that raises leaves the previous
  value (or the key's absence) untouched rather than an emptied option —
  and **copies** what it is given, so a `bytearray` the caller keeps and
  mutates afterwards does not write through into the stored option.
  Re-assigning an existing code keeps its position; order is wire-visible.
  - **`.get(key, default=None, *, decode=True) -> Any`** — `decode=True`
    (default) uses the code's registered `DhcpOptionType`; `decode=False`
    returns the raw `bytearray`; `decode=<type[DhcpOptionType]>` or
    `decode=<Callable[[bytearray], T]>` overrides the codec explicitly.
  - **`.items(decoded=True) -> list[DhcpOption]`** — `decoded=True` (default)
    or a codemap type returns a **`list`** of `DhcpOption` `(code, value)`
    pairs, freshly decoded; `decoded=False` returns the mapping's own
    `ItemsView[int, bytearray]` of raw payloads. Only the raw form is a live
    view — the decoded form builds new pairs, so it has no `.mapping` and no
    set operations.
  - **`.append(option)`** / **`.replace(option)`** — `option` is a
    `DhcpOption` or `(code, value)` tuple; `.append` concatenates onto any
    existing bytes for that code (RFC 3396 long-option splitting on
    decode/reassembly), `.replace` overwrites.
  - **`.decode(options: memoryview, base_offset=0) -> memoryview`** — parses
    a raw TLV options buffer into `self`, returning any unconsumed tail
    (used internally by `DhcpMessage.decode` for the options field and, on
    RFC 3396 overload, the `file`/`sname` fields). Malformed lengths log a
    warning rather than raising.
  - **`.encode(word_size=1) -> bytearray`** / **`.partial_encode(maxsize,
    word_size=1) -> tuple[bytearray, DhcpOptions | None]`** — serialize to
    TLV bytes; `partial_encode` stops once `maxsize` is reached and returns
    the leftover options as a second `DhcpOptions`, used by
    `DhcpMessage.encode`'s RFC 3396 packing.
  - **`.copy() -> DhcpOptions`** — independent copy: same codemap, every
    payload copied into a fresh `bytearray`. Use this before handing an
    options bag to code that mutates it (a response pipeline, an encoder);
    a plain assignment aliases the container *and* its payload buffers, so
    the mutations write straight back into the source.

## Option codes (`code.py`, `base.py`)

- **`DhcpOptionCode`** (`IntEnum` + `BaseDhcpOptionCode`) — the standard
  IANA option-code registry (`PAD`=0 … `END`=255 and everything in
  between), each member RFC-documented in its docstring. `.label() -> str`
  returns the enum member name (or `BaseDhcpOptionCode.label()`'s
  `"UNKNOWN"` fallback for an unregistered raw int). `.register_type(ty:
  type[DhcpOptionType]) -> None` binds a codec to a specific member;
  `.get_type() -> type[DhcpOptionType]` resolves it (calling
  `.ensure_registered()` first). `DhcpOptionCode.ensure_registered()` lazily
  imports `options/registry.py`, which calls `.register_type(...)` for every
  standard option — this runs automatically the first time a `DhcpOptions`
  keyed by `DhcpOptionCode` is constructed or a lookup is made, so
  application code never needs to call it directly. Unregistered codes
  (`PAD`, `END`, and any code without a `registry.py` entry) fall back to
  `Bytes` (opaque).
- **`BaseDhcpOptionCode`** — protocol/base for a custom code enum:
  `.get_type()`, `.label()`, `.from_code(code: int)` (classmethod,
  constructs/looks up a code value), `.normalize(code, value) -> DhcpOption`,
  `.decode(code, value: bytearray) -> DhcpOption`. Subclass this (instead of
  `DhcpOptionCode`) to build an application-specific option-code enum with
  its own codec bindings, and pass it as `DhcpOptions(codemap=...)`.
- **`DhcpOption`** (`NamedTuple[code: int | BaseDhcpOptionCode, value:
  DhcpOptionType]`) — one decoded/normalized option pair, as returned by
  `.decode`/`.normalize` and accepted by `DhcpOptions.append`/`.replace`.

**Gotcha**: `PAD` and `END` are intentionally never registered — they're
zero-length wire markers, not payload-bearing codecs.

**Gotcha**: option 43 (`VENDOR_SPECIFIC_INFORMATION`) is registered as
opaque `Bytes` by default — TLV parsing is opt-in via `TlvOption`, not
automatic. Option 125 is enterprise-number records, not generic TLVs. The
local `DhcpOptionCode.GRD` alias is IANA option 212 (`OPTION_6RD`).

## Option payload codecs (`pydhcp.options.type`)

Every codec implements the `DhcpOptionType` protocol: `_dhcp_read(option:
memoryview) -> tuple[Self, int]` (classmethod decode + bytes consumed),
`_dhcp_write(buffer: bytearray) -> int` (encode + bytes written), optional
`_dhcp_len_hint() -> int | None` (fixed-size codecs only), and `__json__()`
for structured (JSON/YAML/TOML/INI) round-tripping. `_dhcp_decode(bytes) ->
Self` / `_dhcp_encode() -> bytes` are the convenience wrappers built on top.

**Hashability**: every record codec is hashable and its hash agrees with its
`__eq__`, so decoded values can go into a `set` or be used as dict keys. The
**list** codecs (`List[T]`, `RecordList[T]`, `UserClass`, `DomainList`,
`PcpServerList`, `UriList`, `CccOption`, the `Vi*`/`MoS*` containers) are
mutable `list` subclasses and so are deliberately **not** hashable — build a
`tuple` from one if you need a key.

- **`DhcpOptionType`** — the base protocol above.
- **`List[T]`** (generic, subscript with a `DhcpOptionType`, e.g.
  `List[IPv4Address]`) — a homogeneous repeated-record list; items are
  normalized through `T(...)` on append/extend/`__setitem__`.
- **`RecordList[T]`** (`List[T]` subclass) — the same container for a record
  type built from **two** constructor arguments (`T(code, value)`). It differs
  from `List` only in normalization: a `tuple` argument is one record, not a
  sequence of items, so `EncapsulatedOptions((1, b"ab"))` is a single TLV;
  a `list` argument is several records. `EncapsulatedOptions`,
  `ViVendorSpecificInformation`, `ViVendorClass`, `MoSIpv4AddressList`,
  `MoSFqdnList` and `CccOption` are all `RecordList` subclasses. Subclass a
  subscripted form — `class MyOption(RecordList[MyRecord])`.
- **`DhcpOptionCodes[C]`** (`List[C]` subclass) — a list of raw option-code
  ints, used for `PARAMETER_REQUEST_LIST`-style options; falls back to a
  plain `int` (≤255) when the code type can't construct the item.

### Scalars (`scalar.py`)

- **`Bytes(src=None)`** — opaque byte payload; `src` a `str` (hex),
  bytes-like, or `None`. The default codec fallback for unregistered codes.
- **`String`** — RFC 2132 NVT-ASCII text, null-terminated on the wire.
  Octets that are not valid UTF-8 are **preserved**, not replaced (logged), so
  the value re-encodes to exactly what arrived — a hostname or boot filename in
  another encoding survives being forwarded. They are held as surrogates, so
  such a value cannot go to a strict encoder: `__json__()` returns the display
  form, with U+FFFD, and is what structured output uses. See `pydhcp.nvt`.
- **`OctetString`** (`String` subclass) — text that is the **whole** payload:
  no NUL terminator, no truncation. RFC 2132 §9.13 defines option 60 as "a
  string of n octets", so `String`'s partition at the first NUL threw away a
  binary vendor class identifier. Registered for `VENDOR_CLASS_IDENTIFIER`
  (60).
- **`UriList`** — list of UTF-8 URI strings, each U16-length-prefixed on the
  wire.
- **`Boolean(val)`** — single-octet boolean (`bool()` truthiness of `val`).
- **`Flag()`** — zero-length presence option: the option's meaning is that it
  is there at all, so it encodes no payload and rejects any. Registered for
  `RAPID_COMMIT` (80), which RFC 4039 §4 defines as "Code 80, Len 0".
  Assigning a falsy value raises; delete the option to express absence.
- **`BaseFixedLengthInteger`** / **`FixedLengthInteger`** — abstract fixed-
  width big-endian integer base; subclasses set `NUMBER_OF_BYTES`/`SIGNED`.
  **`U8`**/**`U16`**/**`U32`** (unsigned, 1/2/4 bytes), **`I32`** (signed,
  4 bytes) are the concrete codecs; encode raises `ValueError` on overflow
  or (for unsigned types) a negative value.
- **`ClientIdentifier`** (`Bytes` subclass) — RFC 2132 client identifier
  (leading type octet + address bytes); requires ≥2 bytes on decode.
- **`OptionOverload`** (`IntFlag`) — `NONE`/`FILE`/`SNAME`/`BOTH`; RFC 3396
  overload selector, single octet.

### Network types (`net.py`)

- **`IPv4Address`** (`ipaddress.IPv4Address` subclass) — single 4-byte IPv4
  address.
- **`ClasslessRoute(gateway, network)`** — RFC 3442 classless static route
  (variable-length prefix + gateway). Also accepts a single
  `(gateway, network)` pair or an existing instance, so routes normalize from
  JSON/YAML/config input. Options 121 and 249 are registered as
  **`List[ClasslessRoute]`**, not a bare `ClasslessRoute`: RFC 3442 defines one
  or more routes and a server sending the option SHOULD include the default
  route, so assign and expect a list.
- **`PolicyFilter`** / **`StaticRoute`** — lists of `(IPv4, IPv4)` 8-byte
  record pairs (destination/mask, destination/router respectively);
  `StaticRoute` rejects a `0.0.0.0` destination.
- **`DomainList`** — RFC 1035/3397 domain-name list with DNS-style
  compression-pointer support on both decode and encode (encode
  deduplicates common suffixes automatically). Names obey the same limits as
  every other option carrying one — 63 octets per label, 255 per name,
  measured on the uncompressed form — and an over-long label raises rather
  than writing a length octet that collides with the pointer flag bits. An
  empty entry is the root name and encodes as a single zero octet.
- **`ClientFqdn(name="", flags=0, rcode1=0, rcode2=0)`** — RFC 4702 client FQDN
  (option 81): flags, RCODE1, RCODE2, then the name. `FLAG_S`/`FLAG_O`/`FLAG_E`/
  `FLAG_N` are the defined bits; the name is RFC 1035 wire format when `FLAG_E`
  is set and ASCII otherwise, and `.encoded` reports which. Reserved flag bits
  and compression pointers are rejected on decode.
- **`SipServers(values=(), encoding=None)`** — RFC 3361 SIP servers (option
  120): `ENCODING_DOMAIN` (0) for RFC 1035 names, `ENCODING_ADDRESS` (1) for
  IPv4 addresses, written as a leading encoding octet. A plain list infers its
  encoding. `.values` is a list of strings either way.
- **`RdnssSelection(flags, primary, secondary, domains=None)`** — RFC 6731
  RDNSS selection record.
- **`DomainName`** — a single **uncompressed** RFC 1035 name as the whole
  payload, through the shared name helpers (so the 63/255-octet limits apply
  and a compression pointer is refused). Registered for `V4_DOTS_RI` (147,
  RFC 8973 §5.2) and `V4_ACCESS_DOMAIN` (213, RFC 5986 §3.2), which are label
  sequences rather than dotted text.
- **`StatusCode(code=0, message="")`** — RFC 6926 §6.2.2: a one-octet status
  code then an optional UTF-8 message. `.code` / `.message`; accepts a
  `(code, message)` pair or a mapping. Registered for `STATUS_CODE` (151),
  where a bare `U8` made any reply carrying the message undecodable.
- **`PcpServerList`** — RFC 7291 §4 PCP servers: a list of **entries**, each a
  list of IPv4 addresses written with a leading List-Length octet. A flat
  address list read that octet as address data. `PcpServerList(["192.0.2.1"])`
  is accepted as one entry.

### Vendor / TLV containers (`vendor.py`)

- **`UserClass`** — RFC 3004 list of opaque length-prefixed byte entries;
  zero-length entries are rejected on both encode and decode. **Opt-in:**
  option 77 is registered as opaque `Bytes`, because iPXE and several PXE ROMs
  send the option unframed and the strict codec rejects those packets. Ask for
  the structured form with `options.get(77, decode=UserClass)` — the same
  arrangement option 43 uses.
- **`TlvOption(code, value)`** — one generic `(code: int, value: Bytes)`
  TLV record.
- **`EncapsulatedOptions`** — TLV container used to build vendor-specific
  sub-option payloads.
- **`VendorSpecificInformation`** — option 43 payload (opaque `Bytes` by
  default; wrap with `TlvOption`/`EncapsulatedOptions` for structured TLV
  access).
- **`RelayAgentInformation`** — option 82 payload; constructed from a list
  of `(sub-code: int, value: bytes)` tuples (see `DhcpRelay`'s
  `insert_relay_agent_info`).
- **`ViVendorSpecificInformationRecord`** / **`ViVendorSpecificInformation`**
  — RFC 3925 vendor-identifying vendor-specific info (enterprise-number-
  keyed TLV records / their list container).
- **`ViVendorClassRecord`** / **`ViVendorClass`** — RFC 3925
  vendor-identifying vendor class (enterprise-number-keyed data / its list
  container).

### Domain names (`type/domain.py`)

Internal, but the single source of truth for every option carrying an RFC 1035
name — options 81, 120, 122, 139/140 and the 3397 search list all route here,
so a malformed name is accepted or refused identically whichever option carries
it. `MAX_LABEL_OCTETS` (63) and `MAX_NAME_OCTETS` (255) are the limits.

- `split_domain_name(name, what, allow_root=False) -> list[str]` — validate and
  return the labels. Separate from encoding so `DomainList`, whose compressed
  encoder cannot share the *encoding*, still shares the *rules*.
- `encode_domain_name(name, what, allow_root=False) -> bytes` — length-prefixed
  labels plus a root label. `allow_root` permits the empty name.
- `decode_domain_name(option, start=0, what) -> (str, octets_read)` — rejects
  compression pointers: with no enclosing message a pointer cannot resolve, and
  read as a length, `0xC0` silently yields a wrong name.

This module deliberately imports nothing from the package, so every codec
carrying a name can reach it with no import-order constraint.

### MoS records (`mos.py`, RFC 5678)

- **`MoSIpv4AddressRecord`** / **`MoSIpv4AddressList`** — Mobility Services
  IPv4-address record and its list container, shared by
  `IPV4_ADDRESS_MOS`.
- **`MoSFqdnRecord`** / **`MoSFqdnList`** — Mobility Services FQDN record
  (non-compressed domain labels) and its list container, shared by
  `IPV4_FQDN_MOS`.

### CCC sub-options (`type/ccc.py`, ISPWORKS/CableLabs CCC)

- **`CccOption`** — the option-125-style TLV container for CCC
  sub-options; **`CccSubOption`** — the sub-option TLV record base.
- Typed sub-option payloads, each a thin wrapper with its own
  `_dhcp_read`/`_dhcp_write`: **`CccPrimaryDhcpServerAddress`** /
  **`CccSecondaryDhcpServerAddress`** / **`CccProvisioningServerAddress`**
  (`IPv4Address`-backed), **`CccProvisioningServerFqdn`** /
  **`CccKerberosRealmName`** (no-DNS-compression domain text),
  **`CccAsReqAsRepBackoffRetry`** / **`CccApReqApRepBackoffRetry`** /
  **`CccProvisioningTimer`** (integer backoff/timer values),
  **`CccTicketGrantingServerUtilization`** / **`CccSecurityTicketControl`**
  (`U8`/`Boolean`-backed flags), **`CccKdcServerAddressList`** (`List[
  IPv4Address]`). Each has a matching `*SubOption` TLV-record wrapper
  (**`CccPrimaryDhcpServerAddressSubOption`**,
  **`CccSecondaryDhcpServerAddressSubOption`**,
  **`CccProvisioningServerAddressSubOption`**,
  **`CccAsReqAsRepBackoffRetrySubOption`**,
  **`CccApReqApRepBackoffRetrySubOption`**,
  **`CccKerberosRealmNameSubOption`**,
  **`CccTicketGrantingServerUtilizationSubOption`**,
  **`CccProvisioningTimerSubOption`**,
  **`CccSecurityTicketControlSubOption`**,
  **`CccKdcServerAddressSubOption`**) pairing the sub-option code with its
  typed value inside a `CccOption`.
