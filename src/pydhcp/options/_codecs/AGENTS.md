# `pydhcp.options` — public API header

Header-file-style reference for the option payload codecs of `pydhcp.options`: every class below is imported from
`pydhcp.options`; the container, the registry and the contract a codec satisfies are in
`pydhcp/options/AGENTS.md`. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; the top header is
`pydhcp/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

## Scalars (`pydhcp.options`)

```python
Bytes(value=None)
Bytes.parse(text)
Bytes.try_parse(text, default=None)
```

- **`Bytes`** — opaque byte payload; `value` is bytes-like or
  `None`, and text or a number (not a count of zero octets) is a `TypeError`.
  **`Bytes.parse()`** reads hex text
  (spaces and colons between octets are ignored; `DHCPValueError` for anything
  that is not whole hex octets, `TypeError` for a non-text) and
  **`Bytes.try_parse()`** answers `default` for text that
  does not parse. `str(Bytes(...))` is the upper-case hex that `parse` reads
  back; a structured document writes octets as hex text and `from_text` /
  `from_mapping` read it with `parse`. The default codec fallback for
  unregistered codes.

```python
String(value="")
```

- **`String`** — RFC 2132 NVT-ASCII text; `value` is text or octets
  (read as text), anything else is a `TypeError`: `None` is not an empty
  string, delete the option instead. **Not** null-terminated: the
  length octet delimits it, and `String("abc")` encodes to `b"abc"`. Some
  senders do append a NUL, so reading **ends the value at the first NUL
  octet**: `b"abc\x00"` and `b"abc\x00def"` both read as `'abc'` (RFC 2132 §2
  asks a receiver to delete trailing NULs; this drops what follows an
  embedded one as well, which `OctetString` does not). A value that holds a
  NUL therefore does not read back as it was written.
  Octets that are not valid UTF-8 are **preserved**, not replaced (logged at DEBUG), so
  the value re-encodes to exactly what arrived — a hostname or boot filename in
  another encoding survives being forwarded. They are held as surrogates, so
  such a value cannot go to a strict encoder: `to_json()` returns the display
  form, with U+FFFD, and is what structured output uses. See `pydhcp._nvt`.

- **`OctetString`** (`String` subclass) — text that is the **whole** payload:
  no NUL terminator, no truncation. RFC 2132 §9.13 defines option 60 as "a
  string of n octets", so `String`'s partition at the first NUL threw away a
  binary vendor class identifier. Registered for `VENDOR_CLASS_IDENTIFIER`
  (60).

```python
Boolean(val)
```

- **`URIList`** — list of UTF-8 URI strings, each U16-length-prefixed on the
  wire.
- **`Boolean`** — single-octet boolean (`bool()` truthiness of `val`).

```python
Flag(value=True)
```

- **`Flag`** — zero-length presence option: the option's meaning is that it
  is there at all, so it encodes no payload and rejects any. Registered for
  `RAPID_COMMIT` (80), which RFC 4039 §4 defines as "Code 80, Len 0".
  Assigning a falsy value raises; delete the option to express absence.

- **`BaseFixedLengthInteger`** / **`FixedLengthInteger`** — abstract fixed-
  width big-endian integer base; subclasses set `NUMBER_OF_BYTES`/`SIGNED`.
  **`U8`**/**`U16`**/**`U32`** (unsigned, 1/2/4 bytes), **`I32`** (signed,
  4 bytes) are the concrete codecs. The constructor takes a whole number (or
  its text) and raises `DHCPValueError` outside the type's range
  (`I32`: -2147483648 to 2147483647) and `TypeError` for a float or other type.
- **`ClientIdentifier`** (`Bytes` subclass) — RFC 2132 client identifier
  (leading type octet + address bytes); requires ≥2 bytes on decode.
- **`OptionOverload`** (`IntFlag`) — `NONE`/`FILE`/`SNAME`/`BOTH`; RFC 2132 §9.3
  option-overload selector (option 52), single octet.

## Network types (`pydhcp.options`)

Split by family: addresses and routes, domain-name lists and single names, the
client FQDN, and server-locator/status codecs. Import every one of them from
`pydhcp.options`.

- **`IPv4AddressOption`** (`ipaddress.IPv4Address` subclass) — single 4-byte IPv4
  address.

```python
ClasslessRoute(gateway, network=None)
ClasslessRoute.parse(text)
ClasslessRoute.try_parse(text, default=None)
```

- **`ClasslessRoute`** — RFC 3442 classless static route
  (variable-length prefix + gateway). Also accepts a single
  `(gateway, network)` pair or an existing instance, so routes normalize from
  JSON/YAML/config input. `str(route)` is `"10.0.0.0/8 via 192.0.2.1"` and
  `ClasslessRoute.parse(text)` / `.try_parse(text, default=None)` read that
  (`DHCPValueError` for anything else, host bits in the network included).
  A destination **read** with host bits set is masked to its prefix (RFC 3442
  §3: "the client MUST zero any bits ... where the corresponding bit in the mask
  is zero"; the RFC's own case is 129.210.177.132/25, installed as
  129.210.177.128/25), so one out-of-spec route does not cost the option;
  the constructor stays strict. Options 121 and 249 are registered as
  **`List[ClasslessRoute]`**, not a bare `ClasslessRoute`: RFC 3442 defines one
  or more routes and a server sending the option SHOULD include the default
  route, so assign and expect a list.

- **`PolicyFilter`** / **`StaticRoute`** — lists of `(IPv4, IPv4)` 8-byte
  record pairs (destination/mask, destination/router respectively);
  `StaticRoute` rejects a `0.0.0.0` destination when it is built or written
  and **keeps one it reads** (RFC 2132 §5.8 forbids a sender it, and a receiver
  keeps what a peer sent).
- **`DomainList`** — RFC 1035/3397 domain-name list with DNS-style
  compression-pointer support on both decode and encode (encode
  deduplicates common suffixes automatically). Names obey the same limits as
  every other option carrying one — 63 octets per label, 255 per name,
  measured on the uncompressed form — and an over-long label raises rather
  than writing a length octet that collides with the pointer flag bits. An
  empty entry is the root name and encodes as a single zero octet.
  Normalizes like `List[T]`: a `list`/`tuple` argument is several entries,
  **anything else is one entry**, and every entry must be a `str`
  (`TypeError` otherwise). So `DomainList("corp")` is `["corp"]` — it is a
  `list[str]` subclass, and without this a bare `str` was read as an
  iterable of *characters*. Registered for `DOMAIN_SEARCH` (119, RFC 3397)
  and `SIP_UA_CONFIG_SERVICE_DOMAINS` (141, RFC 6011 §4.1), the two options
  that **require** the compressed form.
  **Decode bounds** (the reader serves options 119, 141, 88, 120 and 146): a
  decoded name is at most 255 octets (RFC 1035 §2.3.4), a name follows at
  most 127 compression pointers (`MAX_POINTER_HOPS`), and a pointer must
  point strictly backwards, at the start of a label or root label of an
  earlier name. A name, pointer, reserved length prefix or label running past
  the end is a `DHCPDecodeError`. A last name that ends between labels, or after
  half a pointer, without a root label or a whole pointer is **discarded**
  (RFC 3397 §3) and the names before it are kept.
- **`UncompressedDomainList`** (`DomainList` subclass) — the same container,
  encoding through the shared `_codecs/_domain.py` name encoder so it never
  emits a compression pointer. Registered for `BCMCS_DOMAIN_NAME_LIST` (88)
  and used for `RDNSSSelection.domains` (146), whose RFCs forbid
  compression: RFC 4280 §4.6 ("DNS name compression MUST NOT be used") and
  RFC 6731 §4.3 via RFC 3315 §8 ("MUST NOT be stored in compressed form").
  **Encode-only** — decoding is `DomainList`'s and still resolves a pointer
  that arrives, because a payload from a non-conforming peer is readable and
  this package is liberal on receive.
  *Gotcha*: this is chosen by the **registry**, so `options[88] = [...]`
  gets it. Assigning an explicit `DomainList(...)` instance to option 88
  bypasses the registry (any `DHCPOptionType` is written as given) and
  compresses — pass a plain list, or `UncompressedDomainList`.

```python
ClientFQDN(name="", flags=0, rcode1=0, rcode2=0, partial=False)
ClientFQDN.parse(text)
ClientFQDN.try_parse(text, default=None)
```

- **`ClientFQDN`** — RFC 4702
  client FQDN (option 81): flags, RCODE1, RCODE2, then the name. `FLAG_S`/
  `FLAG_O`/`FLAG_E`/`FLAG_N` are the defined bits (`FLAGS_MASK`, `0x0F`, holds them all); the name is RFC 1035 wire
  format when `FLAG_E` is set and ASCII otherwise, and `.encoded` reports
  which. With the E bit the field is a qualified name (with the terminating
  label), a **partial** name (without it) or empty (RFC 4702 §2.3):
  `.partial` is true for a partial name and for an empty field, false for a
  qualified name and for the root (a lone terminator), and encode writes
  exactly what was decoded. `partial=True` needs the E bit. The reserved
  flag bits (`0xF0`) are ignored on decode and `flags` holds only the low
  four; constructing with one set raises `DHCPValueError`. A compression
  pointer, a label cut short or data after the terminator is a `DHCPDecodeError`.
  `str()` is the name, followed by ` [flags=0x05 rcode1=0 rcode2=0 partial]` when any of
  those is set; `ClientFQDN.parse(text)` / `.try_parse(text, default=None)` read that
  (`DHCPValueError` for a malformed bracket or a reserved flag bit).

```python
SIPServers(values=(), encoding=None)
```

- **`SIPServers`** — RFC 3361 SIP servers (option
  120): `ENCODING_DOMAIN` (0) for RFC 1035 names, `ENCODING_ADDRESS` (1) for
  IPv4 addresses, written as a leading encoding octet. A plain list infers its
  encoding. `.values` is a tuple of strings either way. Names are **read
  compressed** (RFC 3361 §3.1: clients MUST support it) with the search list's
  bounds (255 octets a name, 127 pointers, a pointer to an earlier name); a
  pointer counts from the encoding octet, the start of the option data. A last
  name that does not end is a `DHCPDecodeError`. Names are written uncompressed.

```python
RDNSSSelection(flags, primary=None, secondary=None, domains=None)
```

- **`RDNSSSelection`** — RFC 6731
  RDNSS selection record. `.domains` is an `UncompressedDomainList` and
  normalizes like one, so `RDNSSSelection(..., "a.com").domains` is
  `["a.com"]` rather than one entry per character. The root name (`""`, spelled
  `"."` too) marks the default RDNSS (§4.3): it is kept on decode, last or not,
  and written as a single zero octet. The six high bits of `flags` are reserved
  and ignored on receipt (`PREFERENCE_BITS`, `0x03`, keeps the two low ones), so a decoded `flags` is 0 to 3. Also built from one
  sequence, the `(flags, primary, secondary, domains)` that `to_json` emits.

- **`DomainName`** — a single **uncompressed** RFC 1035 name as the whole
  payload, through the shared name helpers (so the 63/255-octet limits apply
  and a compression pointer is refused). Registered for `V4_DOTS_RI` (147,
  RFC 8973 §5.2) and `V4_ACCESS_DOMAIN` (213, RFC 5986 §3.2), which are label
  sequences rather than dotted text.

```python
StatusCode(code=0, message="")
StatusCode.parse(text)
StatusCode.try_parse(text, default=None)
```

- **`StatusCode`** — RFC 6926 §6.2.2: a one-octet status
  code then an optional UTF-8 message. `.code` / `.message`; accepts a
  `(code, message)` pair or a mapping. `str()` is `"<code> <message>"` (just
  the code when there is no message); `StatusCode.parse(text)` /
  `.try_parse(text, default=None)` read it, the message being everything after
  the first space. Registered for `STATUS_CODE` (151),
  where a bare `U8` made any reply carrying the message undecodable.

- **`PCPServerList`** — RFC 7291 §4 PCP servers: a list of **entries**, each a
  list of IPv4 addresses written with a leading List-Length octet. A flat
  address list read that octet as address data. `PCPServerList(["192.0.2.1"])`
  is accepted as one entry.

## Vendor and TLV containers (`pydhcp.options`)

```python
TLVOption(code, value)
```

- **`UserClass`** — RFC 3004 list of opaque length-prefixed byte entries;
  zero-length entries are rejected on both encode and decode. **Opt-in:**
  option 77 is registered as opaque `Bytes`, because iPXE and several PXE ROMs
  send the option unframed and the strict codec rejects those packets. Ask for
  the structured form with `options.get(77, decode=UserClass)` — the same
  arrangement option 43 uses.
- **`TLVOption`** — one generic `(code: int, value: Bytes)`
  TLV record.
- **`EncapsulatedOptions`** — TLV container for building vendor-specific
  sub-option payloads.
- **`VendorSpecificInformation`** — option 43 payload (opaque `Bytes` by
  default; wrap with `TLVOption`/`EncapsulatedOptions` for structured TLV
  access).
- **`RelayAgentInformation`** — option 82 payload; sub-options are plain
  code, length, value tuples, so 0 and 255 are ordinary sub-option codes
  (RFC 3046 §2.0: no pad sub-option, no terminating 255), unlike
  `EncapsulatedOptions`; constructed from a list
  of `(sub-code: int, value: bytes)` tuples (see `DHCPRelay`'s
  `insert_relay_agent_info`).
- **`VIVendorSpecificInformationRecord`** / **`VIVendorSpecificInformation`**
  — RFC 3925 vendor-identifying vendor-specific info (enterprise-number-
  keyed TLV records / their list container).
- **`VIVendorClassRecord`** / **`VIVendorClass`** — RFC 3925
  vendor-identifying vendor class (enterprise-number-keyed data / its list
  container). Each entry may be bytes or the hex text `to_json` writes, so a
  message written as JSON, YAML or TOML reads back as the same value.

## Domain names (`pydhcp.options._codecs._domain`)

```python
split_domain_name(name, what="domain name", allow_root=False) -> list[str]
encode_domain_name(name, what="domain name", allow_root=False) -> bytes
decode_domain_name(option, start=0, what="domain name") -> tuple[str, int]
```

Internal, but the single source of truth for every option carrying an RFC 1035
name — options 81, 120, 122, 139/140, 88/146 (via
`UncompressedDomainList`) and the 3397 search list all route here, so a
malformed name is accepted or refused identically whichever option carries
it. `MAX_LABEL_OCTETS` (63) and `MAX_NAME_OCTETS` (255) are the limits.

- `split_domain_name()` — validate and
  return the labels. Separate from encoding so `DomainList`, whose compressed
  encoder cannot share the *encoding*, still shares the *rules*.
- `encode_domain_name()` — length-prefixed
  labels plus a root label. `allow_root` permits the empty name.
- `decode_domain_name()` — rejects
  compression pointers: with no enclosing message a pointer cannot resolve, and
  read as a length, `0xC0` silently yields a wrong name.

This module deliberately imports nothing from the package, so every codec
carrying a name can reach it with no import-order constraint.

## MoS records (`pydhcp.options`)

- **`MoSIPv4AddressRecord`** / **`MoSIPv4AddressList`** — Mobility Services
  IPv4-address record and its list container, shared by
  `IPV4_ADDRESS_MOS`.
- **`MoSFQDNRecord`** / **`MoSFQDNList`** — Mobility Services FQDN record
  (non-compressed domain labels) and its list container, shared by
  `IPV4_FQDN_MOS`.

## CCC sub-options (`pydhcp.options`)

- **`CCCOption`** — the TLV sub-option container for **option 122**
  (RFC 3495). It is *not* "option-125-style": option 125 carries
  enterprise-number records, as this header says a few sections up, and the
  two are different shapes. **`CCCSubOption`** — the sub-option TLV record base.
- Typed sub-option payloads, each a thin wrapper with its own
  `unpack_from`/`pack_into`: **`CCCPrimaryDHCPServerAddress`** /
  **`CCCSecondaryDHCPServerAddress`** (`IPv4AddressOption`-backed);
  **`CCCProvisioningServerAddress`**, which is **not** `IPv4AddressOption`-backed but
  a *tagged union* — a leading type octet selects an IPv4 address (1) or an
  FQDN (0), so it carries whichever the sender used;
  **`CCCProvisioningServerFQDN`** / **`CCCKerberosRealmName`**
  (no-DNS-compression domain text; a realm built by hand is upper-cased, one
  read from the wire keeps the case it arrived in); **`CCCASBackoffRetry`** /
  **`CCCAPBackoffRetry`** / **`CCCProvisioningTimer`** (integer
  backoff/timer values); **`CCCTicketGrantingServerUtilization`**, a
  `Boolean`; **`CCCSecurityTicketControl`**, a **16-bit integer mask** and not
  a flag; and **`CCCKDCServerAddressList`**
  (`List[IPv4AddressOption]`). Each has a matching `*SubOption` TLV-record wrapper
  (**`CCCPrimaryDHCPServerAddressSubOption`**,
  **`CCCSecondaryDHCPServerAddressSubOption`**,
  **`CCCProvisioningServerAddressSubOption`**,
  **`CCCASBackoffRetrySubOption`**,
  **`CCCAPBackoffRetrySubOption`**,
  **`CCCKerberosRealmNameSubOption`**,
  **`CCCTicketGrantingServerUtilizationSubOption`**,
  **`CCCProvisioningTimerSubOption`**,
  **`CCCSecurityTicketControlSubOption`**,
  **`CCCKDCServerAddressSubOption`**) pairing the sub-option code with its
  typed value inside a `CCCOption`.
