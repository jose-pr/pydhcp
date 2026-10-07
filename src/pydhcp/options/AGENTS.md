# `pydhcp.options` — public API header

Header-file-style reference for `pydhcp.options`: the DHCP options
container, the option-code registry, and the option payload codecs
(private modules under `pydhcp.options._codecs`, exported from `pydhcp.options`).
Every name below is importable from `pydhcp.options`; the top-level `pydhcp`
package re-exports only the container, the code enum, the integers `U8`,
`U16` and `U32` and the list and vendor codecs a handler commonly assigns; the
top header's table names every one it does not. The top-level package header ships beside this
one as `pydhcp/AGENTS.md`; for the project overview, install and CLI, see
<https://github.com/jose-pr/pydhcp> (the repo-root `AGENTS.md` is contributor orientation and is not part
of the installed package).

## Container (`__init__.py`)

- **`DHCPOptions(codemap=None)`** (`MutableMapping[int, bytearray]`) — the
  option bag carried by `DHCPMessage.options`.
  - **`get()` decodes; `[]` does not.** `options[53]` is
    `bytearray(b"\x05")` while `options.get(53)` is
    `DHCPMessageType.DHCPACK` — deliberately, and the only asymmetry in the
    container. Everything inherited from `MutableMapping` goes through
    `__getitem__`, so `dict(options)`, `.values()`, `.pop()`, `.setdefault()`
    and `.popitem()` all yield **raw `bytearray`s**, like `[]` and not like
    `.get()`. Write `get(code, decode=False)` when you want the bytes.
    `.items()` is the other deviation: see below. `.setdefault(code, value)`
    stores `value` when the code is absent and answers the raw `bytearray`
    either way. `codemap` defaults to
  `DHCPOptionCode`; pass a custom `BaseDHCPOptionCode` subclass to change
  code→type resolution. `__setitem__`/`__getitem__` key on the raw `int`
  code; values may be set as a `DHCPOptionType`, `bytes`/`bytearray`/
  `memoryview`, or any value the registered codec's constructor accepts.
  `__setitem__` and `.append()` are **atomic** — a codec that raises leaves
  the previous value (or the key's absence) untouched rather than an emptied
  option — and `__setitem__` **copies** what it is given, so a `bytearray` the
  caller keeps and mutates afterwards does not write through into the stored
  option. A value its codec refuses raises the codec's own exception class
  (`TypeError` or `ValueError`) with the message starting `option 12
  (HOSTNAME) cannot hold a NoneType:`. **`==` compares raw payloads** (the same
  codes and octets, in any order; nothing is decoded, so it never raises) and
  is `NotImplemented` against anything but another `DHCPOptions`, a `dict`
  included; a bag is unhashable.
  Re-assigning an existing code keeps its position; order is wire-visible.
  `__setitem__` and `.append()` **check the code**: it must be an `int`
  (`bool` is refused) in `MIN_OPTION_CODE`..`MAX_OPTION_CODE` (**1..254**,
  both exported from `pydhcp.options`). `0` (PAD) and `255` (END) raise
  `ValueError` — they are wire framing, not options: stored, they would be
  sent as `00 02 ..` / `ff 02 ..` TLVs that a receiver reads as padding and as
  end-of-options. A code above 255 raises here too. `.decode()` is
  deliberately **not** checked: receive stays liberal and already treats 0
  and 255 as framing.
  - **`.get(key, default=None, decode=True) -> Any`** — `key` is positional
    only (`get(key=53)` is a `TypeError`); `decode=True`
    (default) uses the code's registered `DHCPOptionType`; `decode=False`
    returns the raw `bytearray`; `decode=<type[DHCPOptionType]>` or
    `decode=<Callable[[bytearray], T]>` overrides the codec explicitly.
  - **`.items(decoded=True) -> list[DHCPOption]`** — `decoded=True` (default)
    or a codemap type returns a **`list`** of `DHCPOption` `(code, value)`
    pairs, freshly decoded; `decoded=False` returns the mapping's own
    `ItemsView[int, bytearray]` of raw payloads. Only the raw form is a live
    view — the decoded form builds new pairs, so it has no `.mapping` and no
    set operations.
  - **`.append(option)`** / **`.replace(option)`** — `option` is a
    `DHCPOption` or `(code, value)` tuple; `.append` concatenates onto any
    existing bytes for that code (RFC 3396 long-option splitting on
    decode/reassembly), `.replace` overwrites.
  - **`DHCPOptions.decode(data: bytes | bytearray | memoryview, *, codemap=None)
    -> DHCPOptions`** (classmethod) — parses a raw TLV options buffer into a
    new bag: PAD is skipped, END stops the parse, octets after END are
    ignored, a repeated code is joined (RFC 3396 long-option splitting).
    Malformed lengths log at DEBUG rather than raising (a listener counts the
    datagram in `metrics.packets_decoded_leniently`). (`DHCPMessage.decode`
    reads the options field and, on **RFC 2132 §9.3** option overload, the
    `file`/`sname` fields into one bag — option 52, a different mechanism.)
  - **`.encode(word_size=1) -> bytearray`** / **`.partial_encode(maxsize,
    word_size=1) -> tuple[bytearray, DHCPOptions | None]`** — serialize to
    TLV bytes; `partial_encode` stops once `maxsize` is reached and returns
    the leftover options as a second `DHCPOptions`, used by
    `DHCPMessage.encode`'s RFC 3396 packing.
    **`word_size`** pads the END marker to a multiple of that many octets, so
    the options field finishes on a word boundary — at 4, END is
    `ff 00 00 00` rather than a bare `ff` — and reserves that much room when
    deciding what still fits. Nothing in this package passes anything but 1;
    it is there for a caller writing into a fixed-layout buffer read
    word-aligned, which is a property of that consumer and not of DHCP. RFC
    2131 requires no alignment.
  - **`.copy() -> DHCPOptions`** — independent copy: same codemap, every
    payload copied into a fresh `bytearray`. Use this before handing an
    options bag to code that mutates it (a response pipeline, an encoder);
    a plain assignment aliases the container *and* its payload buffers, so
    the mutations write straight back into the source.
  - **`.retain(codes) -> None`** — keep only the options whose code is in `codes`
    (any iterable of integers or option codes), in their present order; the
    rest are deleted. A read-only bag raises `TypeError`, even when nothing would go.

- The `MISSING` sentinel this module uses to tell "no default given" from
  "default is `None`" lives in `pydhcp._generic`, not in `pydhcp._constants` — it
  is a Python idiom rather than a DHCP constant, and it is private.

## Option codes (`_codes.py`)

- **`DHCPOptionCode`** (`IntEnum` + `BaseDHCPOptionCode`) — the standard
  IANA option-code registry (`PAD`=0 … `END`=255 and everything in
  between), each member RFC-documented in its docstring. `.label() -> str`
  returns the enum member name (or `BaseDHCPOptionCode.label()`'s
  `"UNKNOWN"` fallback for an unregistered raw int). `.register_type(ty:
  type[DHCPOptionType]) -> None` binds a codec to a specific member;
  `.get_type() -> type[DHCPOptionType]` resolves it. The built-in codecs are
  bound to the standard codes when the options package is imported
  (`options/_registry.py` calls `.register_type(...)` for each), so a lookup
  never depends on an earlier call and *your* registration is always the later
  write. Unregistered codes (`PAD`, `END`, and any code without a registry
  entry) fall back to `Bytes` (opaque). `DHCPMessageType`, the codec of option
  53, is defined in the options package and re-exported by `pydhcp.packet` and
  the root; a number it has no name for is an unnamed member carrying it
  (`.label()` is `TYPE_<n>`), never refused.
- **`OptionCode`** — the `typing.Protocol` of a code enum (`get_type`, `label`,
  `int()`, and the classmethods `from_code`, `normalize`, `decode`), which
  `DHCPOptions(codemap=...)` takes; **`BaseDHCPOptionCode`** — its base class with
  the defaults, for a custom code enum:
  `.get_type()`, `.label()`, `.from_code(code: int)` (classmethod,
  constructs/looks up a code value), `.normalize(code, value) -> DHCPOption`,
  `.decode(code, value: bytearray) -> DHCPOption`. Subclass this (instead of
  `DHCPOptionCode`) to build an application-specific option-code enum with
  its own codec bindings, and pass it as `DHCPOptions(codemap=...)`.
  `int(code)` is the `value` attribute (an `IntEnum` member has one) or, for
  an `int` subclass, its own integer identity; a subclass with **neither**
  raises `TypeError` rather than answering `0`, which is PAD. `repr()` never
  raises, so such a code still prints as `[000]UNKNOWN` while you debug it.
- **`DHCPOption`** (`NamedTuple[code: int | BaseDHCPOptionCode, value:
  DHCPOptionType]`) — one decoded/normalized option pair, as returned by
  `.decode`/`.normalize` and accepted by `DHCPOptions.append`/`.replace`.

**Gotcha**: `PAD` and `END` are intentionally never registered — they're
zero-length wire markers, not payload-bearing codecs. They are also not
storable: `options[0]` / `options[255]` raise, see `DHCPOptions` above.

**Gotcha**: option 43 (`VENDOR_SPECIFIC_INFORMATION`) is registered as
opaque `Bytes` by default — TLV parsing is opt-in via `TLVOption`, not
automatic. Option 125 is enterprise-number records, not generic TLVs. The
`DHCPOptionCode.SIXRD` is IANA option 212 (`OPTION_6RD`); `GRD` is an alias member
of it, so `DHCPOptionCode(212).name` is `SIXRD`.

## Option payload codecs (`pydhcp.options`)

### Writing a codec (`OptionCodec`)

`OptionCodec` is the `typing.Protocol` a codec satisfies; `isinstance(x,
OptionCodec)` is a run-time check that the methods exist (names only, not
signatures). `DHCPOptionType` is the base class that supplies all of it but
the three things a codec writes itself:

- **the constructor `Codec(value)`** — one argument: a value, or what a
  document holds (what `to_json()` returned). Validate here and raise
  `DHCPValueError` for a value the option cannot carry.
- **`unpack_from(cls, option: memoryview) -> tuple[Codec, int]`** (classmethod)
  — read one value from the start of `option`; return it and the number of
  octets it took. Raise `DHCPDecodeError` for octets that are not a value. A
  list codec calls it repeatedly on the rest of the payload.
- **`pack_into(self, buffer: bytearray) -> int`** — append the payload's octets
  to `buffer`; return how many.

and may override these, each with a default:

- **`fixed_size(cls) -> int | None`** (classmethod) — the exact payload length
  of every value; `unpack` refuses any other length. Default `None`.
- **`to_json(self) -> Any`** — the value as plain data (`str`, `int`, `bool`,
  `list`, `dict`) for a JSON, YAML, TOML or INI document. Default: the value
  itself. `Codec(value.to_json())` must equal `value`: `from_text` and
  `from_mapping` rebuild a value that way.
- **`display_text(self) -> str`** — what `message.summary()`, the log and the
  capture formats show. Default: `repr(value)`.

What the base adds: **`Codec.unpack(data) -> Codec`** (classmethod) reads the
whole payload — `fixed_size` is checked, octets `unpack_from` did not take are
an error, and a `DHCPValueError` the constructor raises becomes a
`DHCPDecodeError` — and **`value.pack() -> bytes`** returns the payload.

*Registering.* `DHCPOptionCode(code).register_type(Codec)` binds the codec to
an option code, a name the enum lacks (`DHCPOptionCode(224)`) as much as a
member, for the rest of the process; `register_type(Bytes)` puts the opaque
default back. After that `options[code] = value` (or any value `Codec(...)`
accepts), `options.get(code)`, `DHCPMessage.decode`/`.encode`,
`message.summary()` and `from_text`/`to_text` in all four formats use it. A
class that is not a `DHCPOptionType` but has the methods of `OptionCodec`
registers too.

*Names.* The contract is `pack`/`unpack`, not `encode`/`decode`, because the
codecs that subclass a builtin keep its methods: `Bytes.decode` is
`bytes.decode` and `String.encode` is `str.encode`.

**Values.** Every codec is a value: it copies, deep-copies and pickles to an
equal value of the same class (the classes `List[...]` builds pickle too, in
another process as well), and `repr()` is the constructor call that rebuilds
it (`ClasslessRoute(gateway='192.0.2.1', network='10.0.0.0/8')`,
`U8(1)`, `DHCPMessageType.DHCPACK`).

- **Record codecs** (`ClasslessRoute`, `ClientFQDN`, `StatusCode`, `SIPServers`,
  `RDNSSSelection`, `TLVOption`, the `VI*`, `MoS*` and `CCC*` records) are
  read-only: assigning or deleting an attribute raises `AttributeError`, and
  a list a record holds (`RDNSSSelection.domains`, `VIVendorClassRecord.value`,
  a `MoS*`/`CCC*` record's list payload) is a read-only copy that raises
  `TypeError` on any change. Equal records hash equal, so they can go into a
  `set` or be dict keys. Comparing a record with another type returns
  `NotImplemented`.
- **List codecs** (`List[T]`, `RecordList[T]`, `UserClass`, `DomainList`,
  `UncompressedDomainList`, `PCPServerList`, `URIList`, `CCCOption`, the
  `VI*`/`MoS*` containers, `PolicyFilter`, `StaticRoute`) are `list`
  subclasses and so **not** hashable: build a `tuple` from one if you need a
  key. Every operation that adds an item normalizes it first: `append`,
  `extend`, `insert`, `+=`, `[i] = x` and slice assignment (each item of the
  slice, not the slice as one item). A refused item raises `DHCPValueError`,
  or `TypeError` for a wrong type, and leaves the list unchanged.
- **Builtin-subclass codecs** (`Bytes`, `String`, `IPv4AddressOption`, the
  integers, `Boolean`, `OptionOverload`, `DHCPMessageType`) compare and hash as
  the builtin they subclass: `options.get(51) == 86400`,
  `String("a") == "a"`, `address in network`. That is documented and kept;
  `Boolean(1) == U8(1)` follows from it.

- **`DHCPOptionType`** — the base class above; **`OptionCodec`** — its protocol.
- **`List[T]`** (generic, subscript with a `DHCPOptionType`, e.g.
  `List[IPv4AddressOption]`) — a homogeneous repeated-record list; items are
  normalized through `T(...)` on every operation that adds an item.
- **`RecordList[T]`** (`List[T]` subclass) — the same container for a record
  type built from **two** constructor arguments (`T(code, value)`). It differs
  from `List` only in normalization: a `tuple` argument is one record, not a
  sequence of items, so `EncapsulatedOptions((1, b"ab"))` is a single TLV;
  a `list` argument is several records. `EncapsulatedOptions`,
  `VIVendorSpecificInformation`, `VIVendorClass`, `MoSIPv4AddressList`,
  `MoSFQDNList` and `CCCOption` are all `RecordList` subclasses. Subclass a
  subscripted form — `class MyOption(RecordList[MyRecord])`.
- **`DHCPOptionCodes[C]`** (`List[C]` subclass) — a list of raw option-code
  ints, used for `PARAMETER_REQUEST_LIST`-style options; falls back to a
  plain `int` (≤255) when the code type can't construct the item.

### Scalars (`_scalar.py`)

- **`Bytes(value=None)`** — opaque byte payload; `value` is bytes-like or
  `None`, and text or a number (not a count of zero octets) is a `TypeError`.
  **`Bytes.parse(text)`** reads hex text
  (spaces and colons between octets are ignored; `DHCPValueError` for anything
  that is not whole hex octets, `TypeError` for a non-text) and
  **`Bytes.try_parse(text, default=None)`** answers `default` for text that
  does not parse. `str(Bytes(...))` is the upper-case hex that `parse` reads
  back; a structured document writes octets as hex text and `from_text` /
  `from_mapping` read it with `parse`. The default codec fallback for
  unregistered codes.
- **`String(value="")`** — RFC 2132 NVT-ASCII text; `value` is text or octets
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
- **`URIList`** — list of UTF-8 URI strings, each U16-length-prefixed on the
  wire.
- **`Boolean(val)`** — single-octet boolean (`bool()` truthiness of `val`).
- **`Flag()`** — zero-length presence option: the option's meaning is that it
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

### Network types (`_addresses.py`, `_domains.py`, `_fqdn.py`, `_servers.py`)

Split by family: addresses and routes, domain-name lists and single names, the
client FQDN, and server-locator/status codecs. Import every one of them from
`pydhcp.options`.

- **`IPv4AddressOption`** (`ipaddress.IPv4Address` subclass) — single 4-byte IPv4
  address.
- **`ClasslessRoute(gateway, network)`** — RFC 3442 classless static route
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
- **`ClientFQDN(name="", flags=0, rcode1=0, rcode2=0, partial=False)`** — RFC 4702
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
- **`SIPServers(values=(), encoding=None)`** — RFC 3361 SIP servers (option
  120): `ENCODING_DOMAIN` (0) for RFC 1035 names, `ENCODING_ADDRESS` (1) for
  IPv4 addresses, written as a leading encoding octet. A plain list infers its
  encoding. `.values` is a tuple of strings either way. Names are **read
  compressed** (RFC 3361 §3.1: clients MUST support it) with the search list's
  bounds (255 octets a name, 127 pointers, a pointer to an earlier name); a
  pointer counts from the encoding octet, the start of the option data. A last
  name that does not end is a `DHCPDecodeError`. Names are written uncompressed.
- **`RDNSSSelection(flags, primary, secondary, domains=None)`** — RFC 6731
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
- **`StatusCode(code=0, message="")`** — RFC 6926 §6.2.2: a one-octet status
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

### Vendor / TLV containers (`_vendor.py`)

- **`UserClass`** — RFC 3004 list of opaque length-prefixed byte entries;
  zero-length entries are rejected on both encode and decode. **Opt-in:**
  option 77 is registered as opaque `Bytes`, because iPXE and several PXE ROMs
  send the option unframed and the strict codec rejects those packets. Ask for
  the structured form with `options.get(77, decode=UserClass)` — the same
  arrangement option 43 uses.
- **`TLVOption(code, value)`** — one generic `(code: int, value: Bytes)`
  TLV record.
- **`EncapsulatedOptions`** — TLV container used to build vendor-specific
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

### Domain names (`_codecs/_domain.py`)

Internal, but the single source of truth for every option carrying an RFC 1035
name — options 81, 120, 122, 139/140, 88/146 (via
`UncompressedDomainList`) and the 3397 search list all route here, so a
malformed name is accepted or refused identically whichever option carries
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

### MoS records (`_mos.py`, RFC 5678)

- **`MoSIPv4AddressRecord`** / **`MoSIPv4AddressList`** — Mobility Services
  IPv4-address record and its list container, shared by
  `IPV4_ADDRESS_MOS`.
- **`MoSFQDNRecord`** / **`MoSFQDNList`** — Mobility Services FQDN record
  (non-compressed domain labels) and its list container, shared by
  `IPV4_FQDN_MOS`.

### CCC sub-options (`_codecs/_ccc.py`, RFC 3495 CableLabs Client Configuration)

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
  a flag — the two were previously documented together as "`U8`/`Boolean`-backed
  flags", which was wrong for both; and **`CCCKDCServerAddressList`**
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
