# `pydhcp.options` — public API header

Header-file-style reference for `pydhcp.options`: the options container, the option-code registry and the contract a
payload codec satisfies; the codecs are in `pydhcp/options/_codecs/AGENTS.md`. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; the top header is
`pydhcp/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

## Container (`pydhcp.options`)

```python
DHCPOptions(codemap=None)
DHCPOptions.get(key, default=None, decode=True) -> Any
DHCPOptions.items(decoded=True) -> list[DHCPOption]
DHCPOptions.append(option)
DHCPOptions.replace(option)
DHCPOptions.decode(data: bytes | bytearray | memoryview, *, codemap=None) -> DHCPOptions
DHCPOptions.encode(word_size=1) -> bytearray
DHCPOptions.partial_encode(maxsize, word_size=1) -> tuple[bytearray, DHCPOptions | None]
DHCPOptions.copy() -> DHCPOptions
DHCPOptions.retain(codes) -> None
```

- **`DHCPOptions`** (`MutableMapping[int, bytearray]`) — the
  option bag carried by `DHCPMessage.options`.
  - **`get`** decodes; `[]` does not.** `options[53]` is
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
  - **`.get()`** — `key` is positional
    only (`get(key=53)` is a `TypeError`); `decode=True`
    (default) uses the code's registered `DHCPOptionType`; `decode=False`
    returns the raw `bytearray`; `decode=<type[DHCPOptionType]>` or
    `decode=<Callable[[bytearray], T]>` overrides the codec explicitly.
  - **`.items()`** — `decoded=True` (default)
    or a codemap type returns a **`list`** of `DHCPOption` `(code, value)`
    pairs, freshly decoded; `decoded=False` returns the mapping's own
    `ItemsView[int, bytearray]` of raw payloads. Only the raw form is a live
    view — the decoded form builds new pairs, so it has no `.mapping` and no
    set operations.
  - **`.append()`** / **`.replace()`** — `option` is a
    `DHCPOption` or `(code, value)` tuple; `.append` concatenates onto any
    existing bytes for that code (RFC 3396 long-option splitting on
    decode/reassembly), `.replace` overwrites.
  - **`DHCPOptions.decode()`** (classmethod) — parses a raw TLV options buffer into a
    new bag: PAD is skipped, END stops the parse, octets after END are
    ignored, a repeated code is joined (RFC 3396 long-option splitting).
    Malformed lengths log at DEBUG rather than raising (a listener counts the
    datagram in `metrics.packets_decoded_leniently`). (`DHCPMessage.decode`
    reads the options field and, on **RFC 2132 §9.3** option overload, the
    `file`/`sname` fields into one bag — option 52, a different mechanism.)
  - **`.encode()`** / **`.partial_encode()`** — serialize to
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
  - **`.copy()`** — independent copy: same codemap, every
    payload copied into a fresh `bytearray`. Use this before handing an
    options bag to code that mutates it (a response pipeline, an encoder);
    a plain assignment aliases the container *and* its payload buffers, so
    the mutations write straight back into the source.
  - **`.retain()`** — keep only the options whose code is in `codes`
    (any iterable of integers or option codes), in their present order; the
    rest are deleted. A read-only bag raises `TypeError`, even when nothing would go.

- The `MISSING` sentinel this module uses to tell "no default given" from
  "default is `None`" lives in `pydhcp._generic`, not in `pydhcp._constants` — it
  is a Python idiom rather than a DHCP constant, and it is private.

## Option codes (`pydhcp.options`)

```python
DHCPOptionCode.label() -> str
DHCPOptionCode.register_type(optiontype) -> None
DHCPOptionCode.get_type() -> type[DHCPOptionType]
```

- **`DHCPOptionCode`** (`IntEnum` + `BaseDHCPOptionCode`) — the standard
  IANA option-code registry (`PAD`=0 … `END`=255 and everything in
  between), each member RFC-documented in its docstring. `.label() -> str`
  returns the enum member name (or `BaseDHCPOptionCode.label()`'s
  `"UNKNOWN"` fallback for an unregistered raw int). `.register_type(optiontype)` binds a codec to a specific member;
  `.get_type() -> type[DHCPOptionType]` resolves it. The built-in codecs are
  bound to the standard codes when the options package is imported
  (`options/_registry.py` calls `.register_type(...)` for each), so a lookup
  never depends on an earlier call and *your* registration is always the later
  write. Unregistered codes (`PAD`, `END`, and any code without a registry
  entry) fall back to `Bytes` (opaque). `DHCPMessageType`, the codec of option
  53, is defined in the options package and re-exported by `pydhcp.packet` and
  the root; a number it has no name for is an unnamed member carrying it
  (`.label()` is `TYPE_<n>`), never refused.

```python
BaseDHCPOptionCode.get_type()
BaseDHCPOptionCode.label()
BaseDHCPOptionCode.from_code(code)
BaseDHCPOptionCode.normalize(code, value) -> DHCPOption
BaseDHCPOptionCode.decode(code, value) -> DHCPOption
```

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

## Writing a codec (`pydhcp.options`)

```python
DHCPOptionType.unpack_from(option) -> tuple[DHCPOptionType, int]
DHCPOptionType.pack_into(buffer) -> int
DHCPOptionType.fixed_size() -> int | None
DHCPOptionType.to_json() -> Any
DHCPOptionType.display_text() -> str
DHCPOptionType.unpack(option) -> DHCPOptionType
DHCPOptionType.pack() -> bytes
```

`OptionCodec` is the `typing.Protocol` a codec satisfies; `isinstance(x,
OptionCodec)` is a run-time check that the methods exist (names only, not
signatures). `DHCPOptionType` is the base class that supplies all of it but
the three things a codec writes itself:

- **the constructor `Codec(value)`** — one argument: a value, or what a
  document holds (what `to_json()` returned). Validate here and raise
  `DHCPValueError` for a value the option cannot carry.
- **`unpack_from()`** (classmethod)
  — read one value from the start of `option`; return it and the number of
  octets it took. Raise `DHCPDecodeError` for octets that are not a value. A
  list codec calls it repeatedly on the rest of the payload.
- **`pack_into()`** — append the payload's octets
  to `buffer`; return how many.

and may override these, each with a default:

- **`fixed_size()`** (classmethod) — the exact payload length
  of every value; `unpack` refuses any other length. Default `None`.
- **`to_json()`** — the value as plain data (`str`, `int`, `bool`,
  `list`, `dict`) for a JSON, YAML, TOML or INI document. Default: the value
  itself. `Codec(value.to_json())` must equal `value`: `from_text` and
  `from_mapping` rebuild a value that way.
- **`display_text()`** — what `message.summary()`, the log and the
  capture formats show. Default: `repr(value)`.

What the base adds: **`Codec.unpack()`** (classmethod) reads the
whole payload — `fixed_size` is checked, octets `unpack_from` did not take are
an error, and a `DHCPValueError` the constructor raises becomes a
`DHCPDecodeError` — and **`value.pack()`** returns the payload.

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
