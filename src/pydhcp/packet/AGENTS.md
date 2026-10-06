# `pydhcp.packet` — public API header

Header-file-style reference for `pydhcp.packet`: the DHCP wire message
format plus JSON/YAML/TOML/INI structured text (`DHCPMessage.from_text` /
`.to_text`, and `pydhcp.packet.structured`). `DHCPMessage` and
the enums `DHCPMessageType`, `DHCPOpcode`, `DHCPFlags` and `DHCPPort` are also
re-exported from the top-level `pydhcp` package. The top-level package
header ships beside this one as `pydhcp/AGENTS.md`; for the project overview
see <https://github.com/jose-pr/pydhcp>. That file is the
top-level package header.

## Message (`_message.py`)

`DHCPMessage` is defined in layers, each a private module of `pydhcp.packet`
subclassing the last: `_fields` (the dataclass and its fields), `_decode`,
`_encode`, `_mapping` and `_display`. Import `DHCPMessage` from
`pydhcp.packet`;
`decode`/`from_mapping` are typed to return the class they are called on.

- **`DHCPMessage(op, *, htype=HardwareAddressType.ETHERNET, hlen=None, hops=0,
  xid=0, secs=timedelta(0), flags=DHCPFlags.UNICAST, ciaddr=0.0.0.0,
  yiaddr=0.0.0.0, siaddr=0.0.0.0, giaddr=0.0.0.0, chaddr=b"", sname="", file="",
  options=None)`** (dataclass) — the full DHCPv4 wire message; only `op` is
  required and everything after it is a keyword. `DHCPMessage(DHCPOpcode.BOOTREQUEST)`
  encodes to a legal 300-octet message. **`hlen`** is the length of `chaddr`
  when left out, and must equal it when given: `DHCPValueError` otherwise, at
  construction and again in `.encode()` if either field was changed since.
  `.decode()` stays liberal: it takes the `hlen` the sender wrote, whatever the
  `htype` (a 4-octet address under Ethernet, 16 octets under InfiniBand, `hlen =
  0`) and keeps the address as long as that, so what was received re-encodes
  as it arrived. `options=None` makes a fresh `DHCPOptions`. Fields:
  `op: DHCPOpcode`, `htype: HardwareAddressType`, `hlen: int`, `hops: int`,
  `xid: int`, `secs: datetime.timedelta`, `flags: DHCPFlags`, `ciaddr: IPv4`,
  `yiaddr: IPv4`, `siaddr: IPv4`, `giaddr: IPv4`, `chaddr: bytes` (≤16
  bytes), `sname: str` (≤64 bytes encoded), `file: str` (≤128 bytes
  encoded), `options: DHCPOptions`. `MAGIC_COOKIE` (class var, 4 bytes) and
  `MIN_LEGAL_SIZE` (class var) are also exposed. **`MIN_LEGAL_SIZE`** is
  548 — the smallest DHCP message every implementation must be able to
  handle, per RFC 2131 §2: `576 − 20 (IPv4) − 8 (UDP) = 548`, of which
  `548 − 236 (fixed header) = 312` is the options field clients "MUST be
  prepared to receive". It is a floor on *capability*, not on any packet, so
  nothing enforces it — see `.decode()` below.
  - **`DHCPMessage.decode(data: bytes | bytearray | memoryview) ->
    DHCPMessage`** — parses a wire packet. Raises `DHCPDecodeError` for a
    too-short fixed header/magic cookie, a bad magic cookie, `hlen > 16`, or
    an `op` that is neither request nor reply (`op` 1 and 2 are the only
    values RFC 2131 defines, and nothing else is forwarded). A **missing END
    marker (`0xFF`) is accepted**, in the options field and in an overloaded
    `sname`/`file` alike: what arrived is kept, and a message with no options
    at all (240 octets) decodes to an empty bag. `encode` always ends the options
    field, and each field it overloads, with END. An `htype` with no IANA name
    is **preserved** as an unnamed `HardwareAddressType` member rather than
    raising or being rewritten, so a relay forwards the type it received. The
    `flags` field is preserved the same way: the reserved bits stay set, and
    `encode` writes them back.
    `hlen = 0` is accepted: RFC 4390 requires it for IPoIB. There is **no
    minimum size check** — a message as short as 241 octets (fixed header +
    cookie + END) decodes, and neither `MIN_LEGAL_SIZE` (548) nor
    `BOOTP_MIN_PACKET_SIZE` (300) is applied on receive. Real senders emit
    short datagrams, and `.encode()` pads only what pydhcp sends. Honors
    RFC 3396 `OPTION_OVERLOAD` (decodes overflow options packed into the
    `file`/`sname` fields).
  - **`.encode(max_packetsize: int = DHCP_MIN_LEGAL_PACKET_SIZE) ->
    bytes`** — serializes to wire bytes; `bytes(message)` is the same call
    with the default size. The result is immutable: write `bytearray(...)`
    to patch an octet. `max_packetsize` budgets the
    whole **IP datagram**, not the message: the options field gets
    `max_packetsize − 268`, where `268 = 20 (IPv4) + 8 (UDP) + 236 (fixed
    header) + 4 (magic cookie)`.
    - **`ValueError`** if `max_packetsize` is below **269** (the overhead
      plus the END octet), **including an explicit `0`** — it is not
      rewritten to the default. 576 is *not* a lower bound here: RFC 2132
      §9.10's minimum constrains the client's option 57, which `DHCPServer`
      clamps on receipt, and `encode(280)` is a legitimate call. Option 53
      alone needs 272, and any overload 275 (the options field then holds
      options 53 and 52).
    - **`DHCPValueError`** naming the field if `hops` (0–255), `hlen` (0–**16**,
      matching `.decode()`, since `chaddr` is a 16-octet field) or `xid`
      (0–2³²−1) is out of range — previously a bare `struct.error`, which
      names the format character rather than the field and is neither
      `ValueError` nor `TypeError`. `secs` is **clamped** to 0–65535 rather
      than rejected: it is elapsed time the client reports.
    - **`DHCPValueError`** naming the field if `chaddr` (>16 octets) does not
      fit; a value is never truncated.
    - **`OverflowError`** if the options do not fit even with `sname` and `file`
      carrying options. The message names the option that did not fit and the
      shortfall: `option 119 (DOMAIN_SEARCH) did not fit; the options need 612
      octets and the options, file and sname fields hold 497 besides each END,
      115 octets short`. A message within 6 octets of that limit may be
      refused although a split layout exists. A **`DHCPValueError`** instead
      when a name has no way to travel: `sname` or `file` must move into option
      66 or 67 and that option already holds other octets (the name is never
      dropped).
    - **A name too long for its field** (a decoded option 66 or 67 longer than
      64 or 128 octets, or one set that long) is carried as option 66 or 67,
      and the field it would have filled carries options, so `decode` reads it
      back into `sname` or `file`.
    - **Overload choice:** the layouts are *tried*, cheapest first, and the
      first that holds everything is used — no overload, in one pass; then
      overloading fields that are empty (`sname`, then `file`, then both);
      then moving an occupied `sname`/`file` into option 66/67. An occupied
      field is never relocated when an empty one would do, since a PXE client
      reads the fixed field more reliably than the option. Each layout first
      writes the options in order, splitting the one that crosses the end of a
      field into instances of its code (RFC 3396); when no layout holds them
      that way, each option is kept whole and placed in the field with room
      for it (an exact search over the three fields, linear in the number of
      options), so a message that fits only that way still encodes; the
      layout written first that holds the message is the one used.

    `DHCP_MESSAGE_TYPE` is always the **first** TLV after the magic cookie,
    overloading or not, then `OPTION_OVERLOAD` when the message overloads, then a
    relocated option 66 and 67 — RFC 2131 §3 has receivers read option 53 before
    parsing the rest. `SUBNET_MASK` is written before `ROUTER` when both are set
    (RFC 2132 §3.3), and every other option in the order it was set; within each
    field of an overloaded message that order holds. Option 52 is decided here,
    never carried over from a decoded message. The result is padded with PAD
    octets (after END) to `BOOTP_MIN_PACKET_SIZE` (300), which RFC 1542 §2.1 lets
    a relay agent require — never past `max_packetsize` less the 28 octets of
    IPv4 and UDP header.
  - **`.to_mapping() -> dict[str, Any]`** / **`DHCPMessage.from_mapping(data:
    Mapping[str, Any], *, codemap=None) -> DHCPMessage`** — structured
    round-trip to/from a plain dict. Option keys are the option's label when it
    has one, else its **numeric code** as a string (every unnamed code shares
    the label `"UNKNOWN"`, so it is not used as a key). `to_mapping` names the
    options with the message's own code map; pass the same `codemap` to
    `from_mapping` (default `DHCPOptionCode`) to read them back.
    - The round trip is **byte-exact**: each option is loaded back at dump
      time, and one whose readable form does not reproduce the original
      octets is written as **`{"hex": "..."}`** instead
      (`DHCPMessage.HEX_VALUE_KEY`). That covers text holding a non-UTF-8
      octet, a payload the codec normalises, and a length the codec does not
      preserve. `sname` and `file` follow the same rule: text when it is
      UTF-8, `{"hex": "..."}` for any other octets. The form survives JSON,
      YAML, TOML and INI alike.
    - **A value is read once, as its codec reads it.** `from_mapping` builds
      each option from what its codec accepts (a name for an enum, dotted text
      for an address, a number for an integer). A codec that refuses the value
      raises `TypeError` or `ValueError` naming the option and the kind of value
      (`option 1 (SUBNET_MASK) cannot hold a str: ...`); octets are read only
      from `{"hex": "..."}`, which any option takes, and from hex text for an
      option whose codec is opaque bytes (`VENDOR_SPECIFIC_INFORMATION`, an
      unnamed code). A missing header field is a `ValueError` naming it.
    - Integer options serialize as plain `int`, not as the `U16`/`U32`
      subclass — YAML cannot represent the subclass and TOML writes something
      it cannot read back.
    Backs the JSON/YAML/TOML/INI helpers below.
  - **`.message_type -> DHCPMessageType | None`** (read-only property) — option
    53 as its member; `None` when there is no option 53 or its payload is not
    one octet. A number `DHCPMessageType` has no name for is an unnamed member
    carrying it (`.name` is `None`, `.label()` is `TYPE_<n>`), so a relay forwards
    what it received. `DHCPServer`, `DHCPClient` and `CaptureEvent` read it here.
  - **`.broadcast -> bool`** (read-only property) — whether the broadcast bit of
    `flags` is set. `flags` holds all sixteen bits as they were received.
  - **`.get_client_id(func=None) -> str`** — `CLIENT_IDENTIFIER` option if
    present, else `func(self)` if given and non-empty, else
    `htype.value + chaddr`; returned as uppercase colon-hex. Raises
    **`NoClientIdentityError`** (`pydhcp.exceptions`; a `ValueError`) when the message has
    none of those — `chaddr` is empty and there is no option 61 — rather
    than returning the hardware-type octet alone, which every such client
    would share. `DHCPServer` drops such a message; `CaptureEvent.client_id`
    reports `"UNKNOWN"`.
  - **`.summary(codemap=None) -> str`** — human-readable multi-line summary
    (used by `.log_str()`/`.log()` and the CLI's `--format summary`); nothing
    reads it back.
  - **`.to_text(format: str) -> str`** / **`DHCPMessage.from_text(text: str,
    format: str, *, codemap=None) -> DHCPMessage`** — the message as a document and back;
    `format` is `"json"`, `"yaml"`, `"toml"` or `"ini"` (case-insensitive),
    anything else raises `ValueError`. `to_mapping()` / `from_mapping()` written
    out by `pydhcp.packet.structured` (below). `"toml"` needs Python 3.11+ or
    `pydhcp[toml]`. A file the capture command wrote loads with `from_text`.
  - **`.log(src, dst, level: int) -> None`** — logs `.summary()` framed with a
    header, at `pydhcp`'s `LOGGER`, at the given `logging` level.

**Hand-authoring a message for `from_text`** — two traps, both refused with
an error:

- **Quote the MAC.** `chaddr: 10:20:30:40:50:55` unquoted is read by PyYAML as
  the sexagesimal integer `8041827055`, and raises with a message naming the
  cause; write `chaddr: "10:20:30:40:50:55"`.
- **Omit or quote `sname`/`file`.** A bare `sname:` loads as `None`, which means
  empty; a value that is not text, null, octets or `{"hex": ...}` raises.

**`DHCPMessage.decode()` honours `cls`**, so a subclass decodes to itself — it
used to hard-code `DHCPMessage(...)` while `from_mapping` already used `cls`.
The annotation still says `-> DHCPMessage` on both; tightening them to `Self`
is a separate typing decision.

## Enums (`_enums.py`)

- **`DHCPMessageType`** (`IntEnum` + `DHCPOptionType` codec) —
  `DHCPDISCOVER`..`DHCPTLS` (1–18); registered as the codec for
  `DHCPOptionCode.DHCP_MESSAGE_TYPE`. Any other octet value is an unnamed
  member (`DHCPMessageType(99)`: `.name` is `None`, `.label()` is `"TYPE_99"`,
  one object per number); a number over 255 raises `ValueError`.
- **`DHCPOpcode`** (`IntEnum`) — `BOOTREQUEST = 1`, `BOOTREPLY = 2`.
- **`DHCPPort`** (`IntEnum`) — `SERVER = 67`, `CLIENT = 68`.
- **`DHCPFlags`** (`IntFlag`) — `UNICAST = 0`, `BROADCAST = 1 << 15`; the other
  fifteen bits are reserved and a decoded value keeps them. `.label()` is
  `"UNICAST"` or `"BROADCAST"`, then `|0x....` for reserved bits that are set.
  Test the bit with `DHCPMessage.broadcast`, not by comparing the value.
- **`HardwareAddressType`** (`IntEnum`) — **defined in `pydhcp._network`** and
  re-exported here; `pydhcp.packet.HardwareAddressType` is unchanged and remains
  the spelling to use for the `htype` header field. It lives one layer down
  because the option codecs need it too and this module imports them. See
  `pydhcp/_network/AGENTS.md` for the full entry.

## Structured text (`structured.py`, public as `pydhcp.packet.structured`)

- **`loads(text: str, format: str) -> dict[str, Any]`** /
  **`dumps(data: dict[str, Any], format: str) -> str`** — a mapping in a
  structured text format, with `json`'s meanings: `loads` takes content (never
  a file name), `dumps` returns text. `format` is one of `"json"`, `"yaml"`,
  `"toml"`, `"ini"` (case-insensitive); anything else raises `ValueError`.
  `"toml"` requires Python 3.11+ (`tomllib`) or the optional `tomli`/`tomli-w`
  packages (`pydhcp[toml]`) and raises `NotImplementedError` with an
  actionable message otherwise. `DHCPMessage.from_text` / `.to_text` are these
  two around `from_mapping` / `to_mapping`.

**Gotcha**: the INI loader/dumper sets `ConfigParser.optionxform = str`
before parsing — any code that builds its own `ConfigParser` for packet or
option data must do the same, or option/field names get silently
lowercased and structured packet round-tripping breaks.
