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
    a missing `0xFF` (END) options terminator, or an `op` that is neither
    request nor reply. An `htype` with no IANA name
    is **preserved** as an unnamed `HardwareAddressType` member rather than
    raising or being rewritten, so a relay forwards the type it received.
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
      clamps on receipt, and `encode(280)` is a legitimate call. Carrying
      any option at all needs 272.
    - **`DHCPValueError`** naming the field if `hops` (0–255), `hlen` (0–**16**,
      matching `.decode()`, since `chaddr` is a 16-octet field) or `xid`
      (0–2³²−1) is out of range — previously a bare `struct.error`, which
      names the format character rather than the field and is neither
      `ValueError` nor `TypeError`. `secs` is **clamped** to 0–65535 rather
      than rejected: it is elapsed time the client reports.
    - **`DHCPValueError`** naming the field if `sname` (>64 octets encoded),
      `file` (>128) or `chaddr` (>16) does not fit — these were **silently
      truncated**, and a truncated `file` is a PXE boot filename that points
      nowhere. Values the encoder legitimately *moves* into options 66/67
      when overloading are unaffected; the check is on what is packed.
    - **`OverflowError`** if options still don't fit after RFC 3396 overload
      packing into `file`/`sname`.
    - **Overload choice:** each option is *tried*, cheapest first, and the
      first that packs completely is used — no overload; then overloading
      fields that are empty (`sname`, then `file`, then both); then moving an
      occupied `sname`/`file` into option 66/67. An occupied field is never
      relocated when an empty one would do, since a PXE client reads the fixed
      field more reliably than the option.

    `DHCP_MESSAGE_TYPE` is always the **first** TLV after the magic cookie,
    overloading or not (and ahead of `OPTION_OVERLOAD`) — RFC 2131 §3 has
    receivers read option 53 before parsing the rest. The result is padded
    with PAD octets (after END) to `BOOTP_MIN_PACKET_SIZE` (300), which RFC
    1542 §2.1 lets a relay agent require — never past a `max_packetsize`
    smaller than that.
  - **`.to_mapping() -> dict[str, Any]`** / **`DHCPMessage.from_mapping(data:
    Mapping[str, Any]) -> DHCPMessage`** — structured round-trip to/from a
    plain dict. Option keys are the option's label when it has one, else its
    **numeric code** as a string (every unnamed code shares the label
    `"UNKNOWN"`, so using it collided them onto one key).
    - The round trip is **byte-exact**: each option is loaded back at dump
      time, and one whose readable form does not reproduce the original
      octets is written as **`{"hex": "..."}`** instead
      (`DHCPMessage.HEX_VALUE_KEY`). That covers text holding a non-UTF-8
      octet, a payload the codec normalises, and a length the codec does not
      preserve. The form survives JSON, YAML, TOML and INI alike.
    - Integer options serialize as plain `int`, not as the `U16`/`U32`
      subclass — YAML cannot represent the subclass and TOML writes something
      it cannot read back.
    Backs the JSON/YAML/TOML/INI helpers below.
  - **`.message_type -> DHCPMessageType | None`** (read-only property) — option
    53 as its member; `None` when there is no option 53 or its payload is not a
    message type this package decodes (the wrong length, or a number
    `DHCPMessageType` has no member for). `DHCPServer`, `DHCPClient` and
    `CaptureEvent` read it here.
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
    format: str) -> DHCPMessage`** — the message as a document and back;
    `format` is `"json"`, `"yaml"`, `"toml"` or `"ini"` (case-insensitive),
    anything else raises `ValueError`. `to_mapping()` / `from_mapping()` written
    out by `pydhcp.packet.structured` (below). `"toml"` needs Python 3.11+ or
    `pydhcp[toml]`. A file the capture command wrote loads with `from_text`.
  - **`.log(src, dst, level: int) -> None`** — logs `.summary()` framed with a
    header, at `pydhcp`'s `LOGGER`, at the given `logging` level.

**Hand-authoring a message for `from_text`** — two traps, both of which used
to corrupt silently rather than fail:

- **Quote the MAC.** `chaddr: 10:20:30:40:50:55` unquoted is read by PyYAML as
  the sexagesimal integer `8041827055`. It now raises and names the cause;
  write `chaddr: "10:20:30:40:50:55"`.
- **Omit or quote `sname`/`file`.** A bare `sname:` loads as `None`, and that
  used to be stringified into the BOOTP field as the four characters `None`.
  `None` now means empty, and a non-text value raises instead of being
  stringified.

**`DHCPMessage.decode()` honours `cls`**, so a subclass decodes to itself — it
used to hard-code `DHCPMessage(...)` while `from_mapping` already used `cls`.
The annotation still says `-> DHCPMessage` on both; tightening them to `Self`
is a separate typing decision.

## Enums (`_enums.py`)

- **`DHCPMessageType`** (`IntEnum` + `DHCPOptionType` codec) —
  `DHCPDISCOVER`..`DHCPTLS` (1–18); registered as the codec for
  `DHCPOptionCode.DHCP_MESSAGE_TYPE`.
- **`DHCPOpcode`** (`IntEnum`) — `BOOTREQUEST = 1`, `BOOTREPLY = 2`.
- **`DHCPPort`** (`IntEnum`) — `SERVER = 67`, `CLIENT = 68`.
- **`DHCPFlags`** (`Flag`) — `UNICAST = 0`, `BROADCAST = 1 << 15`.
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
