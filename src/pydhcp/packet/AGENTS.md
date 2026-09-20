# `pydhcp.packet` — public API header

Header-file-style reference for `pydhcp.packet`: the DHCP wire message
format plus JSON/YAML/TOML/INI structured (de)serialization. All exports are
also re-exported from the top-level `pydhcp` package. See the repo-root
`AGENTS.md` for the project overview and `src/pydhcp/AGENTS.md` for the
top-level package header.

## Message (`message.py`)

- **`DhcpMessage`** (dataclass) — the full DHCPv4 wire message. Fields:
  `op: OpCode`, `htype: HardwareAddressType`, `hlen: int`, `hops: int`,
  `xid: int`, `secs: datetime.timedelta`, `flags: Flags`, `ciaddr: IPv4`,
  `yiaddr: IPv4`, `siaddr: IPv4`, `giaddr: IPv4`, `chaddr: bytes` (≤16
  bytes), `sname: str` (≤64 bytes encoded), `file: str` (≤128 bytes
  encoded), `options: DhcpOptions`. `MAGIC_COOKIE` (class var, 4 bytes) and
  `MIN_LEGAL_SIZE` (class var) are also exposed. **`MIN_LEGAL_SIZE`** is
  548 — the smallest DHCP message every implementation must be able to
  handle, per RFC 2131 §2: `576 − 20 (IPv4) − 8 (UDP) = 548`, of which
  `548 − 236 (fixed header) = 312` is the options field clients "MUST be
  prepared to receive". It is a floor on *capability*, not on any packet, so
  nothing enforces it — see `.decode()` below.
  - **`DhcpMessage.decode(data: bytes | bytearray | memoryview) ->
    DhcpMessage`** — parses a wire packet. Raises `ValueError` for a
    too-short fixed header/magic cookie, a bad magic cookie, `hlen > 16`, or
    a missing `0xFF` (END) options terminator. An `htype` with no IANA name
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
    bytearray`** — serializes to wire bytes. `max_packetsize` budgets the
    whole **IP datagram**, not the message: the options field gets
    `max_packetsize − 268`, where `268 = 20 (IPv4) + 8 (UDP) + 236 (fixed
    header) + 4 (magic cookie)`.
    - **`ValueError`** if `max_packetsize` is below **269** (the overhead
      plus the END octet), **including an explicit `0`** — it is not
      rewritten to the default. 576 is *not* a lower bound here: RFC 2132
      §9.10's minimum constrains the client's option 57, which `DhcpServer`
      clamps on receipt, and `encode(280)` is a legitimate call. Carrying
      any option at all needs 272.
    - **`ValueError`** naming the field if `hops` (0–255), `hlen` (0–**16**,
      matching `.decode()`, since `chaddr` is a 16-octet field) or `xid`
      (0–2³²−1) is out of range — previously a bare `struct.error`, which
      names the format character rather than the field and is neither
      `ValueError` nor `TypeError`. `secs` is **clamped** to 0–65535 rather
      than rejected: it is elapsed time the client reports.
    - **`ValueError`** naming the field if `sname` (>64 octets encoded),
      `file` (>128) or `chaddr` (>16) does not fit — these were **silently
      truncated**, and a truncated `file` is a PXE boot filename that points
      nowhere. Values the encoder legitimately *moves* into options 66/67
      when overloading are unaffected; the check is on what is packed.
    - **`OverflowError`** if options still don't fit after RFC 3396 overload
      packing into `file`/`sname`.

    `DHCP_MESSAGE_TYPE` is always the **first** TLV after the magic cookie,
    overloading or not (and ahead of `OPTION_OVERLOAD`) — RFC 2131 §3 has
    receivers read option 53 before parsing the rest. The result is padded
    with PAD octets (after END) to `BOOTP_MIN_PACKET_SIZE` (300), which RFC
    1542 §2.1 lets a relay agent require — never past a `max_packetsize`
    smaller than that.
  - **`.to_mapping() -> dict[str, Any]`** / **`DhcpMessage.from_mapping(data:
    Mapping[str, Any]) -> DhcpMessage`** — structured round-trip to/from a
    plain dict. Option keys are the option's label when it has one, else its
    **numeric code** as a string (every unnamed code shares the label
    `"UNKNOWN"`, so using it collided them onto one key).
    - The round trip is **byte-exact**: each option is loaded back at dump
      time, and one whose readable form does not reproduce the original
      octets is written as **`{"hex": "..."}`** instead
      (`DhcpMessage.HEX_VALUE_KEY`). That covers text holding a non-UTF-8
      octet, a payload the codec normalises, and a length the codec does not
      preserve. The form survives JSON, YAML, TOML and INI alike.
    - Integer options serialize as plain `int`, not as the `U16`/`U32`
      subclass — YAML cannot represent the subclass and TOML writes something
      it cannot read back.
    Backs the JSON/YAML/TOML/INI helpers below.
  - **`.client_id(func=None) -> str`** — `CLIENT_IDENTIFIER` option if
    present, else `func(self)` if given and non-empty, else
    `htype.value + chaddr`; returned as uppercase colon-hex. Raises
    **`NoClientIdentity`** (a `ValueError` subclass) when the message has
    none of those — `chaddr` is empty and there is no option 61 — rather
    than returning the hardware-type octet alone, which every such client
    would share. `DhcpServer` drops such a message; `CaptureEvent.client_id`
    reports `"UNKNOWN"`.
  - **`.dumps(codemap=None) -> str`** — human-readable multi-line summary
    (used by `.log_str()`/`.log()` and the CLI's `--format summary`).
  - **`.log(src, dst, level: int) -> None`** — logs `.dumps()` framed with a
    header, at `pydhcp`'s `LOGGER`, at the given `logging` level.

## Enums (`enums.py`)

- **`DhcpMessageType`** (`IntEnum` + `DhcpOptionType` codec) —
  `DHCPDISCOVER`..`DHCPTLS` (1–18); registered as the codec for
  `DhcpOptionCode.DHCP_MESSAGE_TYPE`.
- **`OpCode`** (`IntEnum`) — `BOOTREQUEST = 1`, `BOOTREPLY = 2`.
- **`DhcpPort`** (`IntEnum`) — `SERVER = 67`, `CLIENT = 68`.
- **`Flags`** (`Flag`) — `UNICAST = 0`, `BROADCAST = 1 << 15`.
- **`HardwareAddressType`** (`IntEnum`) — the IANA ARP hardware types used by
  DHCP, `NONE` (0) through `HFI` (37), including `INFINIBAND` (32) for
  RFC 4390 IPoIB. Any other octet 0–255 becomes a cached **unnamed**
  pseudo-member, so a value a client sent is never rewritten.
  - `.label() -> str` — the member name, or `HTYPE_<n>` for an unnamed one.
    Use this, not `.name`, which is `None` for unnamed members;
    `to_mapping()` emits it and `HardwareAddressType("HTYPE_<n>")` reads it
    back.
  - `.dumps(address: bytes) -> str` renders colon-hex for `ETHERNET`, else
    `repr(address)`.

## Structured (de)serialization (`structured.py`)

- **`load_message(text: str, format: str) -> DhcpMessage`** /
  **`dump_message(message: DhcpMessage, format: str) -> str`** — round-trip
  a `DhcpMessage` through a structured text format. `format` is one of
  `"json"`, `"yaml"`, `"toml"`, `"ini"` (case-insensitive); anything else
  raises `ValueError`. `"toml"` requires Python 3.11+ (`tomllib`) or the
  optional `tomli`/`tomli-w` packages (`pydhcp[toml]`) — raises
  `NotImplementedError` with an actionable message otherwise.
- **`load_mapping(text: str, format: str) -> dict[str, Any]`** /
  **`dump_mapping(data: dict[str, Any], format: str) -> str`** — the
  lower-level mapping (de)serializers `load_message`/`dump_message` build
  on; useful when you want `DhcpMessage.from_mapping`/`.to_mapping()`
  control over the intermediate dict.

**Gotcha**: the INI loader/dumper sets `ConfigParser.optionxform = str`
before parsing — any code that builds its own `ConfigParser` for packet or
option data must do the same, or option/field names get silently
lowercased and structured packet round-tripping breaks.
