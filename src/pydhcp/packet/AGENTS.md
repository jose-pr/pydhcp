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
  `MIN_LEGAL_SIZE` (class var) are also exposed.
  - **`DhcpMessage.decode(data: bytes | bytearray | memoryview) ->
    DhcpMessage`** — parses a wire packet. Raises `ValueError` for a
    too-short fixed header/magic cookie, a bad magic cookie, `hlen > 16`, or
    a missing `0xFF` (END) options terminator. Unknown `htype` values fall
    back to `ETHERNET` with a logged warning rather than raising. Honors
    RFC 3396 `OPTION_OVERLOAD` (decodes overflow options packed into the
    `file`/`sname` fields).
  - **`.encode(max_packetsize: int = DHCP_MIN_LEGAL_PACKET_SIZE) ->
    bytearray`** — serializes to wire bytes. Raises `ValueError` if
    `max_packetsize` is too small for even a bare packet, and
    `OverflowError` if options still don't fit after using RFC 3396 overload
    packing into `file`/`sname`. `DHCP_MESSAGE_TYPE` is always moved to the
    front of the options field.
  - **`.to_mapping() -> dict[str, Any]`** / **`DhcpMessage.from_mapping(data:
    Mapping[str, Any]) -> DhcpMessage`** — structured round-trip to/from a
    plain dict (option keys are the option's label when known, else its
    numeric code as a string; unrecognized option values fall back to raw
    hex bytes). Backs the JSON/YAML/TOML/INI helpers below.
  - **`.client_id(func=None) -> str`** — `CLIENT_IDENTIFIER` option if
    present, else `func(self)` if given and non-empty, else
    `htype.value + chaddr`; returned as uppercase colon-hex.
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
- **`HardwareAddressType`** (`IntEnum`) — `NONE`..`LOCALNET` (0–12);
  `.dumps(address: bytes) -> str` renders colon-hex for `ETHERNET`, else
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
