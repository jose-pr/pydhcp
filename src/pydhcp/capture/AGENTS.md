# `pydhcp.capture` — public API header

Header-file-style reference for `pydhcp.capture`: the capture role, its writer, filter and hooks, and capture files
read and replayed. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; the top header is
`pydhcp/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

## Capture (`pydhcp.capture`)

```python
DHCPCapture(listen=None, *, packet_filter=None, sink=None, hook=None, hook_fail_fast=False,
    poll_interval=None, max_packet_size=None, per_interface=None, reuse_address=None,
    receive_buffer_size=None)
```

- **`DHCPCapture`** (`DHCPListener` subclass) — `packet_filter` is
  either a filter-expression string (compiled via `compile_capture_filter`)
  or a `Callable[[CaptureEvent], bool]`; `sink` gets every accepted event;
  `hook` also gets every accepted event but exceptions are only logged
  unless `hook_fail_fast=True`, in which case the failure is re-raised, stored
  on `self.hook_error` and the receive loop is shut down. Check `hook_error`
  after `serve_forever()` returns to tell a hook failure from an ordinary shutdown --
  re-raising alone does not reach the caller, because `handle()` runs inside
  the listener's per-packet exception handler. `self.accepted_count` tracks
  how many events passed the filter.

```python
CaptureEvent(message, context, captured_at, datagram=None)
```

- **`CaptureEvent`** (frozen dataclass) — `message: DHCPMessage`, `context:
  DHCPRequestContext | None`, `captured_at: datetime`, `datagram:
  pktcap.CapturedDatagram | None = None`. A live event has a `context`; an event
  **read from a capture file has `context=None`** and a `datagram` (its addresses,
  time and octets), so `.source`, `.destination` and `.payload` come from it and the
  `interface` filter key fails its clause. Properties: `.source` /
  `.destination` (`SocketAddress`: where the datagram was sent, so the broadcast
  address for a client with no address, and the port it arrived on),
  `.payload` (`bytes | None`: the datagram as the client sent it, which
  `DHCPRequestContext.payload` holds; `None` for a context built by hand),
  `.message_type` (str name or `"UNKNOWN"`),
  `.client_id` (str), `.xid` (8-hex-digit str).

```python
DHCPCaptureWriter(target, format=None, *, per_capture=False, max_files=1000)
```

- **`DHCPCaptureWriter`** — writes what a capture heard, built on pktcap's
  `CaptureWriter`. Called with a `CaptureEvent` it writes one item, so it is
  a `sink=`: `DHCPCapture(sink=DHCPCaptureWriter("caps.json"))`. A record is
  exactly `DHCPMessage.to_text(format)`: one compact line of JSON for `json`,
  and the text of the message for `yaml`, `toml` and `ini`, in UTF-8 with a
  line feed ending every line on every platform. **A capture file (`pcap`,
  `pcapng`) holds the datagram as the client sent it**, the event's `payload`,
  which tcpdump and Wireshark read and `pktcap.read_datagrams` reads back octet
  for octet (a message encoded again is padded to 300 octets and is not that
  packet): an event with no `payload` is a `ValueError`, raised by the call, and
  nothing is written. Each datagram is written under the event's two addresses
  (the destination port is the one it arrived on) and its `captured_at`.
  Properties: `.format`, `.written` (items written), `.refused` (items a full
  budget turned away); `close()`, and a context manager. A stream stays the
  caller's to close.
  - `target` is a path or a **binary** stream (`sys.stdout.buffer`). A path is
    **appended to** for a record format and **replaced** for a capture file (a
    capture cannot be appended to), and its directories are made when the first
    item is written (building the writer touches nothing); a `yaml` file gets
    `---` before every document, the first included, so an appended file stays
    one valid stream; `json` is one record per line.
  - `format` is one of `pktcap.OUTPUT_FORMATS`: `pcap`, `pcapng`, `json`, `yaml`,
    `toml` or `ini`; `None` takes it from the ending of `target`'s name (`.pcap`,
    `.cap`, `.pcapng`, `.json`, `.jsonl`, `.ndjson`, `.yaml`, `.yml`, `.toml`,
    `.ini`, any letter case) and raises `pktcap.UnsupportedFormatError` (a
    `ValueError`) when the ending names none. `toml` and `ini` hold one record
    per file and so need `per_capture`; `yaml` and `toml` need their extras
    (`ImportError` naming `pip install "pydhcp[yaml]"` or `"pydhcp[toml]"`). With `per_capture` a capture format is one file
    for each datagram.
  - `per_capture=True`: `target` is a filename pattern in `str.format` syntax
    (`out/{client_id}/{timestamp}_{msg_type}.{format}`), one file per record,
    directories made as needed. The placeholders are `FILENAME_FIELDS`:
    `{client_id}`, `{msg_type}` and `{xid}` from the event, `{timestamp}` (the
    event's `captured_at` in UTC, `20260714T123015.000000Z`; a naive time is read
    as UTC), `{index}` (an `int` counting from 0, so `{index:06d}` works) and
    `{format}`. Each value from the event is at most 64 characters: one with
    runs of other than `A-Za-z0-9_.-` becomes `_`, leading and trailing `.` and
    `_` are dropped (`unknown` when nothing is left), and a longer one is cut to
    its first 55 characters and ends in `-` and 8 hexadecimal digits of the
    SHA-256 of the whole, so two long identifiers that start alike name two
    files. A file name Windows opens as a device (`NUL`) gets a leading `_`.
    A pattern that is malformed, names a placeholder that is no field or uses
    anything but bare names (`{}`, `{0}`, `{xid.real}`) is a `ValueError`
    **when the writer is built**; format specs (`{client_id:>12}`) are fine. A
    pattern naming none of `UNIQUE_FILENAME_FIELDS` logs one warning, because
    each record then replaces the last.
  - `max_files` (a `ValueError` below 1) bounds the distinct files a
    `per_capture` writer creates: a record that needs one more is **not
    written**, counted in `refused`, and logged once at WARNING by `pktcap`.
    Rewriting a file already written is free, which leaves a pattern the client
    cannot influence unlimited. The pattern is filled with values the client
    chooses, so without the bound one unauthenticated sender decides how many
    files land on the disk (measured: 5,000 forged identifiers, 5,000 files).
  - `write`'s `OSError` (a full disk, a directory that is a file) is let through
    as it is, so a sink that must not raise catches it.

```python
dissect_dhcp(data: bytes) -> pktcap.Dissected
register_dhcp_dissector(registry=None) -> None
```

- **`dissect_dhcp`**, **`DHCPLayer`** and
  **`register_dhcp_dissector`** — DHCP as a layer of
  pktcap's dissection, so a capture file read with `pktcap.read_dissected`
  carries a `DHCPLayer` on each frame that holds a message. `DHCPLayer` is a named
  tuple of plain values: `op` (`BOOTREQUEST`), `xid` (an `int`), `message_type`
  (`DHCPDISCOVER`; `UNKNOWN` without option 53), `client_id` (colon-separated
  upper-case hex: option 61, else the hardware type and address) and `message`
  (`DHCPMessage.to_mapping()`; a mapping, so the layer is not hashable).
  `dissect_dhcp` decodes with `DHCPMessage.decode` and returns the layer with an
  empty payload and nothing after it; octets that are not a message are a
  `pktcap.DissectError` (a `ValueError`) whose text is the fixed `not a DHCP
  message`, quoting none of them. It keeps the contract `pktcap.check_dissector`
  checks. `register_dhcp_dissector` registers it on UDP ports 67 and 68 in
  `registry`, or in `pktcap.default_registry()` (process-wide) when none is given;
  **nothing registers on import**, and a port that already has a dissector is a
  `ValueError` with nothing registered by the call. With it registered,
  `pktcap.compile_capture_filter("proto=dhcp", pktcap.frame_filter)` selects the
  frames that carry a message.

```python
read_capture(source, *, packet_filter=None, ports=(67, 68), dissector=None) ->
    Iterator[CaptureEvent]
capture_dissector(ports=(67, 68)) -> pktcap.FrameDissector
```

- **`read_capture`** — the DHCP messages of a pcap or pcapng capture
  (`source` a path or a binary stream), as events with `context=None`, in file
  order: one for each UDP datagram to or from one of `ports` that the DHCP dissector
  read and that passes `packet_filter` (text or a predicate, as for `DHCPCapture`).
  `captured_at` is the datagram's time, the epoch when the file's time is not one;
  `message` is `DHCPMessage.decode` of the octets, and `payload` those octets.
  Datagrams between IPv6 addresses are not DHCP for IPv4 and are passed over.
  Arguments are checked at the call; the file is read while iterating, and a
  damaged capture raises `pktcap.CaptureFormatError` **after** the events before the
  damage. **`capture_dissector`** is the
  default `dissector`: a copy of pktcap's registry (the process-wide one is left
  alone) with `dissect_dhcp` on `ports`; pass your own and read its `stats` (and
  `unsupported_linktypes`) afterwards to tell an empty capture from frames nothing
  could read: `malformed` frames held a message that did not decode or a cut-short
  layer. A `dissector` you pass must have `dissect_dhcp` registered on `ports`.

```python
replay_capture(source, server, port=67, *, endpoint=None, speed=1.0, max_delay=5.0, limit=None)
    -> pktcap.ReplayResult
```

- **`replay_capture`** — send again, through
  `pktcap.replay_to`, the payload of each datagram the capture shows going to **UDP
  port 67**, to `server` at `port`: **never to an address from the capture**, and a
  datagram to port 68 (a reply) is not sent. `source` is a pcap or pcapng capture
  (path or binary stream) or an iterable of `pktcap.CapturedDatagram`. `endpoint` is
  a `netimps.UDPEndpoint` the caller made, to send from a chosen port or interface
  or to a broadcast address. `speed=1.0` keeps the recorded waits (`None` removes
  them), `max_delay` bounds one wait, `limit` ends the replay after that many
  datagrams. `ReplayResult(sent, partial)`. `OSError` when `server` does not
  resolve or a send fails; `ValueError` for an option out of range.

- **`FILENAME_FIELDS`** — `("client_id", "timestamp", "msg_type", "xid",
  "format", "index")`, the placeholders a `per_capture` pattern may name.
- **`UNIQUE_FILENAME_FIELDS`** — `{"timestamp", "xid", "index"}`, the subset that
  differs between two packets of one capture. A pattern naming none of them
  resolves to the same filename for packets that agree on the rest, so each
  record overwrites the last.
- **`MAX_CAPTURE_FILES`** (`1000`) — the default `max_files`.

```python
command_hook(command, *, packet_format="json", timeout=HOOK_TIMEOUT_SECONDS, fail_fast=False) ->
    CaptureHook
```

- **`command_hook`** — a hook that runs a program once per
  captured packet. `command` is found when the hook is made: a name with a
  directory part (`./hook`, `/opt/hook`) is that file, taken relative to the
  working directory then, and a bare name is looked up on `PATH`; `ValueError`
  when it does not exist, is not a file or (POSIX) is not executable. It is run by
  its absolute path with **no arguments and no shell**. It reads the packet on
  standard input (`packet_format` `json` is one compact line, `yaml`/`toml`/`ini`
  are `DHCPMessage.to_text`) and its environment is a copy of this process's
  plus `PYDHCP_CAPTURE_CLIENT_ID`, `PYDHCP_CAPTURE_MSG_TYPE`, `PYDHCP_CAPTURE_XID`
  and `PYDHCP_CAPTURE_FORMAT`. Its output is decoded as UTF-8 with
  `errors="replace"`. Each run is bounded by `timeout` seconds (`ValueError`
  unless above 0): past it the program **and the processes it started** are
  killed (`taskkill /T` on Windows, the process group elsewhere) and the hook
  raises **`DHCPTimeoutError`**. A non-zero exit is logged at ERROR, at most once
  a minute whatever its frequency, with the status and the last 400 characters of
  standard error; with `fail_fast` it also raises **`DHCPHookError`**. The sizes
  of the two streams are logged at DEBUG, never their contents. Pass it as
  `DHCPCapture(hook=...)`; `hook_fail_fast=True` there stops the capture on the
  first error.

- **`HOOK_TIMEOUT_SECONDS`** (`10.0`) — the default `timeout` of `command_hook`.
  The hook runs on the receive thread, so without a bound a hanging program would
  stop packets being read at all.

```python
compile_capture_filter(text) -> Callable[[CaptureEvent], bool]
```

- **`compile_capture_filter`** —
  `None`/blank → always-true. The grammar is pktcap's: `key=value` or
  `key!=value` clauses joined by `and` (any letter case, space on both sides;
  there is no `or`, and an expression may not end in `and`). `!=` selects what
  the clause does not. Keys: `op`, `msg_type`, `xid`, `client_id`, `chaddr`,
  `src`, `src_port`, `dst`, `dst_port`, `interface`, or
  `option.<NAME_OR_CODE>` (compares the option's decoded/enum-name or string
  value, as one text: a comma in it is part of it). For every other key a
  comma means **any of**: `msg_type=DHCPDISCOVER,DHCPREQUEST`.
  - `op` and `msg_type` take a member's name in any letter case (`bootrequest`,
    `dhcpdiscover`) or a number from 0 to 255, named or not; `msg_type` also
    takes `UNKNOWN` (a message with no option 53) and `TYPE_<n>` (an unnamed
    type). `xid` is an integer in any base up to 32 bits; the ports 0 to 65535;
    `src` and `dst` an IPv4 address; `interface` an adapter name, compared as
    written. `client_id` and `chaddr` are whole octets of hexadecimal digits with
    `:`, `-` or `.` between groups, compared without them, so `00:11:22:33:44:55`,
    `00-11-22-33-44-55`, `0011.2233.4455` and `001122334455` are one filter.
  - A value no packet could match is refused when the filter is compiled, so
    a typo is one start-up error and never a capture that reports nothing:
    an unknown name (the message lists the names), a number out of range, hex
    that is not octets, an `option.` code outside 1 to 254. The error is
    **`pktcap.CaptureFilterError`**, a `ValueError`, and names the clause.

**Gotcha**: without packet info (a socket bound to one address)
`CaptureEvent.destination` falls back to the address replies leave from, which it
takes from `context.interface.ip` and casts to `IPv4` to satisfy `SocketAddress`;
an IPv6-only interface isn't actually handled
(`NetworkInterface.ip` is `ipaddress.IPv4Address | ipaddress.IPv6Address`) — capture on an
IPv6-only interface can break at runtime. The `dst` filter key compares with
`.destination`, so `dst=255.255.255.255` selects the broadcasts and
`dst=<server address>` the unicasts.

```python
AsyncDHCPCapture(listen=None, *, packet_filter=None, sink=None, hook=None, hook_fail_fast=False,
    max_packet_size=None, per_interface=None, reuse_address=None, receive_buffer_size=None,
    max_queued=None)
```

- **`AsyncDHCPCapture`** — the same
  filter/sink/hook rules running on `AsyncDHCPListener`: a sibling of
  `DHCPCapture` over one private core, not a subclass. Identical arguments minus
  `poll_interval`, and both constructors share the core's state setup. Drive
  it with `await .serve_forever()` or `await .start()`, `.shutdown()`,
  `await .wait_closed()` and `await .aclose()`, and check `.hook_error` after
  `.wait_closed()` returns.
  - `accepted_count`, `hook_error` and whatever a `sink` keeps are unguarded on
    both, and the single handler worker is again the whole guarantee — the sink
    runs on it too, so a per-run budget such as the CLI's `--count` needs no
    lock and no library-side state of its own.
  - `hook_fail_fast` shuts the capture down through
    `AsyncDHCPListener.shutdown()`, called from that worker thread; see the `.shutdown()` note under `AsyncDHCPListener` (`pydhcp/listener/AGENTS.md`) for why the sockets are still
    open when `handle()` re-raises: `await .aclose()` releases them.

- **Type aliases** (`pydhcp.capture`, not re-exported from the top level, so
  import them from the module): **`CaptureSink = Callable[[CaptureEvent], None]`**, **`CaptureHook = Callable[[CaptureEvent], None]`**, and
  **`CapturePredicate = Callable[[CaptureEvent], bool]`** — the three callable
  shapes `DHCPCapture`/`AsyncDHCPCapture` accept. A `packet_filter` string is
  compiled to a `CapturePredicate`; passing one directly skips the parser.

- **`PacketFilterLike`** (`Union[str, CapturePredicate]`) — what `packet_filter=` accepts: a
  filter expression, or the predicate itself.
