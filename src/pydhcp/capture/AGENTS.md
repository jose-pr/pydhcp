# `pydhcp.capture` — public API header

Header-file-style reference for `pydhcp.capture`: DHCP as a layer of pktcap's dissection, the
sockets DHCP messages arrive at read as pktcap frames, and the plugin that gives pktcap's
commands the DHCP filter keys. Every public export with its signature, arguments, contract and
gotchas, so the package can be used without reading its source. It ships inside the package and
is self-contained; the top header is `pydhcp/AGENTS.md`. Development documentation lives with
the source at <https://github.com/jose-pr/pydhcp>.

Everything here needs the `pktcap` extra (`pip install "pydhcp[pktcap]"`) except the type
`DHCPLayer`: a call without it is an `ImportError` with the one line
`captures need the 'pktcap' extra: pip install "pydhcp[pktcap]"`, and only a missing `pktcap`
counts (a failure inside it is raised as it is). Importing `pydhcp.capture` imports neither
pktcap nor asyncio and registers nothing. Writing a capture (every format), filtering it, hooks
and replaying it are pktcap's: `pydhcp capture` and `pydhcp replay` are its commands with the
defaults below (`pydhcp/cli/AGENTS.md`), and a program uses `pktcap.copy_frames`,
`pktcap.CaptureWriter`, `pktcap.command_hook` and `pktcap.replay_to`
(`pktcap/_copy/AGENTS.md`, `pktcap/_formats/AGENTS.md`).

## Capture (`pydhcp.capture`)

```python
sniff_dhcp(listen=None, *, per_interface=None, stop=None, dissector=None) ->
    Iterator[pktcap.DissectedFrame]
asniff_dhcp(listen=None, *, per_interface=None, dissector=None) ->
    AsyncIterator[pktcap.DissectedFrame]
```

- **`sniff_dhcp`** — the DHCP messages that reach `listen`, as pktcap's dissected frames, in
  arrival order. `listen` is netimps' listen specification (`netimps.parse_listen`) with default
  ports 67 and 68 and IPv4: `None` is every address, `"127.0.0.1:6767"` one socket, an adapter
  name or a MAC the sockets of that adapter. The sockets are bound **when it is called**,
  broadcast allowed and the receive buffer grown to 1 MiB, and nothing is opened when any part
  is refused (`ValueError` for an adapter that matches nothing, `OSError` for a port that is
  taken). `per_interface=True` binds one socket for each address of the host instead of a
  wildcard, which on Linux hears no broadcast. The iterator closes every socket when it ends,
  fails, is closed or is dropped; `stop()` is called between datagrams and at least once a
  second, and true ends it. `dissector` omitted is `capture_dissector()` reading DHCP on 67, 68
  and the ports the sockets are bound to, so the last layer of a frame that holds a message is
  a `DHCPLayer`; a datagram that is no message is a frame whose `error` says so. The IP header
  of such a frame is made up and no other host's traffic is seen (`pktcap.sniff_udp`).
  **`asniff_dhcp`** is the same on an event loop (`pktcap.asniff_udp`): when it ends, fails or
  is cancelled every task is cancelled and every socket closed, and a loop that stops early
  awaits its `aclose()`.

```python
capture_dissector(ports=(67, 68)) -> pktcap.FrameDissector
dissect_dhcp(data: bytes) -> pktcap.Dissected
register_dhcp_dissector(registry=None) -> None
```

- **`capture_dissector`** — a frame dissector that reads DHCP on `ports`, over a copy of
  pktcap's registry (the process-wide one is left alone) in which `DHCPLayer` and its filter keys
  are declared, so `pktcap.frame_filter_for(dissector.registry)` compiles `proto=dhcp` and
  `msg_type=DHCPOFFER`. Its `stats` (and `unsupported_linktypes`) tell an empty capture from
  frames nothing could read.
- **`dissect_dhcp`**, **`DHCPLayer`** and **`register_dhcp_dissector`** — DHCP as a layer of
  pktcap's dissection, so a capture file read with `pktcap.read_dissected` carries a `DHCPLayer`
  on each frame that holds a message. `DHCPLayer` is a named tuple of plain values: `op`
  (`BOOTREQUEST`), `xid` (an `int`), `message_type` (`DHCPDISCOVER`; `UNKNOWN` without option
  53), `client_id` (colon-separated upper-case hex: option 61, else the hardware type and
  address; `UNKNOWN` with neither) and `message` (`DHCPMessage.to_mapping()`; a mapping, so the
  layer is not hashable). **`DHCPLayer.summary()`** is one line: the message type, `xid=` as
  eight hex digits, `client=` and, when they are not zero, `yiaddr=` and `giaddr=`
  (`DHCPOFFER xid=1A52B52E client=01:02:00:00:99:00:02 yiaddr=10.99.0.100`), the text pktcap's
  `text` format shows for a frame whose innermost layer is DHCP. `dissect_dhcp` decodes with
  `DHCPMessage.decode` and returns the layer with an empty payload and nothing after it; octets
  that are not a message are a `pktcap.DissectError` (a `ValueError`) whose text is the fixed
  `not a DHCP message`, quoting none of them. It keeps the contract `pktcap.check_dissector`
  checks. `register_dhcp_dissector` registers it on UDP ports 67 and 68 in `registry`, or in
  `pktcap.default_registry()` (process-wide) when none is given; **nothing registers on
  import**, and a port that already has a dissector is a `ValueError` with nothing registered by
  the call. `DHCPMessage.decode(frame.datagram().payload)` is the message object of a frame.

```python
pktcap_plugin(registry) -> None
```

- **`pktcap_plugin`** — the hook pktcap loads by name: `PKTCAP_LOAD=pydhcp.capture pktcap
  convert -i heard.pcap -f "msg_type=DHCPDISCOVER"` (or `--load pydhcp.capture`, or a `load`
  key in pktcap's configuration file). `registry` is a `pktcap.DissectorRegistry`. It declares
  `DHCPLayer` in `registry` with the filter keys below, then calls
  `register_dhcp_dissector(registry)`; when that raises, the layer is taken out again and the
  error goes on, so a failed call registers nothing (`ValueError` for a layer name or a port
  that is taken). `pydhcp capture` and `pydhcp replay` load it themselves. Keys, each also as
  `dhcp.KEY`, over `DHCPLayer`: `op`, `msg_type`, `xid`, `client_id`, `chaddr` and
  `option.NAME_OR_CODE` (a code 1 to 254, or a name as `DHCPOptionCode.resolve` reads it:
  `option.bootfile-name`, `option.option-67`). Values: `op` and `msg_type` take a member's name in any letter case or
  a number from 0 to 255, named or not, and `msg_type` also `UNKNOWN` (no option 53) and
  `TYPE_<n>` (an unnamed type); `xid` is an integer in any base up to 32 bits; `client_id` and
  `chaddr` are whole octets in hexadecimal with `:`, `-` or `.` between groups, compared without
  them; `option.NAME` compares the option's decoded value (an enum's name, else its text) as one
  text, so a comma in it is part of it. For every other key a comma means any of
  (`msg_type=DHCPDISCOVER,DHCPREQUEST`). A value no message could match is refused when the
  filter is compiled, a typo is one start-up error. `src`, `dst`, `sport` and `dport` are
  pktcap's own. A bare `option` is refused: it needs a name or a number. A second plugin that
  also registers `op` makes the bare `op` ambiguous: write `dhcp.op`.
