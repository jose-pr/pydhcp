# `pydhcp.cli` — public API header

Header-file-style reference for `pydhcp.cli`: the `pydhcp` command, its settings, exit statuses and environment
variables. Every public export with its signature,
arguments, contract and gotchas, so the package can be used without reading its
source. It ships inside the package and is self-contained; the top header is
`pydhcp/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pydhcp>.

## Command line (`pydhcp.cli`)

A package: `App` and `main()` are in `pydhcp.cli` itself, and each subcommand
has its own private module (`cli._interfaces`, `cli._server`, `cli._relay`,
`cli._packet`, `cli._capture`, `cli._replay`, with `cli._packets` for what `capture` and
`replay` share and `cli._common` for the shared bases: `server`, `relay` and `capture`
declare `--listen` and `--per-interface` once, in a base class that also gives each its
`PYDHCP_<COMMAND>_*` variables and ends the run on Ctrl-C). `capture` and `replay` are
subclasses of the commands of `pktcap.cli`: their options, statuses and output are
pktcap's, with the DHCP defaults below. `pydhcp.cli` exports `App`, `main` and the six
command classes `Interfaces`, `Server`, `Relay`, `Packet`, `Capture` and `Replay`, and
nothing else.

Invoked as **`pydhcp`** (the console script) or **`python -m pydhcp`** — both
reach `cli.main()` and exit with its status, and both report themselves as `pydhcp` in usage and error
lines. The program name comes from `App._parsername_`, not the class name,
which duho would otherwise use.

Every subcommand takes `-v`, `-q` and `--loglevel [NAME:]LEVEL`, which set the level of
the `pydhcp` logger every module logger is a child of (`logging.getLogger("pydhcp")`).

- **The `cli` extra.** The command line is built on `duho`, which the `cli` extra
  installs: `pip install "pydhcp[cli]"`. `import pydhcp.cli` and `main` need nothing;
  `App` and the six command classes load on first use, and without `duho` that use
  is an `ImportError` naming the extra. Neither `import pydhcp` nor `import
  pydhcp.cli` imports `duho`, `pktcap`, `yaml`, `tomllib`, `tomli` or `tomli_w`.
- **The `pktcap` extra.** `capture` and `replay` need `pktcap`
  (`pip install "pydhcp[pktcap]"`). Without it `pydhcp capture` and `pydhcp replay` print
  `pydhcp: error: captures need the 'pktcap' extra: pip install "pydhcp[pktcap]"` and
  end with status 1, before any option is parsed; the other commands run, and `Capture` and
  `Replay` are an `ImportError` naming the extra.

```python
main(argv: Sequence[str] | None = None) -> int
```

- **`main`** — the `pydhcp`
  console-script entry point (`[project.scripts]` in `pyproject.toml`); without
  `duho` it prints `pydhcp: error: the command line needs the 'cli' extra: pip
  install "pydhcp[cli]"` and returns 1 (`python -m pydhcp` the same);
  `argv` is the arguments after the program name (default `sys.argv[1:]`).
  It never exits by itself and returns the **exit status**: **0** success
  (including `--help`, `--version` and a run ended with Ctrl-C), **1** a run
  that failed (an address in use, a file that cannot be written, a hook that
  failed under `--hook-fail-fast`, a packet that does not decode), **2** a wrong
  invocation (a bad option, a malformed `--listen`, `relay` without `--server`,
  a configuration file that cannot be used). An error is one line on stderr,
  `pydhcp: error: ...`; results go to stdout and logging to stderr. A closed
  stdout ends the command quietly, with status 1. Nothing is logged as
  "starting" before the arguments are accepted.
  **Tools:** with `PYDHCP_MCP=stdio` the program serves its commands as MCP tools over
  standard input and output instead of running one: exactly `pydhcp.packet` and
  `pydhcp.interfaces` (each field of the command is a property of the tool, named as the
  field: `decode`, `encode`, `input`, `output`, `packet_format`; `output_format`). A tool
  call has no standard input: `packet` without `input` fails naming `--input`. `server`,
  `relay`, `capture` and `replay` are not tools: they do not return until stopped, start a
  program per packet or send datagrams.
  Subcommands:
  `interfaces` (`--format text|json`: text is one tab-separated line per
  address, name, address, MAC or `-`, network; json is one array of objects
  `name`, `ip`, `mac`, `network`), `server` (`--listen`,
  `--per-interface`, `--lease-file`, `--lenient-reply-ports`), `relay` (`--listen`,
  `--server` repeatable or comma-separated and **required**, `--max-hops`,
  `--insert-relay-agent-info`, `--circuit-id`, `--remote-id`), `packet`
  (`--decode`/`--encode` mutually exclusive+required, `--input`/`--output`
  accepting `-` for stdio, `--format json|yaml|toml|ini|summary`, all but `json` and `summary` through pktcap (its extra); `summary` is
  decode-only, its first line is the op and XID), `capture` and `replay` (below). Also gets
  `--version` (via `App._version_ = duho.AUTO`, resolved from installed
  package metadata) for free. Every option has one line of help, with its
  default.

- **Settings** come, highest first, from the option, the environment variable,
  the configuration file and the field's default, and duho applies that order
  to every field of every command (see "Environment variables" below for the
  names). The root takes `--config FILE`/`-c FILE` (or `PYDHCP_CONFIG`) **before the
  command name**: `pydhcp --config pydhcp.toml server`. After it the option is refused with
  the line to use, as are `--config-format`, `PYDHCP_CONFIG_FORMAT` and `--config -`: the
  ending of the file's name says its format (`.json`, `.toml`, `.yaml`, `.yml`, `.ini`,
  `.cfg`) and standard input is no file. duho's `ConfigArgs` takes the option and
  `duho.config` reads the file; `duho/AGENTS.md` inside the installed package ("Config
  backends") says what each format holds, among them that an INI file's `[DEFAULT]` keys are
  the top level, which here is no command's section and so refused. TOML before Python 3.11
  needs `pip install "duho[config]"` and YAML `"duho[yaml]"`; the error names it.
  `server`, `relay`, `capture` and `replay` read the file; `packet` and `interfaces` have no
  section. **There is no default location**: a
  daemon does not pick up a file nobody named. The file has one section per
  command, named for it, and its keys are the command's field names
  (`listen`, `per_interface`, `lease_file`; `server`, `max_hops`,
  `insert_relay_agent_info`, `circuit_id`, `remote_id`; and for `capture` the fields of its
  options: `filter`, `format`, `output`, `per_record`, `max_files`, `datagrams`, `append`,
  `interface`, `read`, `count`, `duration`, `hook`, `hook_fail_fast`, `hook_timeout`, and
  `load`, the list of pktcap plugins to import beside `pydhcp.capture`: the file is one the
  user named, so it may name code to load, as it may name a hook; `replay` takes its
  options the same way):

  ```toml
  # pydhcp.toml
  [server]
  listen = "127.0.0.1:6767"
  lease_file = "/var/lib/pydhcp/leases.json"

  [capture]
  filter = "msg_type=DHCPDISCOVER"
  load = ["my_plugin"]
  ```

  The same file in YAML (`duho[yaml]`):

  ```yaml
  # pydhcp.yaml
  server:
    listen: "127.0.0.1:6767"
    lease_file: /var/lib/pydhcp/leases.json
  capture:
    filter: msg_type=DHCPDISCOVER
    load: [my_plugin]
  ```

  A list is a list (`server = ["192.0.2.1", "192.0.2.2"]`); `listen` also takes
  the listener's pair, list and null-host forms (`listen = ["127.0.0.1", 6767]`).
  A file that does not parse, a top-level key that is not a command, a section
  that is not a mapping, a key the command does not have, and a section of
  *another* command than the one run are each refused by name, status 2, one
  line with the file's path and, where the parser gives one, the position, in
  duho's words: `pydhcp: error: server.toml:12:5: Expected ']' at the end of a table
  declaration (at line 12, column 5)`. A `--config` file that does not exist is a usage
  error (status 2); one that `PYDHCP_CONFIG` names is status 1.

- Each `--server` value is split by **`netimps.split_host`**, the parser the
  `--listen` specs go through, and reaches `DHCPRelay` as a
  `(host, port)` tuple with port 67 supplied when the argument names none.
  One difference from `--listen`: an
  empty host is **rejected** here rather than defaulted to `0.0.0.0` — the
  wildcard is a place to listen, not an upstream to forward to. This is not
  IPv6 support: `relay._normalize_server_address` still calls `IPv4()` on
  whatever it receives, so an IPv6 upstream fails with a clear message.

- **`pydhcp capture`** is `pktcap capture` with DHCP's defaults: `--listen`/`-l` (pydhcp's
  grammar, ports 67 and 68, IPv4, broadcast allowed), `--per-interface`, `--interface NAME`
  (frame capture, Linux, needs `CAP_NET_RAW`) and `--read FILE` (`-` is standard input) are
  three sources that exclude each other (status 2); with none of them it listens on `*`.
  `--filter`/`-f EXPR` keeps messages by `src`, `dst`, `host`, `sport`, `dport`, `port`,
  `proto`, `linktype`, `LAYER.FIELD` and the DHCP keys `op`, `msg_type`, `xid`, `client_id`,
  `chaddr` and `option.NAME`; it is ANDed with `proto=dhcp`. `--output`/`-o`, `--format`
  (`pcap`, `pcapng`, `json`, `yaml`, `toml`, `ini`, `text`; from the ending of `--output`,
  else `json` for `-`), `--per-record` (one file per record, `--output` the pattern with
  `{client_id}`, `{msg_type}`, `{xid}`, `{timestamp}`, `{index}` and `{format}`),
  `--max-files`, `--datagrams`, `--append`, `--count`, `--duration`/`-d`, `--hook`,
  `--hook-fail-fast`, `--hook-timeout` and `--load` (`PKTCAP_LOAD`; more plugins beside
  `pydhcp.capture`) are pktcap's, and `pktcap/cli/AGENTS.md` has each one's contract. What it prints is
  pktcap's record of the frame (`time`, `linktype`, `length`, `layers`: `ipv4`, `udp` and
  `dhcp`, whose `message` is the mapping `pydhcp packet --decode` prints), and the one
  summary line on stderr; `--format text` prints `DHCPLayer.summary()`. The message alone is
  `jq -c '.layers[-1].message'`. A hook runs for each record written, with the record on
  standard input and `PKTCAP_HOOK_CLIENT_ID`, `PKTCAP_HOOK_MSG_TYPE`, `PKTCAP_HOOK_XID` and
  `PKTCAP_HOOK_FORMAT` in its environment; it comes from `--hook`, `PYDHCP_CAPTURE_HOOK` and
  the settings file the user named, and from nowhere else. Status 0 is a finished capture
  (Ctrl-C included), 1 a run that failed (a port taken, a file that cannot be written, a
  hook that failed under `--hook-fail-fast`, a file budget spent), 2 a wrong invocation
  (a bad filter or format, `--format toml` or `ini` without `--per-record`, a capture file
  that is not one or is damaged). `Bound: ADDRESS` is logged (INFO) for each socket bound.
- **`pydhcp replay --input FILE --to HOST[:PORT]`** is `pktcap replay`: it sends the payload
  of the requests (`dport=67`, narrowed by `--filter`) to the destination named, port 67 by
  default, in capture order and time (`--speed`, `--no-delay`, `--max-delay`, `--limit`),
  from `--source-port` and with `--broadcast` allowed, and prints `sent N, partial M` (or
  `{"sent": N, "partial": M}` with `--json`). The addresses in the capture are never sent
  to. A file that is not a capture is status 2 naming it, a destination that does not
  resolve is status 1.

## Configuration files (`pydhcp._config`)

```python
load_config(source, format=None) -> dict[str, Any]
```

- **`load_config`** — one configuration
  file as a mapping, read by `duho.config` (the `cli` extra; without it the `ImportError`
  names `pip install "pydhcp[cli]"`). `source` is a path (`-` is a file name). The format is
  `format` (`json`, `toml`, `yaml` or `ini`, any case) or else the file name's ending
  (`.json`, `.toml`, `.yaml`, `.yml`, `.ini`, `.cfg`, any case); any other name is refused,
  content is never sniffed. Each format's rules are duho's. A reader that is not installed
  (TOML before Python 3.11, YAML) is a `DHCPConfigError` whose text names duho's extra.
- A file that cannot be read raises the `OSError`. A document that does not parse,
  whose top level is not a mapping, whose format cannot be told or whose reader is missing raises
  **`DHCPConfigError`** with `path`, `lineno` and `colno` (1-based, `None` when the
  parser gave none) and `msg`; the message and the exception chain carry no text from
  the document.

## Environment variables

Read when the command starts, by the command line only: `import pydhcp` reads none of
them. A boolean accepts `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off`, in any
case; empty counts as unset; any other text is an error naming the variable (status 2).
Every option has the variable `PYDHCP_<COMMAND>_<OPTION>`, listed below; the variables
that follow no such rule (`PYDHCP_CONFIG`, `PYDHCP_TRACEBACK`,
`PYDHCP_MCP` and the four a command hook is given) are in `pydhcp/AGENTS.md`.

| Variable | Sets |
| --- | --- |
| `PYDHCP_SERVER_LISTEN`, `PYDHCP_SERVER_PER_INTERFACE`, `PYDHCP_SERVER_LEASE_FILE`, `PYDHCP_SERVER_LENIENT_REPLY_PORTS` | `server --listen`, `--per-interface`, `--lease-file`, `--lenient-reply-ports` |
| `PYDHCP_RELAY_LISTEN`, `PYDHCP_RELAY_SERVER` (comma-separated), `PYDHCP_RELAY_MAX_HOPS`, `PYDHCP_RELAY_INSERT_RELAY_AGENT_INFO`, `PYDHCP_RELAY_CIRCUIT_ID`, `PYDHCP_RELAY_REMOTE_ID`, `PYDHCP_RELAY_PER_INTERFACE` | `relay --listen`, `--server`, `--max-hops`, `--insert-relay-agent-info`, `--circuit-id`, `--remote-id`, `--per-interface` |
| `PYDHCP_CAPTURE_LISTEN`, `PYDHCP_CAPTURE_PER_INTERFACE`, `PYDHCP_CAPTURE_FILTER`, `PYDHCP_CAPTURE_FORMAT`, `PYDHCP_CAPTURE_OUTPUT`, `PYDHCP_CAPTURE_PER_RECORD`, `PYDHCP_CAPTURE_MAX_FILES`, `PYDHCP_CAPTURE_DATAGRAMS`, `PYDHCP_CAPTURE_APPEND`, `PYDHCP_CAPTURE_INTERFACE`, `PYDHCP_CAPTURE_READ`, `PYDHCP_CAPTURE_COUNT`, `PYDHCP_CAPTURE_DURATION`, `PYDHCP_CAPTURE_HOOK`, `PYDHCP_CAPTURE_HOOK_FAIL_FAST`, `PYDHCP_CAPTURE_HOOK_TIMEOUT` | `capture --listen`, `--per-interface`, `--filter`, `--format`, `--output`, `--per-record`, `--max-files`, `--datagrams`, `--append`, `--interface`, `--read`, `--count`, `--duration`, `--hook`, `--hook-fail-fast`, `--hook-timeout` |
| `PYDHCP_REPLAY_INPUT`, `PYDHCP_REPLAY_TO`, `PYDHCP_REPLAY_FILTER`, `PYDHCP_REPLAY_SPEED`, `PYDHCP_REPLAY_NO_DELAY`, `PYDHCP_REPLAY_MAX_DELAY`, `PYDHCP_REPLAY_LIMIT`, `PYDHCP_REPLAY_SOURCE_PORT`, `PYDHCP_REPLAY_BROADCAST`, `PYDHCP_REPLAY_JSON_OUT` | `replay --input`, `--to`, `--filter`, `--speed`, `--no-delay`, `--max-delay`, `--limit`, `--source-port`, `--broadcast`, `--json` |
| `PYDHCP_PACKET_INPUT`, `PYDHCP_PACKET_OUTPUT`, `PYDHCP_PACKET_FORMAT` | `packet --input`, `--output`, `--format` (`--decode` and `--encode` choose a mode and are not settings) |
| `PYDHCP_INTERFACES_FORMAT` | `interfaces --format` |
