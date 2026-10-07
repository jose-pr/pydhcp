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
`cli._packet`, `cli._capture`, `cli._replay`, with `cli._capture_hook` for `--hook`
loading (a command is `capture.command_hook`) and `cli._common` for the shared
bases: `server`, `relay` and `capture` declare `--listen` and `--per-interface` once,
in a base class that also gives each its `PYDHCP_<COMMAND>_*` variables and ends
the run on Ctrl-C). `pydhcp.cli` exports `App`, `main` and the six command
classes `Interfaces`, `Server`, `Relay`, `Packet`, `Capture` and `Replay`, and nothing else: no limit or format list is reachable only from there
(`pydhcp.capture.MAX_CAPTURE_FILES`, `pktcap.OUTPUT_FORMATS`).

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
  pydhcp.cli` imports `duho`, `yaml`, `tomllib`, `tomli` or `tomli_w`.

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
  `name`, `ip`, `mac`, `network`), `server` (`--config`, `--listen`,
  `--per-interface`, `--lease-file`, `--lenient-reply-ports`), `relay` (`--listen`,
  `--server` repeatable or comma-separated and **required**, `--max-hops`,
  `--insert-relay-agent-info`, `--circuit-id`, `--remote-id`), `packet`
  (`--decode`/`--encode` mutually exclusive+required, `--input`/`--output`
  accepting `-` for stdio, `--format json|yaml|toml|ini|summary`; `summary` is
  decode-only, its first line is the op and XID), `capture` (`--listen`,
  `--filter`, `--format`, `--output` file/pattern/`-`, `--per-capture`, `--read`,
  `--max-files`, `--count`, `--hook` `module:function` or an
  executable (a name with a directory is that file, resolved against the working
  directory when the capture starts and run by its absolute path; a bare name is
  looked up on `PATH`; a non-executable file is refused at start-up), `--hook-fail-fast`, `--per-interface`). Also gets
  `--version` (via `App._version_ = duho.AUTO`, resolved from installed
  package metadata) for free. Every option has one line of help, with its
  default.

- **Settings** come, highest first, from the option, the environment variable,
  the configuration file and the field's default, and duho applies that order
  to every field of every command (see "Environment variables" below for the
  names). `server`, `relay` and `capture` take `--config FILE` (or
  `PYDHCP_CONFIG`) and `--config-format json|yaml|toml|ini`; `FILE` is `-` for
  standard input, which needs the format. **There is no default location**: a
  daemon does not pick up a file nobody named. The file has one section per
  command, named for it, and its keys are the command's field names
  (`listen`, `per_interface`, `lease_file`; `server`, `max_hops`,
  `insert_relay_agent_info`, `circuit_id`, `remote_id`; `packet_filter`,
  `packet_format`, `output`, `per_capture`, `count`, `hook`, `hook_fail_fast`):

  ```yaml
  server:
    listen: 127.0.0.1:6767
    lease_file: /var/lib/pydhcp/leases.json
  ```

  A list is a list (`server: [192.0.2.1, 192.0.2.2]`); `listen` also takes
  the listener's pair, list and null-host forms (`listen: [127.0.0.1, 6767]`).
  A file that does not parse, a top-level key that is not a command, a section
  that is not a mapping, a key the command does not have, and a section of
  *another* command than the one run are each refused by name, status 2, one
  line with the file's path and, where the parser gives one, the position:
  `pydhcp: error: server.yaml:12:5: expected ',' or ']'`.

- Each `--server` value is split by **`listener._split_host_port`**, the same
  parser the `--listen` specs go through, and reaches `DHCPRelay` as a
  `(host, port)` tuple with port 67 supplied when the argument names none.
  One difference from `--listen`: an
  empty host is **rejected** here rather than defaulted to `0.0.0.0` — the
  wildcard is a place to listen, not an upstream to forward to. This is not
  IPv6 support: `relay._normalize_server_address` still calls `IPv4()` on
  whatever it receives, so an IPv6 upstream fails with a clear message.

- **`capture --per-capture` validates its filename pattern before binding**:
  `DHCPCaptureWriter` is built first, so an unknown placeholder is a startup
  `ValueError` (status 2), and a pattern naming none of `{timestamp}`, `{xid}`
  or `{index}` gets a warning that records will overwrite each other. Both are
  invisible otherwise: the pattern is expanded per packet inside the receive
  handler, where the listener logs the exception and carries on, so
  `--output "cap_{mac}.json"` recorded nothing while logging once per packet.
  The overwrite case is a **warning, not an error, deliberately**: rewriting one
  file is also how a pattern the client cannot influence stays outside the file
  budget.
- **`--max-files N`** (default `MAX_CAPTURE_FILES`, 1000) is the writer's
  `max_files`: how many *distinct* files one `--per-capture` run may create. **A
  record that needs a file past the bound ends the capture**: status 1 and a last
  line, `pydhcp: error: capture stopped: N files written, the limit of
  --max-files; M records refused ...`. `--max-files` without `--per-capture`, or
  below 1, is a wrong invocation (status 2). Each value interpolated into a
  filename is at most 64 characters (see `DHCPCaptureWriter`).
- **Where the records go**: `--output -` (the default) is standard output, as
  UTF-8 with a line feed ending each line on every platform (Windows included),
  flushed after each record; `--output FILE` is appended to, and `--output
  PATTERN --per-capture` is one file per record. `--format` is `pcap`, `pcapng`,
  `json`, `yaml`, `toml` or `ini`; without it the ending of `--output` names it
  (`.pcap`, `.cap`, `.pcapng`, `.json`, `.jsonl`, `.ndjson`, `.yaml`, `.yml`,
  `.toml`, `.ini`), and an ending that names none, and standard output, are `json`.
  **`capture --read FILE`** (`-` is standard input; `PYDHCP_CAPTURE_READ`, `read` in
  the configuration file) puts the DHCP messages of a pcap or pcapng capture
  through the same `--filter`, `--format`, `--output`, `--count` and `--hook`, with
  no socket bound, and ends when the file does; `--listen` with it is status 2. A
  capture cut or damaged in the middle prints the records before the damage and
  exits 2 with a line naming the file. When frames could not be read, one stderr line
  says how many (`pydhcp: FILE: of N frames, 2 cut short or damaged; 1 of a link type
  nothing here reads (105)`); the status is unchanged.
  **`pydhcp replay --input FILE --server HOST[:PORT]`** (`-i`, `-s`; `--speed`,
  `--no-delay`, `--max-delay`, `--limit`; `PYDHCP_REPLAY_*`) is `replay_capture`: it
  sends the requests of the capture to the server named (port 67 by default),
  prints `N datagrams sent, M partial passed over` and exits 0; a file that is
  not a capture is status 2 naming it, a server that does not resolve is status 1.
  **`--format pcap` and `--format pcapng` write the datagrams as the clients sent
  them** (a file tcpdump and Wireshark open; to standard output the same octets, for
  `| tcpdump -r -`), the file replaced, not appended to; a `--hook` is then given
  JSON on standard input and `PYDHCP_CAPTURE_FORMAT` is `json`.
- **A record that cannot be written ends the capture**: the first one that
  fails (a directory the pattern names is a file, a full or read-only disk, a
  path that is a directory) stops the capture with status 1 and one line,
  `pydhcp: error: capture stopped: cannot write <path>: <reason>`, as
  `--hook-fail-fast` does for a hook. A single output file is opened for append
  **before anything is bound** (and created when absent), and a target that
  cannot be written, such as a directory or a read-only file, is a wrong
  invocation (status 2).

- Capture's JSON output (`--format json`, to standard output or a growing
  file) is compact JSON by design, one object per line; a `--per-capture` JSON
  file holds the same one line. Use `message.to_text("json")` directly only for
  single structured packet files where pretty JSON is acceptable.

## Configuration files (`pydhcp._config`)

```python
load_config(source, format=None) -> dict[str, Any]
```

- **`load_config`** — one configuration
  file as a mapping of sections. `source` is a path or `-` (standard input,
  which has no name and so needs `format`). The format is `format` (`json`,
  `yaml`, `toml` or `ini`, any case) or else the file name's suffix (`.json`,
  `.yaml`, `.yml`, `.toml`, `.ini`, any case); any other suffix is refused,
  content is never sniffed. The text is UTF-8, with or without a byte-order
  mark. An empty YAML file is `{}`. INI values are read without interpolation
  (a `%` is text) and a duplicate section or key is an error; YAML is
  `safe_load`. `.yaml` needs the `yaml` extra and `.toml` Python 3.11+ or the
  `toml` extra; without it the `DHCPConfigError` says `pip install "pydhcp[yaml]"`
  (or `[toml]`), and the format stays a listed one.
- A file that cannot be read raises the `OSError`. A document that does not parse,
  whose top level is not a mapping, or whose format cannot be told raises
  **`DHCPConfigError`** with `path`, `lineno` and `colno` (1-based, `None` when the
  parser gave none) and `msg`; the message and the exception chain carry no text from
  the document.

## Environment variables

Read when the command starts, by the command line only: `import pydhcp` reads none of
them. A boolean accepts `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off`, in any
case; empty counts as unset; any other text is an error naming the variable (status 2).
Every option has the variable `PYDHCP_<COMMAND>_<OPTION>`, listed below; the variables
that follow no such rule (`PYDHCP_CONFIG`, `PYDHCP_CONFIG_FORMAT`, `PYDHCP_TRACEBACK`,
`PYDHCP_MCP` and the four a command hook is given) are in `pydhcp/AGENTS.md`.

| Variable | Sets |
| --- | --- |
| `PYDHCP_SERVER_LISTEN`, `PYDHCP_SERVER_PER_INTERFACE`, `PYDHCP_SERVER_LEASE_FILE`, `PYDHCP_SERVER_LENIENT_REPLY_PORTS` | `server --listen`, `--per-interface`, `--lease-file`, `--lenient-reply-ports` |
| `PYDHCP_RELAY_LISTEN`, `PYDHCP_RELAY_SERVER` (comma-separated), `PYDHCP_RELAY_MAX_HOPS`, `PYDHCP_RELAY_INSERT_RELAY_AGENT_INFO`, `PYDHCP_RELAY_CIRCUIT_ID`, `PYDHCP_RELAY_REMOTE_ID`, `PYDHCP_RELAY_PER_INTERFACE` | `relay --listen`, `--server`, `--max-hops`, `--insert-relay-agent-info`, `--circuit-id`, `--remote-id`, `--per-interface` |
| `PYDHCP_CAPTURE_LISTEN`, `PYDHCP_CAPTURE_FILTER`, `PYDHCP_CAPTURE_RECORD_FORMAT`, `PYDHCP_CAPTURE_OUTPUT`, `PYDHCP_CAPTURE_PER_CAPTURE`, `PYDHCP_CAPTURE_MAX_FILES`, `PYDHCP_CAPTURE_COUNT`, `PYDHCP_CAPTURE_HOOK`, `PYDHCP_CAPTURE_HOOK_FAIL_FAST`, `PYDHCP_CAPTURE_PER_INTERFACE`, `PYDHCP_CAPTURE_READ` | `capture --listen`, `--filter`, `--format`, `--output`, `--per-capture`, `--max-files`, `--count`, `--hook`, `--hook-fail-fast`, `--per-interface`, `--read` |
| `PYDHCP_REPLAY_INPUT`, `PYDHCP_REPLAY_SERVER`, `PYDHCP_REPLAY_SPEED`, `PYDHCP_REPLAY_NO_DELAY`, `PYDHCP_REPLAY_MAX_DELAY`, `PYDHCP_REPLAY_LIMIT` | `replay --input`, `--server`, `--speed`, `--no-delay`, `--max-delay`, `--limit` |
| `PYDHCP_PACKET_INPUT`, `PYDHCP_PACKET_OUTPUT`, `PYDHCP_PACKET_FORMAT` | `packet --input`, `--output`, `--format` (`--decode` and `--encode` choose a mode and are not settings) |
| `PYDHCP_INTERFACES_FORMAT` | `interfaces --format` |
