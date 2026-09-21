from __future__ import annotations

import contextlib
import importlib
import json as _json
import logging as _logging
import pathlib
import os
import subprocess
import sys
import typing as _ty

import duho
from duho import AUTO, Cli, Cmd, DefaultsFormatter, LoggingArgs, Meta

from .capture import (
    UNIQUE_FILENAME_FIELDS,
    CaptureEvent,
    DhcpCapture,
    validate_filename_pattern,
)
from .listener import _split_host_port
from .network import host_ip_interfaces
from .server import DhcpServer
from .lease import FileLeaseBackend, LeaseBackend
from .relay import DEFAULT_MAX_HOPS, DhcpRelay
from .config import load_config
from .packet.enums import DhcpPort
from .packet.message import DhcpMessage
from .packet.structured import dump_message, load_message

#: This module's logger, a child of the package logger `pydhcp` -- which is
#: what `-v`/`--loglevel pydhcp:DEBUG` configure, and what the imports above
#: have already set up with its `NullHandler`.
LOGGER = _logging.getLogger(__name__)

PACKET_FORMATS = ("json", "yaml", "toml", "ini", "summary")
CAPTURE_FORMATS = ("json", "yaml", "toml", "ini")


class _Command(LoggingArgs, Cmd):
    """Base for every subcommand, carrying the logger name.

    `_logger_name_` has to be on the *parsed* subcommand instance: duho resolves
    the logger as `getattr(self, "_logger_name_", self._parsername_)` on that
    instance, and it is the subcommand that gets parsed, not `App`. Setting it
    only on `App` meant `-v` configured a logger named after the subcommand --
    "server", "relay", "capture" -- while the library logs to "pydhcp", which
    stayed at the root level. So `pydhcp server -v` printed one line from the
    command itself and nothing at all from the server.
    """

    _logger_name_ = "pydhcp"


class Interfaces(_Command):
    """List network interfaces"""

    _parsername_ = "interfaces"

    def __call__(self) -> None:
        print("Available Network Interfaces:")
        for interface in host_ip_interfaces():
            print(f"Name: {interface.name}")
            print(f"  IP:   {interface.ip}")
            print(f"  MAC:  {interface.mac}")
            print(f"  Net:  {interface.network}")


class Server(_Command):
    """Start DHCP server"""

    _parsername_ = "server"

    config: _ty.Optional[str] = None
    "Path to config file (JSON, YAML, TOML, or INI)"
    ("--config",)

    listen: _ty.Optional[str] = None
    "Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'"
    ("--listen", "-l")

    per_interface: bool = False
    "Bind each interface separately instead of using wildcard packet-info routing"
    ("--per-interface",)

    lease_file: _ty.Optional[str] = None
    "Persist leases to this JSON file instead of keeping them in memory"
    ("--lease-file",)

    def __call__(self) -> None:
        config: _ty.Dict[str, _ty.Any] = {}
        if self.config:
            config = load_config(self.config)

        server_config = config.get("server", {})
        # An explicit flag beats the config file. The other order meant
        # `--config shared.yaml --listen 127.0.0.1:6767` bound whatever the file
        # said, which is the opposite of what every other CLI does and gives no
        # way to override a shared config for one run.
        listen = self.listen or server_config.get("listen") or "*"
        lease_file = self.lease_file or server_config.get("lease_file")
        unknown = sorted(set(server_config) - {"listen", "lease_file"})
        if unknown:
            self._logger_.warning(
                "Ignoring unsupported key(s) under [server] in %s: %s",
                self.config,
                ", ".join(unknown),
            )

        # A persistent backend is the difference between a restart keeping every
        # client on its address and every client renumbering. deployment.md has
        # always told operators to mount lease storage; until now the CLI had no
        # way to write to it, so the volume stayed empty.
        backend: _ty.Optional[LeaseBackend] = None
        if lease_file:
            backend = FileLeaseBackend(lease_file)
            self._logger_.info("Persisting leases to %s", lease_file)

        self._logger_.info("Starting DHCP server, listening on: %s...", listen)
        server = DhcpServer(
            listen=listen,
            per_interface=self.per_interface,
            lease_backend=backend,
        )
        try:
            server.bind()
            server.listen()
        except KeyboardInterrupt:
            self._logger_.info("Stopping server...")
            server.stop()
        finally:
            # Flush a coalescing backend, and let the in-memory one no-op.
            close = getattr(server.lease_backend, "close", None)
            if close is not None:
                close()


def _parse_server_address(value: str) -> "tuple[str, int]":
    """Split one `--server` argument into `(host, port)`, port 67 by default.

    Shares the listener's parser rather than repeating it. The hand-rolled one
    here split on a lone ':', which made `--server "[::1]:6767"` -- three colons
    -- fall through as a single opaque host string; the listener reads the same
    text as `("::1", 6767)`. Two parsers, two answers for the same syntax.

    An empty host is rejected here even though `_split_host_port` defaults it to
    `0.0.0.0`: the wildcard means "every local address" and is a reasonable
    thing to *listen* on, but as the address of an upstream server to forward
    *to* it is meaningless, so `--server :6767` is a typo worth reporting.
    """
    text = value.strip()
    if not text or (text.startswith(":") and not text.startswith("::")):
        raise ValueError(
            f"--server needs an upstream host address, got {value!r}; "
            "a bare port has no server to forward to"
        )
    host, port = _split_host_port(text)
    return host, int(DhcpPort.SERVER) if port is None else port


class Relay(_Command):
    """Start DHCP relay agent"""

    _parsername_ = "relay"

    listen: _ty.Optional[str] = None
    "Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'"
    ("--listen", "-l")

    # A tuple, not a list: a mutable class-level default is shared by every
    # instance -- `a.server is b.server is Relay.server` -- so one command
    # appending to it would change the default every parser built afterwards
    # sees. duho copies at parser-build time, which hid it on the shipped path.
    server: _ty.Tuple[str, ...] = ()
    "Upstream DHCP server address, optionally host:port (repeatable)"
    ("--server", "-s")

    max_hops: int = DEFAULT_MAX_HOPS
    "Drop requests whose hop count exceeds this (RFC 1542 default 4, max 16)"
    ("--max-hops",)

    insert_relay_agent_info: bool = False
    "Add RELAY_AGENT_INFORMATION (option 82) to forwarded requests"
    ("--insert-relay-agent-info",)

    circuit_id: _ty.Optional[str] = None
    "Hex-encoded circuit ID sub-option (requires --insert-relay-agent-info)"
    ("--circuit-id",)

    remote_id: _ty.Optional[str] = None
    "Hex-encoded remote ID sub-option (requires --insert-relay-agent-info)"
    ("--remote-id",)

    per_interface: bool = False
    "Bind each interface separately instead of using wildcard packet-info routing"
    ("--per-interface",)

    def __call__(self) -> None:
        # The help text has always said these "require --insert-relay-agent-info",
        # and nothing enforced it: `_insert_relay_agent_info` returns early when
        # the flag is off, so `-s 10.0.0.1 --circuit-id 0a01` forwarded packets
        # with no option 82 and said nothing. Checked here rather than in
        # DhcpRelay because the library documents these as independent kwargs
        # and tests construct it that way -- raising there is an API break.
        ignored = [
            flag
            for flag, value in (
                ("--circuit-id", self.circuit_id),
                ("--remote-id", self.remote_id),
            )
            if value
        ]
        if ignored and not self.insert_relay_agent_info:
            raise ValueError(
                f"{' and '.join(ignored)} require --insert-relay-agent-info; "
                "without it no relay agent information option is added at all"
            )

        server_addresses = [_parse_server_address(addr) for addr in self.server]
        circuit_id = bytes.fromhex(self.circuit_id) if self.circuit_id else None
        remote_id = bytes.fromhex(self.remote_id) if self.remote_id else None

        if self.insert_relay_agent_info and not ignored:
            # An empty sub-option list inserts nothing, so the flag alone is a
            # no-op. A warning rather than an error: the flag is the library's
            # documented switch and a future sub-option could make it meaningful.
            self._logger_.warning(
                "--insert-relay-agent-info was given without --circuit-id or "
                "--remote-id, so no relay agent information option will be added"
            )

        # Construct first, announce second. The constructor is what validates
        # the upstream addresses and `max_hops`, so announcing first meant a bad
        # argument was reported *after* "Starting DHCP relay..." and read as a
        # runtime failure rather than as the argument error it is.
        relay = DhcpRelay(
            listen=self.listen or "*",
            server_addresses=server_addresses,
            max_hops=self.max_hops,
            insert_relay_agent_info=self.insert_relay_agent_info,
            circuit_id=circuit_id,
            remote_id=remote_id,
            per_interface=self.per_interface,
        )
        self._logger_.info(
            "Starting DHCP relay, listening on: %s, forwarding to: %s...",
            self.listen or "*",
            ", ".join(self.server),
        )
        try:
            relay.bind()
            relay.listen()
        except KeyboardInterrupt:
            self._logger_.info("Stopping relay...")
            relay.stop()


class Packet(_Command):
    """Encode or decode DHCP packets"""

    _parsername_ = "packet"

    decode: _ty.Annotated[
        bool,
        Meta(
            action="store_const",
            const=True,
            conflicts="mode",
            conflicts_required=True,
            kwargs={"dest": "mode"},
        ),
    ] = False
    ("--decode",)

    encode: _ty.Annotated[
        bool,
        Meta(
            action="store_const",
            const=False,
            conflicts="mode",
            conflicts_required=True,
            kwargs={"dest": "mode"},
        ),
    ] = False
    ("--encode",)

    input: str = "-"
    "Input file path, or '-' for stdin"
    ("--input", "-i")

    output: str = "-"
    "Output file path, or '-' for stdout"
    ("--output", "-o")

    packet_format: _ty.Annotated[str, Meta(choices=PACKET_FORMATS)] = "json"
    "Packet text format; 'summary' is decode-only"
    ("--format", "-f")

    def __call__(self) -> None:
        try:
            if self.input == "-":
                payload_text = sys.stdin.read()
            else:
                payload_text = pathlib.Path(self.input).read_text(encoding="utf-8")

            if self.mode:
                packet = DhcpMessage.decode(
                    bytearray.fromhex(
                        "".join(ch for ch in payload_text if ch not in " \t\r\n:")
                    )
                )
                if self.packet_format == "summary":
                    output = packet.log_str("capture", "decoded")
                else:
                    output = dump_message(packet, self.packet_format)
            else:
                if self.packet_format == "summary":
                    raise ValueError(
                        "summary output is only supported when decoding packets"
                    )
                packet = load_message(payload_text, self.packet_format)
                output = packet.encode().hex()

            if self.output == "-":
                sys.stdout.write(output)
                if not output.endswith("\n"):
                    sys.stdout.write("\n")
            else:
                pathlib.Path(self.output).write_text(output, encoding="utf-8")
        except Exception as e:
            print(f"Error processing packet: {e}", file=sys.stderr)
            sys.exit(1)


def _infer_capture_format(
    output: "pathlib.Path | str | None", packet_format: "str | None"
) -> str:
    if packet_format:
        return packet_format
    if output is not None and str(output) != "-":
        suffix = pathlib.Path(str(output)).suffix.lower()
        if suffix == ".json":
            return "json"
        if suffix in {".yaml", ".yml"}:
            return "yaml"
        if suffix == ".toml":
            return "toml"
        if suffix == ".ini":
            return "ini"
    return "json"


def _infer_output_mode(
    output: "pathlib.Path | str | None", output_mode: "str | None"
) -> str:
    if output_mode:
        return output_mode
    if output is None or str(output) == "-":
        return "stream"
    return "single"


def _serialize_capture_event(event: CaptureEvent, packet_format: str) -> str:
    if packet_format == "json":
        return _json.dumps(event.message.to_mapping()) + "\n"
    return dump_message(event.message, packet_format)


def _stream_separator(packet_format: str, first: bool) -> str:
    """Return what must precede a record so the file stays parseable.

    YAML gets its `---` even on the first record of a run. The flag says "first
    for this process", but the file is opened for append: a second run's first
    record was written straight onto the last record of the first with no
    separator, so YAML merged the two mappings and the earlier record silently
    disappeared on load. A leading `---` is valid for the opening document too,
    which makes the output correct whether the file is new or appended to.
    """
    if packet_format == "json":
        return ""  # newline-delimited; a separator would break it
    return "---\n"


#: How many distinct files one `--output-mode per-capture` run may create.
#: The filename pattern interpolates values the *client* chooses -- the client
#: identifier above all -- so without a bound, one unauthenticated sender
#: decides how many files land on the operator's disk. Measured: 5,000 forged
#: identifiers produced 5,000 files.
MAX_PER_CAPTURE_FILES = 1000


def _per_capture_budget(state: "dict[str, _ty.Any]", path: pathlib.Path) -> bool:
    """Whether this run may still create `path`. Rewriting a file is always fine.

    Counted per run rather than per name so that a pattern *without* a
    client-chosen component -- which simply overwrites one file -- is not
    limited at all.
    """
    seen = state.setdefault("per_capture_files", set())
    if path in seen:
        return True
    if len(seen) < MAX_PER_CAPTURE_FILES:
        seen.add(path)
        return True
    if not state.get("per_capture_full_reported"):
        state["per_capture_full_reported"] = True
        LOGGER.warning(
            f"Reached {MAX_PER_CAPTURE_FILES} per-capture files; not creating more. "
            "The filename pattern includes a value the client chooses, so a flood "
            "of forged identifiers would otherwise fill the disk. Raise "
            "MAX_PER_CAPTURE_FILES, or use a pattern without {client_id}."
        )
    state["per_capture_refused"] = state.get("per_capture_refused", 0) + 1
    return False


def _write_capture_record(
    event: CaptureEvent,
    *,
    output: "pathlib.Path | str | None",
    output_mode: str,
    packet_format: str,
    state: "dict[str, _ty.Any]",
) -> str:
    payload = _serialize_capture_event(event, packet_format)
    target = "-" if output is None else str(output)
    if output_mode == "per-capture":
        if target == "-":
            raise ValueError("--output-mode per-capture requires a filename pattern")
        path = pathlib.Path(event.format_filename(target, packet_format))
        if not _per_capture_budget(state, path):
            return payload
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
        return payload

    prefix = _stream_separator(packet_format, bool(state.get("first", True)))
    state["first"] = False
    record = prefix + payload
    if target == "-":
        sys.stdout.write(record)
        if not record.endswith("\n"):
            sys.stdout.write("\n")
        # Flush per record: piped into `jq` or `tee`, stdout is block-buffered,
        # so a live capture showed nothing for ~8 KB or until it exited -- and
        # lost whatever was still buffered if it was killed.
        sys.stdout.flush()
        return payload

    path = pathlib.Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(record)
        if not record.endswith("\n"):
            handle.write("\n")
    return payload


#: How long a command hook may run before it is treated as a failure. The hook
#: runs on the receive thread, so without a bound a hanging one (a network
#: export, say) stops packets being read at all, with nothing logged.
HOOK_TIMEOUT_SECONDS = 10.0


@contextlib.contextmanager
def _cwd_on_sys_path() -> "_ty.Iterator[None]":
    """Make `--hook myhooks:on_capture` work from the installed console script.

    A console script's `sys.path[0]` is its own Scripts directory, not the
    working directory, so the form the docs show could not import a module
    sitting next to the user.
    """
    cwd = os.getcwd()
    added = cwd not in sys.path
    if added:
        sys.path.insert(0, cwd)
    try:
        yield
    finally:
        if added:
            try:
                sys.path.remove(cwd)
            except ValueError:  # pragma: no cover - someone else removed it
                pass


def _load_capture_hook(
    hook: "str | None", packet_format: str, fail_fast: bool
) -> "_ty.Callable[[CaptureEvent], None] | None":
    if not hook:
        return None
    hook_path = pathlib.Path(hook)
    # A module reference is `package.module:function` -- never contains a path
    # separator. Deciding on the separator rather than on ':' alone keeps
    # "C:\hooks\export.exe" a path on every platform: it has exactly one ':', so
    # it used to be read as module "C" and reported as "No module named 'C'",
    # and splitdrive alone would only have fixed that on Windows.
    looks_like_path = "/" in hook or "\\" in hook or hook_path.exists()
    if not looks_like_path and hook.count(":") == 1:
        module_name, function_name = hook.split(":", 1)
        with _cwd_on_sys_path():
            module = importlib.import_module(module_name)
        function = getattr(module, function_name, None)
        if not callable(function):
            raise ValueError(f"Capture hook {hook!r} does not resolve to a callable")
        return _ty.cast(_ty.Callable[[CaptureEvent], None], function)
    if not hook_path.exists():
        raise ValueError(f"Capture hook command does not exist: {hook}")
    if not hook_path.is_file():
        raise ValueError(f"Capture hook command is not a file: {hook}")

    def command_hook(event: CaptureEvent) -> None:
        payload = _serialize_capture_event(event, packet_format)
        env = os.environ.copy()
        env.update(
            {
                "PYDHCP_CAPTURE_CLIENT_ID": event.client_id,
                "PYDHCP_CAPTURE_MSG_TYPE": event.message_type,
                "PYDHCP_CAPTURE_XID": event.xid,
                "PYDHCP_CAPTURE_FORMAT": packet_format,
            }
        )
        try:
            result = subprocess.run(
                [str(hook_path)],
                input=payload,
                text=True,
                capture_output=True,
                env=env,
                timeout=HOOK_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as expired:
            # The hook runs on the receive thread, so without this a hanging one
            # stops packets being read at all and nothing says why.
            raise RuntimeError(
                f"Capture hook command timed out after {HOOK_TIMEOUT_SECONDS}s: "
                f"{hook_path}"
            ) from expired
        if result.stdout:
            LOGGER.debug("Capture hook command output: %s", result.stdout.strip())
        if result.returncode != 0:
            LOGGER.error(
                "Capture hook command failed (%s): %s",
                result.returncode,
                result.stderr.strip(),
            )
            if fail_fast:
                raise RuntimeError(
                    f"Capture hook command failed with exit code {result.returncode}"
                )

    return command_hook


class Capture(_Command):
    """Capture DHCP packets"""

    _parsername_ = "capture"

    listen: _ty.Optional[str] = None
    "Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'"
    ("--listen", "-l")

    packet_filter: _ty.Optional[str] = None
    "Capture filter expression"
    ("--filter",)

    packet_format: _ty.Annotated[_ty.Optional[str], Meta(choices=CAPTURE_FORMATS)] = (
        None
    )
    ("--format", "-f")

    output: pathlib.Path = pathlib.Path("-")
    "Capture output path, filename pattern, or '-' for stdout"
    ("--output", "-o")

    output_mode: _ty.Annotated[
        _ty.Optional[str], Meta(choices=("stream", "single", "per-capture"))
    ] = None
    "Write a stream, one combined file, or one file per captured packet"
    ("--output-mode",)

    count: _ty.Optional[int] = None
    "Stop after N accepted packets"
    ("--count", "-c")

    hook: _ty.Optional[str] = None
    "Python hook module:function or external command path"
    ("--hook",)

    hook_fail_fast: bool = False
    "Stop capturing and exit non-zero on the first hook failure"
    ("--hook-fail-fast",)

    per_interface: bool = False
    "Bind each interface separately instead of using wildcard packet-info routing"
    ("--per-interface",)

    def __call__(self) -> None:
        try:
            output = self.output if self.output is not None else pathlib.Path("-")
            output_mode = _infer_output_mode(output, self.output_mode)
            if output_mode == "per-capture":
                if str(output) == "-":
                    raise ValueError(
                        "--output-mode per-capture requires --output to be a "
                        "filename pattern"
                    )
                # Both checks run before binding, for the same reason the
                # capture filter is compiled eagerly: the pattern is only ever
                # expanded inside the receive handler, so a mistake there costs
                # one message per packet and no recording at all.
                used_fields = validate_filename_pattern(str(output))
                if not used_fields & UNIQUE_FILENAME_FIELDS:
                    self._logger_.warning(
                        "--output pattern %s names neither {timestamp} nor {xid}, "
                        "so any two packets agreeing on the rest of it resolve to "
                        "the same file and only the last one is kept",
                        output,
                    )
            packet_format = _infer_capture_format(output, self.packet_format)
            if packet_format in ("toml", "ini") and output_mode != "per-capture":
                # Concatenating records produces a file no parser will read: TOML
                # has no document separator, and a second [message] section is a
                # DuplicateSectionError to configparser. One record per file is
                # the only shape these formats have for this. Raised before
                # binding, so it fails immediately rather than after capturing.
                raise ValueError(
                    f"--format {packet_format} cannot hold more than one packet in a "
                    f"single file; use --output-mode per-capture with a filename "
                    f"pattern, or --format json (newline-delimited) or yaml "
                    f"(multi-document). Note the format is inferred from the "
                    f"--output extension when --format is not given."
                )
            state: "dict[str, _ty.Any]" = {"first": True, "count": 0}
            capture: DhcpCapture

            def sink(event: CaptureEvent) -> None:
                _write_capture_record(
                    event,
                    output=output,
                    output_mode=output_mode,
                    packet_format=packet_format,
                    state=state,
                )
                state["count"] += 1
                if self.count is not None and state["count"] >= self.count:
                    capture.stop()

            hook = _load_capture_hook(self.hook, packet_format, self.hook_fail_fast)
            capture = DhcpCapture(
                listen=self.listen or "*",
                packet_filter=self.packet_filter,
                sink=sink,
                hook=hook,
                hook_fail_fast=self.hook_fail_fast,
                per_interface=self.per_interface,
            )
            capture.bind()
            capture.listen()
            if capture.hook_error is not None:
                # --hook-fail-fast asked for this: say why it stopped, and do
                # not report success.
                print(
                    f"Capture stopped: hook failed ({capture.hook_error})",
                    file=sys.stderr,
                )
                sys.exit(1)
        except Exception as e:
            print(f"Error capturing packets: {e}", file=sys.stderr)
            sys.exit(1)


class App(Cli):
    """pydhcp CLI Interface"""

    # duho names the program after the class, so every usage line and every
    # error read "App" -- a name that appears nowhere the user installed,
    # typed, or could look up.
    _parsername_ = "pydhcp"
    _version_ = AUTO
    _logger_name_ = "pydhcp"
    _help_formatter_ = DefaultsFormatter
    _subcommands_ = [Interfaces, Server, Relay, Packet, Capture]


def main() -> None:
    try:
        sys.exit(duho.main(App))
    except (ValueError, OSError, NotImplementedError) as error:
        # A mistyped port, a missing config, an address already in use or a bad
        # hex id is a user error, not a crash. duho lets exceptions out of the
        # command, so these arrived as tracebacks -- including the privileged-
        # port hint the listener carefully builds. Set PYDHCP_TRACEBACK=1 to see
        # the traceback anyway when diagnosing pydhcp itself.
        if os.environ.get("PYDHCP_TRACEBACK"):
            raise
        print(f"pydhcp: error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
