from __future__ import annotations

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

from .capture import CaptureEvent, DhcpCapture
from .network import host_ip_interfaces
from .server import DhcpServer
from .relay import DhcpRelay
from .config import load_config
from .packet.message import DhcpMessage
from .packet.structured import dump_message, load_message

PACKET_FORMATS = ("json", "yaml", "toml", "ini", "summary")
CAPTURE_FORMATS = ("json", "yaml", "toml", "ini")


class Interfaces(LoggingArgs, Cmd):
    """List network interfaces"""

    _parsername_ = "interfaces"

    def __call__(self) -> None:
        print("Available Network Interfaces:")
        for interface in host_ip_interfaces():
            print(f"Name: {interface.name}")
            print(f"  IP:   {interface.ip}")
            print(f"  MAC:  {interface.mac}")
            print(f"  Net:  {interface.network}")


class Server(LoggingArgs, Cmd):
    """Start DHCP server"""

    _parsername_ = "server"

    config: _ty.Optional[str] = None
    "Path to config file (JSON, YAML, TOML, or INI)"
    ("--config",)

    listen: _ty.Optional[str] = None
    "Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'"
    ("--listen", "-l")

    def __call__(self) -> None:
        config: _ty.Dict[str, _ty.Any] = {}
        if self.config:
            config = load_config(self.config)

        server_config = config.get("server", {})
        listen = server_config.get("listen", self.listen or "*")

        self._logger_.info("Starting DHCP server, listening on: %s...", listen)
        server = DhcpServer(listen=listen)
        try:
            server.bind()
            server.listen()
        except KeyboardInterrupt:
            self._logger_.info("Stopping server...")
            server.stop()


def _parse_server_address(value: str) -> "tuple[str, int] | str":
    if value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        return (host or "0.0.0.0", int(port_text))
    return value


class Relay(LoggingArgs, Cmd):
    """Start DHCP relay agent"""

    _parsername_ = "relay"

    listen: _ty.Optional[str] = None
    "Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'"
    ("--listen", "-l")

    server: _ty.List[str] = []
    "Upstream DHCP server address, optionally host:port (repeatable)"
    ("--server", "-s")

    max_hops: int = 16
    "Drop requests exceeding this hop count"
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

    def __call__(self) -> None:
        server_addresses = [_parse_server_address(addr) for addr in self.server]
        circuit_id = bytes.fromhex(self.circuit_id) if self.circuit_id else None
        remote_id = bytes.fromhex(self.remote_id) if self.remote_id else None

        self._logger_.info(
            "Starting DHCP relay, listening on: %s, forwarding to: %s...",
            self.listen or "*",
            self.server,
        )
        relay = DhcpRelay(
            listen=self.listen or "*",
            server_addresses=server_addresses,
            max_hops=self.max_hops,
            insert_relay_agent_info=self.insert_relay_agent_info,
            circuit_id=circuit_id,
            remote_id=remote_id,
        )
        try:
            relay.bind()
            relay.listen()
        except KeyboardInterrupt:
            self._logger_.info("Stopping relay...")
            relay.stop()


class Packet(LoggingArgs, Cmd):
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
        return payload

    path = pathlib.Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(record)
        if not record.endswith("\n"):
            handle.write("\n")
    return payload


def _load_capture_hook(
    hook: "str | None", packet_format: str, fail_fast: bool
) -> "_ty.Callable[[CaptureEvent], None] | None":
    if not hook:
        return None
    hook_path = pathlib.Path(hook)
    if hook.count(":") == 1 and not hook_path.exists():
        module_name, function_name = hook.split(":", 1)
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
        result = subprocess.run(
            [str(hook_path)],
            input=payload,
            text=True,
            capture_output=True,
            env=env,
        )
        if result.returncode != 0:
            _logging.getLogger("pydhcp").error(
                "Capture hook command failed (%s): %s",
                result.returncode,
                result.stderr.strip(),
            )
            if fail_fast:
                raise RuntimeError(
                    f"Capture hook command failed with exit code {result.returncode}"
                )

    return command_hook


class Capture(LoggingArgs, Cmd):
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
    ("--hook-fail-fast",)

    per_interface: bool = False
    "Bind each interface separately instead of using wildcard packet-info routing"
    ("--per-interface",)

    def __call__(self) -> None:
        try:
            output = self.output if self.output is not None else pathlib.Path("-")
            output_mode = _infer_output_mode(output, self.output_mode)
            if output_mode == "per-capture" and str(output) == "-":
                raise ValueError(
                    "--output-mode per-capture requires --output to be a filename pattern"
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
        except Exception as e:
            print(f"Error capturing packets: {e}", file=sys.stderr)
            sys.exit(1)


class App(Cli):
    """pydhcp CLI Interface"""

    _version_ = AUTO
    _logger_name_ = "pydhcp"
    _help_formatter_ = DefaultsFormatter
    _subcommands_ = [Interfaces, Server, Relay, Packet, Capture]


def main() -> None:
    sys.exit(duho.main(App))


if __name__ == "__main__":
    main()
