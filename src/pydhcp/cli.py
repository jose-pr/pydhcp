from __future__ import annotations

import argparse
import importlib
import json as _json
import pathlib
import os
import subprocess
import sys
import typing as _ty
import logging as _logging

from .capture import CaptureEvent, DhcpCapture
from .network import host_ip_interfaces
from .server import DhcpServer
from .relay import DhcpRelay
from .config import load_config
from .packet.message import DhcpMessage
from .packet.structured import dump_message, load_message
from .log import LOGGER


def cmd_interfaces(args: argparse.Namespace) -> None:
    print("Available Network Interfaces:")
    for interface in host_ip_interfaces():
        print(f"Name: {interface.name}")
        print(f"  IP:   {interface.ip}")
        print(f"  MAC:  {interface.mac}")
        print(f"  Net:  {interface.network}")


def cmd_server(args: argparse.Namespace) -> None:
    if args.log_level:
        LOGGER.setLevel(getattr(_logging, args.log_level.upper()))

    config = {}
    if args.config:
        config = load_config(args.config)

    server_config = config.get("server", {})
    listen = server_config.get("listen", args.listen or "*")

    print(f"Starting DHCP server, listening on: {listen}...")
    server = DhcpServer(listen=listen)
    try:
        server.bind()
        server.listen()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.stop()


def _parse_server_address(value: str) -> tuple[str, int] | str:
    if value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        return (host or "0.0.0.0", int(port_text))
    return value


def cmd_relay(args: argparse.Namespace) -> None:
    if args.log_level:
        LOGGER.setLevel(getattr(_logging, args.log_level.upper()))

    server_addresses = [_parse_server_address(addr) for addr in args.server]
    circuit_id = bytes.fromhex(args.circuit_id) if args.circuit_id else None
    remote_id = bytes.fromhex(args.remote_id) if args.remote_id else None

    print(f"Starting DHCP relay, listening on: {args.listen or '*'}, forwarding to: {args.server}...")
    relay = DhcpRelay(
        listen=args.listen or "*",
        server_addresses=server_addresses,
        max_hops=args.max_hops,
        insert_relay_agent_info=args.insert_relay_agent_info,
        circuit_id=circuit_id,
        remote_id=remote_id,
    )
    try:
        relay.bind()
        relay.listen()
    except KeyboardInterrupt:
        print("\nStopping relay...")
        relay.stop()


def cmd_packet(args: argparse.Namespace) -> None:
    try:
        if args.input == "-":
            payload_text = sys.stdin.read()
        else:
            payload_text = pathlib.Path(args.input).read_text(encoding="utf-8")

        if args.mode == "decode":
            packet = DhcpMessage.decode(bytearray.fromhex("".join(ch for ch in payload_text if ch not in " \t\r\n:")))
            if args.packet_format == "summary":
                output = packet.log_str("capture", "decoded")
            else:
                output = dump_message(packet, args.packet_format)
        else:
            if args.packet_format == "summary":
                raise ValueError("summary output is only supported when decoding packets")
            packet = load_message(payload_text, args.packet_format)
            output = packet.encode().hex()

        if args.output == "-":
            sys.stdout.write(output)
            if not output.endswith("\n"):
                sys.stdout.write("\n")
        else:
            pathlib.Path(args.output).write_text(output, encoding="utf-8")
    except Exception as e:
        print(f"Error processing packet: {e}", file=sys.stderr)
        sys.exit(1)


def _infer_capture_format(output: pathlib.Path | str | None, packet_format: str | None) -> str:
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


def _infer_output_mode(output: pathlib.Path | str | None, output_mode: str | None) -> str:
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
    if first:
        return ""
    return "" if packet_format == "json" else "---\n"


def _write_capture_record(
    event: CaptureEvent,
    *,
    output: pathlib.Path | str | None,
    output_mode: str,
    packet_format: str,
    state: dict[str, _ty.Any],
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


def _load_capture_hook(hook: str | None, packet_format: str, fail_fast: bool) -> _ty.Callable[[CaptureEvent], None] | None:
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
            LOGGER.error("Capture hook command failed (%s): %s", result.returncode, result.stderr.strip())
            if fail_fast:
                raise RuntimeError(f"Capture hook command failed with exit code {result.returncode}")

    return command_hook


def cmd_capture(args: argparse.Namespace) -> None:
    try:
        if args.log_level:
            LOGGER.setLevel(getattr(_logging, args.log_level.upper()))
        output = args.output if args.output is not None else pathlib.Path("-")
        output_mode = _infer_output_mode(output, args.output_mode)
        if output_mode == "per-capture" and str(output) == "-":
            raise ValueError("--output-mode per-capture requires --output to be a filename pattern")
        packet_format = _infer_capture_format(output, args.packet_format)
        state: dict[str, _ty.Any] = {"first": True, "count": 0}
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
            if args.count is not None and state["count"] >= args.count:
                capture.stop()

        hook = _load_capture_hook(args.hook, packet_format, args.hook_fail_fast)
        capture = DhcpCapture(
            listen=args.listen or "*",
            packet_filter=args.packet_filter,
            sink=sink,
            hook=hook,
            hook_fail_fast=args.hook_fail_fast,
            per_interface=args.per_interface,
        )
        capture.bind()
        capture.listen()
    except Exception as e:
        print(f"Error capturing packets: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="pydhcp CLI Interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("interfaces", help="List network interfaces")

    server_parser = subparsers.add_parser("server", help="Start DHCP server")
    server_parser.add_argument("--config", help="Path to config file (JSON, YAML, TOML, or INI)")
    server_parser.add_argument(
        "--listen",
        help="Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'",
    )
    server_parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Set pydhcp log verbosity",
    )

    relay_parser = subparsers.add_parser("relay", help="Start DHCP relay agent")
    relay_parser.add_argument(
        "--listen",
        help="Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'",
    )
    relay_parser.add_argument(
        "--server",
        action="append",
        required=True,
        help="Upstream DHCP server address, optionally host:port (repeatable)",
    )
    relay_parser.add_argument("--max-hops", type=int, default=16, help="Drop requests exceeding this hop count")
    relay_parser.add_argument(
        "--insert-relay-agent-info",
        action="store_true",
        help="Add RELAY_AGENT_INFORMATION (option 82) to forwarded requests",
    )
    relay_parser.add_argument("--circuit-id", help="Hex-encoded circuit ID sub-option (requires --insert-relay-agent-info)")
    relay_parser.add_argument("--remote-id", help="Hex-encoded remote ID sub-option (requires --insert-relay-agent-info)")
    relay_parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Set pydhcp log verbosity",
    )

    packet_parser = subparsers.add_parser("packet", help="Encode or decode DHCP packets")
    mode_group = packet_parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--decode", dest="mode", action="store_const", const="decode")
    mode_group.add_argument("--encode", dest="mode", action="store_const", const="encode")
    packet_parser.add_argument(
        "--input",
        default="-",
        help="Input file path, or '-' for stdin (default: '-')",
    )
    packet_parser.add_argument(
        "--output",
        default="-",
        help="Output file path, or '-' for stdout (default: '-')",
    )
    packet_parser.add_argument(
        "--format",
        dest="packet_format",
        default="json",
        choices=["json", "yaml", "toml", "ini", "summary"],
        help="Packet text format; 'summary' is decode-only (default: json)",
    )

    capture_parser = subparsers.add_parser("capture", help="Capture DHCP packets")
    capture_parser.add_argument(
        "--listen",
        help="Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'",
    )
    capture_parser.add_argument("--filter", dest="packet_filter", help="Capture filter expression")
    capture_parser.add_argument("--format", dest="packet_format", choices=["json", "yaml", "toml", "ini"])
    capture_parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("-"),
        help="Capture output path, filename pattern, or '-' for stdout",
    )
    capture_parser.add_argument(
        "--output-mode",
        choices=["stream", "single", "per-capture"],
        help="Write a stream, one combined file, or one file per captured packet",
    )
    capture_parser.add_argument("--count", type=int, help="Stop after N accepted packets")
    capture_parser.add_argument("--hook", help="Python hook module:function or external command path")
    capture_parser.add_argument("--hook-fail-fast", action="store_true")
    capture_parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Set pydhcp log verbosity",
    )
    capture_parser.add_argument(
        "--per-interface",
        action="store_true",
        help="Bind each interface separately instead of using wildcard packet-info routing",
    )

    args = parser.parse_args()

    if args.command == "interfaces":
        cmd_interfaces(args)
    elif args.command == "server":
        cmd_server(args)
    elif args.command == "relay":
        cmd_relay(args)
    elif args.command == "packet":
        cmd_packet(args)
    elif args.command == "capture":
        cmd_capture(args)


if __name__ == "__main__":
    main()
