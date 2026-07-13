import argparse
import pathlib
import sys
import typing as _ty
import logging as _logging

from .netutils import host_ip_interfaces
from .server import DhcpServer
from .config import load_config
from .message import DhcpMessage
from .structured import dump_message, load_message
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


def cmd_packet(args: argparse.Namespace) -> None:
    try:
        if args.input_file is not None:
            payload_text = args.input_file.read_text(encoding="utf-8")
        elif args.stdin:
            payload_text = sys.stdin.read()
        else:
            payload_text = args.input_text

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

        if args.output_file is not None:
            args.output_file.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
            if not output.endswith("\n"):
                sys.stdout.write("\n")
    except Exception as e:
        print(f"Error processing packet: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="pydhcp CLI Interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("interfaces", help="List network interfaces")

    server_parser = subparsers.add_parser("server", help="Start DHCP server")
    server_parser.add_argument("--config", help="Path to config file (JSON or INI)")
    server_parser.add_argument(
        "--listen",
        help="Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'",
    )
    server_parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Set pydhcp log verbosity",
    )

    packet_parser = subparsers.add_parser("packet", help="Encode or decode DHCP packets")
    mode_group = packet_parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--decode", dest="mode", action="store_const", const="decode")
    mode_group.add_argument("--encode", dest="mode", action="store_const", const="encode")
    input_group = packet_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input", dest="input_text", help="Inline packet text")
    input_group.add_argument("--input-file", type=pathlib.Path, dest="input_file", help="Read packet text from a file")
    input_group.add_argument("--stdin", action="store_true", help="Read packet text from standard input")
    format_group = packet_parser.add_mutually_exclusive_group()
    format_group.add_argument("--json", dest="packet_format", action="store_const", const="json")
    format_group.add_argument("--yaml", dest="packet_format", action="store_const", const="yaml")
    format_group.add_argument("--toml", dest="packet_format", action="store_const", const="toml")
    format_group.add_argument("--ini", dest="packet_format", action="store_const", const="ini")
    format_group.add_argument("--summary", dest="packet_format", action="store_const", const="summary")
    packet_parser.set_defaults(packet_format="json", input_file=None, input_text=None)
    packet_parser.add_argument(
        "--output-file",
        type=pathlib.Path,
        help="Write packet output to a file instead of stdout",
    )

    args = parser.parse_args()

    if args.command == "interfaces":
        cmd_interfaces(args)
    elif args.command == "server":
        cmd_server(args)
    elif args.command == "packet":
        cmd_packet(args)


if __name__ == "__main__":
    main()
