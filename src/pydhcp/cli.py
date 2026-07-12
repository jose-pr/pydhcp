import argparse
import pathlib
import sys
import typing as _ty
import logging as _logging

from .netutils import host_ip_interfaces
from .server import DhcpServer
from .config import load_config
from .message import DhcpMessage
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
    if args.decode:
        try:
            raw_bytes = bytearray.fromhex(args.decode.replace(":", "").replace(" ", "").replace("\n", "").replace("\r", ""))
            msg = DhcpMessage.decode(raw_bytes)
            print("Decoded Message:")
            print(f"  OP: {msg.op.name}")
            print(f"  XID: 0x{msg.xid:08X}")
            print(f"  Client IP: {msg.ciaddr}")
            print(f"  Your IP: {msg.yiaddr}")
            print(f"  Server IP: {msg.siaddr}")
            print(f"  MAC: {msg.chaddr.hex().upper()}")
            print("  Options:")
            for code, opt in msg.options.items(decoded=True):
                name = getattr(code, "name", str(code))
                print(f"    {name}: {opt}")
        except Exception as e:
            print(f"Error decoding packet: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Please specify --decode <HEX>", file=sys.stderr)
        sys.exit(1)


def cmd_bench(args: argparse.Namespace) -> None:
    # Import locally to prevent test imports overhead
    sys.path.insert(0, ".")
    iterations = args.iterations if args.iterations is not None else 10000
    if args.suite == "options":
        from benchmarks.bench_options import run_benchmarks, write_json_report
    else:
        from benchmarks.bench_parse import run_benchmarks, write_json_report

    benchmarks = run_benchmarks(iterations=iterations)
    if args.json_output:
        write_json_report(args.json_output, iterations, benchmarks)


def main() -> None:
    parser = argparse.ArgumentParser(description="pydhcp CLI Interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("interfaces", help="List network interfaces")

    server_parser = subparsers.add_parser("server", help="Start DHCP server")
    server_parser.add_argument("--config", help="Path to config file (JSON or INI)")
    server_parser.add_argument("--listen", help="Listen address/port spec")
    server_parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Set pydhcp log verbosity",
    )

    packet_parser = subparsers.add_parser("packet", help="Decode DHCP packets")
    packet_parser.add_argument("--decode", help="Hex string of packet bytes to decode")

    bench_parser = subparsers.add_parser("bench", help="Run performance benchmarks")
    bench_parser.add_argument(
        "--suite",
        choices=["parse", "options"],
        default="parse",
        help="Benchmark suite to run",
    )
    bench_parser.add_argument(
        "--iterations",
        type=int,
        help="Override the benchmark iteration count",
    )
    bench_parser.add_argument(
        "--json-output",
        type=pathlib.Path,
        help="Optional path to write structured benchmark results as JSON",
    )

    args = parser.parse_args()

    if args.command == "interfaces":
        cmd_interfaces(args)
    elif args.command == "server":
        cmd_server(args)
    elif args.command == "packet":
        cmd_packet(args)
    elif args.command == "bench":
        cmd_bench(args)


if __name__ == "__main__":
    main()
