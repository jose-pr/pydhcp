"""Send scripted DHCP requests, as a client or as a relay would.

Run: python emit.py <mode> [options]

Modes:
  discover   one DISCOVER, broadcast from 0.0.0.0:68 (a client with no address)
  relayed    one DISCOVER sent as a relay does: unicast to --dst from --src:67
             with giaddr set
  flood      --count DISCOVERs, each with its own chaddr and xid, broadcast
             from --src:68 (a host on the segment forging clients)
  kinds      three DISCOVERs each to --dst-port .. +3 ports by three routes (the
             limited broadcast, the subnet broadcast, a unicast), the kind
             encoded in the xid's high octet
"""

from __future__ import annotations

import argparse
import socket
import time

from pydhcp import DHCPClient
from ipaddress import IPv4Address as IPv4

parser = argparse.ArgumentParser()
parser.add_argument("mode")
parser.add_argument("--src", default="0.0.0.0")
parser.add_argument("--dst", default="255.255.255.255")
parser.add_argument("--dst-port", type=int, default=67)
parser.add_argument("--src-port", type=int, default=68)
parser.add_argument("--giaddr")
parser.add_argument("--chaddr", default="020000000099")
parser.add_argument("--count", type=int, default=1)
parser.add_argument("--xid", type=lambda s: int(s, 0), default=0x1A2B3C4D)
parser.add_argument("--subnet-broadcast")
parser.add_argument("--device", help="send out of this interface regardless of routes")
args = parser.parse_args()

builder = DHCPClient()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
if args.device:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.device.encode())
sock.bind((args.src, args.src_port))


def discover(chaddr: bytes, xid: int):
    return builder.build_discover(chaddr, xid=xid)


if args.mode == "discover":
    sock.sendto(
        discover(bytes.fromhex(args.chaddr), args.xid).encode(),
        (args.dst, args.dst_port),
    )
elif args.mode == "relayed":
    message = discover(bytes.fromhex(args.chaddr), args.xid)
    message.giaddr = IPv4(args.giaddr)
    message.hops = 1
    sock.sendto(message.encode(), (args.dst, args.dst_port))
elif args.mode == "flood":
    for index in range(args.count):
        chaddr = bytes.fromhex("02ff") + index.to_bytes(4, "big")
        sock.sendto(
            discover(chaddr, 0x70000000 + index).encode(), (args.dst, args.dst_port)
        )
        if index % 64 == 63:
            time.sleep(0.01)
elif args.mode == "kinds":
    for port in range(args.dst_port, args.dst_port + 4):
        for marker, target in (
            (0xB1, "255.255.255.255"),
            (0xB2, args.subnet_broadcast),
            (0xC0, args.dst),
        ):
            for index in range(3):
                payload = discover(bytes.fromhex(args.chaddr), (marker << 24) | index)
                try:
                    sock.sendto(payload.encode(), (target, port))
                except OSError as error:
                    print(f"cannot send to {target}:{port}: {error}")
                time.sleep(0.02)
else:
    raise SystemExit(f"unknown mode {args.mode}")
print("sent", flush=True)
