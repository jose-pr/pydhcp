"""Record every DHCP datagram crossing one interface, as it was on the wire.

Run: python tap.py <interface> <output.jsonl> <ready-file>

Sees what the namespace sends as well as what it receives (an `ETH_P_IP` socket
would see only the latter). Uses only the standard library, so what it reports
is the kernel's account and not the library's. One JSON object per line, written as the frame arrives.
"""

from __future__ import annotations

import json
import signal
import socket
import struct
import sys

iface, out_path, ready_path = sys.argv[1], sys.argv[2], sys.argv[3]
ETH_P_ALL = 0x0003
KINDS = {0: "host", 1: "broadcast", 2: "multicast", 3: "otherhost", 4: "outgoing"}
SO_RCVBUFFORCE = 33

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
try:
    sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 16 * 1024 * 1024)
except OSError:
    pass
sock.bind((iface, ETH_P_ALL))
sock.settimeout(0.2)
out = open(out_path, "w", encoding="utf-8", buffering=1, newline="\n")
stop = False


def _stop(*_args: object) -> None:
    global stop
    stop = True


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)
open(ready_path, "w").close()


def mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


seq = 0
while not stop:
    try:
        data, info = sock.recvfrom(65535)
    except socket.timeout:
        continue
    if len(data) < 14 + 20 + 8 or data[12:14] != b"\x08\x00":
        continue
    header = (data[14] & 0x0F) * 4
    if data[14 + 9] != 17:
        continue
    udp = 14 + header
    sport, dport, length = struct.unpack("!HHH", data[udp : udp + 6])
    if not ({sport, dport} & {67, 68}):
        continue
    payload = data[udp + 8 : udp + length]
    seq += 1
    out.write(
        json.dumps(
            {
                "seq": seq,
                "kind": KINDS.get(info[2], str(info[2])),
                "src_mac": mac(data[6:12]),
                "dst_mac": mac(data[0:6]),
                "src_ip": socket.inet_ntoa(data[26:30]),
                "dst_ip": socket.inet_ntoa(data[30:34]),
                "sport": sport,
                "dport": dport,
                "payload": payload.hex(),
            }
        )
        + "\n"
    )
