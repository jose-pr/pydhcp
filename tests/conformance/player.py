"""The scripted ends of a recording, run inside a lab namespace. Development only.

    python player.py send IFACE STEPS.json PROGRESS.jsonl
    python player.py answer IFACE REPLIES.json READY

``send`` plays a case's steps in order: each is one datagram from the source
address and port the step names, bound to the interface (so a client with no
address can broadcast) and followed by ``SILENCE`` seconds in which the answer
reaches the tap. A step that says ``holds`` has the interface carry that address
for as long as it takes. ``PROGRESS`` gets one line per step with its start on
``time.monotonic()``, the clock the tap stamps frames with.

``answer`` is the scripted server: it listens on port 67 of the interface and
answers each request whose type ``REPLIES`` names (a message in ``exchange``'s
form) to ``giaddr`` at port 67, or to the limited broadcast at port 68. It runs
until it is terminated.

Standard library and ``exchange`` only: what is sent is what the case says.
"""

from __future__ import annotations

import json
import signal
import socket
import subprocess
import sys
import time

import exchange

#: How long after a datagram the answer is given to arrive before the next one goes.
SILENCE = 1.5
PREFIX = 24


def _udp(iface: str, address: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
    sock.bind((address, port))
    return sock


def _holds(iface: str, address: str) -> bool:
    shown = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", iface], capture_output=True, text=True
    ).stdout
    return (address + "/") in shown


def send(iface: str, steps_path: str, progress_path: str) -> None:
    with open(steps_path, encoding="utf-8") as handle:
        steps = json.load(handle)
    with open(
        progress_path, "w", encoding="utf-8", buffering=1, newline="\n"
    ) as progress:
        for step in steps:
            added = (
                step.get("holds")
                if step.get("holds") and not _holds(iface, step["holds"])
                else None
            )
            if added:
                subprocess.run(
                    ["ip", "addr", "add", "%s/%d" % (added, PREFIX), "dev", iface],
                    check=True,
                )
            sock = _udp(iface, step.get("src", "0.0.0.0"), step.get("sport", 68))
            try:
                progress.write(
                    json.dumps({"step": step["name"], "t": time.monotonic()}) + "\n"
                )
                sock.sendto(
                    exchange.build(step["message"]),
                    (step.get("dst", "255.255.255.255"), step.get("dport", 67)),
                )
                time.sleep(SILENCE)
            finally:
                sock.close()
                if added:
                    subprocess.run(
                        ["ip", "addr", "del", "%s/%d" % (added, PREFIX), "dev", iface]
                    )


def answer(iface: str, replies_path: str, ready_path: str) -> None:
    with open(replies_path, encoding="utf-8") as handle:
        replies = json.load(handle)
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    sock = _udp(iface, "0.0.0.0", 67)
    sock.settimeout(0.2)
    open(ready_path, "w").close()
    while not stopping:
        try:
            request, _source = sock.recvfrom(4096)
        except socket.timeout:
            continue
        try:
            reply = replies.get(exchange.message_type(request))
        except ValueError:
            continue
        if reply is None:
            continue
        data = exchange.answer(request, reply)
        giaddr = exchange.read(request)["giaddr"]
        target = (giaddr, 67) if giaddr != "0.0.0.0" else ("255.255.255.255", 68)
        sock.sendto(data, target)


if __name__ == "__main__":
    {"send": send, "answer": answer}[sys.argv[1]](*sys.argv[2:])
