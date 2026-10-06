"""A reply sent while the socket's send buffer is full.

Run: python full_buffer.py <reply-destination> [--wait SECONDS]

An asynchronous listener on the wildcard at port 67, whose sockets are
non-blocking and whose handler answers from a worker thread. On the first
request the handler fills the socket's send buffer with the smallest amount that
does it (datagrams to an on-link address nobody answers ARP for, which the kernel
holds, still charged to the socket, until it gives up on the address), then sends
one reply to <reply-destination> port 68 through the request's transport, and
prints what happened to it.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import signal
import socket
import time

from pydhcp import AsyncDHCPListener

parser = argparse.ArgumentParser()
parser.add_argument("destination")
parser.add_argument("--wait", type=float, default=20.0)
args = parser.parse_args()

REPLY = b"reply-sent-while-the-send-buffer-was-full"


class Listener(AsyncDHCPListener):
    answered = False

    def handle(self, msg, context) -> None:
        if self.answered:
            return
        self.answered = True
        sock = context.transport.socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        filled = 0
        try:
            while filled < 10000:
                sock.sendto(b"f" * 64, ("10.99.0.77", 9))
                filled += 1
        except BlockingIOError:
            print(f"full after {filled} datagrams", flush=True)
        else:
            print("the send buffer did not fill", flush=True)
            return
        context.transport.SEND_WAIT_SECONDS = args.wait
        began = time.monotonic()
        try:
            context.transport.send(
                REPLY,
                ipaddress.IPv4Address(args.destination),
                port=68,
                client_mac=msg.chaddr,
            )
        except OSError as error:
            print(f"lost: {type(error).__name__}: {error}", flush=True)
        else:
            print(f"sent after {time.monotonic() - began:.1f} s", flush=True)


async def main() -> None:
    listener = Listener(listen=("*", 67))
    done = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, done.set)
    await listener.start()
    print("serving", flush=True)
    await done.wait()
    await listener.aclose()


asyncio.run(main())
