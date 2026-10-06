"""Which listeners hear a broadcast: an address-bound one, or the wildcard?

Run: python addrbound_listen.py <address> <base port> <seconds>

Three listeners, each built through the public constructor, on three ports:
  base+0  listen=(address, port)          bound to one address
  base+1  listen=("0.0.0.0", port), per_interface=True
  base+2  listen=("0.0.0.0", port)        the wildcard
`emit.py kinds` sends three DISCOVERs to each port by three routes; the kind is
in the xid's high octet. Prints one JSON object of how many each listener heard.
"""

from __future__ import annotations

import collections
import json
import sys
import time

from pydhcp import DHCPListener

address, base, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
KINDS = {0xB1: "limited_broadcast", 0xB2: "subnet_broadcast", 0xC0: "unicast"}


class Counting(DHCPListener):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.seen: "collections.Counter[str]" = collections.Counter()

    def handle(self, msg, context) -> None:
        self.seen[KINDS.get(msg.xid >> 24, hex(msg.xid))] += 1


listeners = {
    "address": Counting(listen=(address, base), poll_interval=0.05),
    "per_interface": Counting(
        listen=("0.0.0.0", base + 1), poll_interval=0.05, per_interface=True
    ),
    "wildcard": Counting(listen=("0.0.0.0", base + 2), poll_interval=0.05),
}
for listener in listeners.values():
    listener.start()
print("ready", flush=True)
time.sleep(seconds)
for name, listener in listeners.items():
    listener.close()
print(json.dumps({name: dict(l.seen) for name, l in listeners.items()}))
