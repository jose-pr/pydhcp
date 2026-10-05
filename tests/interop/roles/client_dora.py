"""pydhcp's own client running a full exchange against whatever answers.

Run: python client_dora.py [--chaddr HEX]

Prints one JSON object: the address the ACK gave and the options it carried,
or null when nothing came back. The interface needs an address for the client
to send from, since `DhcpClient` configures nothing itself.
"""

from __future__ import annotations

import argparse
import json

from pydhcp import DhcpClient
from pydhcp.options import DhcpOptionCode

parser = argparse.ArgumentParser()
parser.add_argument("--chaddr", default="020000000077")
args = parser.parse_args()

client = DhcpClient(listen=("0.0.0.0", 68))
client.start()
try:
    ack = client.dora(bytes.fromhex(args.chaddr), timeout=1.0, retries=3)
finally:
    client.stop()
    client.close()

if ack is None:
    print(json.dumps(None))
else:
    options = {}
    for code in (DhcpOptionCode.ROUTER, DhcpOptionCode.DNS, DhcpOptionCode.SUBNET_MASK):
        value = ack.options.get(code)
        options[code.name] = None if value is None else str(value)
    print(json.dumps({"yiaddr": str(ack.yiaddr), "options": options}))
