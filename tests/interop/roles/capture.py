"""An asynchronous capture on the wildcard at port 67.

Run: python capture.py <output.jsonl>

One JSON object per recorded datagram, written as it arrives: the message
type, the transaction, the sender, and the destination the capture reports.
"""

from __future__ import annotations

import asyncio
import json
import signal
import sys

from pydhcp import AsyncDHCPCapture

out = open(sys.argv[1], "w", encoding="utf-8", buffering=1, newline="\n")


def sink(event) -> None:
    out.write(
        json.dumps(
            {
                "type": event.message_type,
                "xid": event.xid,
                "source": str(event.source.ip),
                "destination": str(event.destination.ip),
                "interface": event.context.interface.name,
            }
        )
        + "\n"
    )


async def main() -> None:
    capture = AsyncDHCPCapture(listen=("*", 67), sink=sink)
    done = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, done.set)
    await capture.start()
    print("capturing", flush=True)
    await done.wait()
    await capture.aclose()


asyncio.run(main())
