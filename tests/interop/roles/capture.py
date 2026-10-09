"""An asynchronous capture on the wildcard at port 67.

Run: python capture.py <output.jsonl>

One JSON object per recorded datagram, written as it arrives: the message
type, the transaction, the sender, the destination the capture reports and the
number of the interface it arrived on.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import signal
import sys

from pydhcp.capture import DHCPLayer, asniff_dhcp

out = open(sys.argv[1], "w", encoding="utf-8", buffering=1, newline="\n")


async def record(frames) -> None:
    async for frame in frames:
        layer = frame.layer(DHCPLayer)
        datagram = frame.datagram()
        if layer is None or datagram is None:
            continue
        out.write(
            json.dumps(
                {
                    "type": layer.message_type,
                    "xid": f"{layer.xid:08X}",
                    "source": datagram.source[0],
                    "destination": datagram.destination[0],
                    "interface": frame.frame.interface,
                }
            )
            + "\n"
        )


async def main() -> None:
    frames = asniff_dhcp(":67")
    done = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, done.set)
    reader = asyncio.ensure_future(record(frames))
    print("capturing", flush=True)
    await done.wait()
    reader.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await reader
    await frames.aclose()


asyncio.run(main())
