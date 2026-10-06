"""A relay on the wildcard at port 67, adding option 82.

Run: python relay.py <server address> [--async] [--status PATH]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import signal
import threading

from pydhcp import AsyncDHCPRelay, DHCPRelay

parser = argparse.ArgumentParser()
parser.add_argument("server")
parser.add_argument("--async", dest="use_async", action="store_true")
parser.add_argument("--status")
args = parser.parse_args()

options = dict(
    listen=("*", 67),
    server_addresses=[args.server],
    insert_relay_agent_info=True,
    circuit_id=b"lab-circuit",
    remote_id=b"lab-relay",
)


def report(relay) -> None:
    if args.status:
        pathlib.Path(args.status).write_text(
            json.dumps(relay.metrics.snapshot()), encoding="utf-8"
        )


async def run_async() -> None:
    relay = AsyncDHCPRelay(**options)
    done = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, done.set)
    await relay.start()
    print("relaying", flush=True)
    await done.wait()
    stopped = relay.stop()
    if stopped is not None:
        await stopped
    report(relay)


def run_sync() -> None:
    relay = DHCPRelay(**options)
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    relay.start()
    print("relaying", flush=True)
    done.wait()
    relay.stop()
    relay.close()
    report(relay)


if args.use_async:
    asyncio.run(run_async())
else:
    run_sync()
