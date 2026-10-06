"""Run a role on its own driver, and measure what it leaves behind.

Shared by the tests that put one datagram through the thread-based and the
asyncio driver of the same role. Every wait has a timeout with margin and fails
with a message; thread counts are taken before and after, and on the asyncio
side so are the tasks, on every loop type the platform has.
"""

from __future__ import annotations

import asyncio
import inspect
import sys
import threading
import time
import typing as _ty

import pytest

from conftest import running

WAIT_SECONDS = 3.0

if sys.platform == "win32":
    LOOPS = [asyncio.ProactorEventLoop, asyncio.SelectorEventLoop]  # type: ignore[attr-defined]
else:
    LOOPS = [asyncio.SelectorEventLoop]


def driver_params(sync_class: type, async_class: type) -> "list[_ty.Any]":
    """`pytest.param`s for the sync driver and for the async one on each loop type."""
    return [
        pytest.param(sync_class, None, id="sync"),
        *[
            pytest.param(async_class, loop, id=f"async-{loop.__name__}")
            for loop in LOOPS
        ],
    ]


def threads_settle(before: int) -> None:
    deadline = time.monotonic() + WAIT_SECONDS
    while threading.active_count() > before and time.monotonic() < deadline:
        time.sleep(0.01)
    assert threading.active_count() <= before, (
        f"{threading.active_count() - before} thread(s) outlived the role: "
        f"{[t.name for t in threading.enumerate()]}"
    )


def wait_for(predicate: _ty.Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out after {WAIT_SECONDS} s waiting for {what}")


def serve(
    server: _ty.Any,
    exercise: _ty.Callable[[int], _ty.Any],
    loop_type: _ty.Optional[type] = None,
) -> _ty.Any:
    """Run `exercise(port)` against `server` on its own driver, then check the leak.

    `exercise` is blocking code (a client socket); on the asyncio driver it runs
    in an executor so the loop keeps serving.
    """
    threads_before = threading.active_count()
    if inspect.iscoroutinefunction(server.start):

        async def main() -> _ty.Any:
            tasks_before = len(asyncio.all_tasks())
            await server.start()
            try:
                port = server.bound_addresses[0].port
                return await asyncio.get_event_loop().run_in_executor(
                    None, exercise, port
                )
            finally:
                server.stop()
                await asyncio.wait_for(server.wait(), WAIT_SECONDS)
                await asyncio.sleep(0)
                assert len(asyncio.all_tasks()) <= tasks_before + 1, "a task leaked"

        loop = (loop_type or asyncio.SelectorEventLoop)()
        try:
            result = loop.run_until_complete(main())
        finally:
            loop.close()
    else:
        with running(server) as started:
            result = exercise(started.bound_addresses[0].port)
    threads_settle(threads_before)
    return result
