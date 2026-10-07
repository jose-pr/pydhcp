"""The lifecycle of the listeners and of the roles built on them.

`serve_forever()` and `start()` bind and receive; `shutdown()` never blocks and
is safe from a handler; `wait_closed()` blocks until receiving has ended;
`close()` (`aclose()` on the asyncio classes) is both, then releases the
sockets, and is final. The library installs no signal handler. Every wait here
has a timeout with a second of margin and fails with a message.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import select
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
import typing as _ty

import pytest

from helpers import LOOPBACK_ALIAS_BINDABLE, build_request, wait_bound, wait_until
from driving import LOOPS, WAIT_SECONDS, threads_settle, wait_for
from pydhcp.capture import AsyncDHCPCapture, DHCPCapture
from pydhcp.client import AsyncDHCPClient, DHCPClient
from pydhcp.listener import AsyncDHCPListener, DHCPListener
from pydhcp.relay import AsyncDHCPRelay, DHCPRelay
from pydhcp.server import AsyncDHCPServer, DHCPServer

LOCAL = ("127.0.0.1", 0)

SYNC_CLASSES = [DHCPListener, DHCPServer, DHCPRelay, DHCPCapture, DHCPClient]
ASYNC_CLASSES = [
    AsyncDHCPListener,
    AsyncDHCPServer,
    AsyncDHCPRelay,
    AsyncDHCPCapture,
    AsyncDHCPClient,
]


def _make(cls: type, **kwargs: _ty.Any) -> _ty.Any:
    if cls in (DHCPRelay, AsyncDHCPRelay):
        kwargs["server_addresses"] = [("127.0.0.1", 6767)]
    return cls(listen=LOCAL, **kwargs)


@pytest.fixture
def uncaught(monkeypatch: pytest.MonkeyPatch) -> "list[BaseException]":
    """Exceptions that ended a thread without being handled."""
    caught: "list[BaseException]" = []
    monkeypatch.setattr(threading, "excepthook", lambda a: caught.append(a.exc_value))
    return caught


def _send(listener: _ty.Any) -> None:
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        address = listener.bound_addresses[0]
        sender.sendto(build_request().encode(), (str(address.ip), address.port))
    finally:
        sender.close()


# --- the synchronous classes ---


@pytest.mark.parametrize("cls", SYNC_CLASSES)
def test_close_on_a_running_listener_ends_the_receive_thread(
    cls: type, uncaught: "list[BaseException]"
) -> None:
    """On Windows the thread died with an uncaught `ValueError` or `OSError` as
    its sockets closed under `select()`; on Linux it never ended, `wait()` blocked
    and `start()` returned nothing."""
    threads_before = threading.active_count()
    listener = _make(cls)
    assert listener.start() is None
    wait_bound(listener)
    (thread,) = [t for t in threading.enumerate() if t.name == "pydhcp-listener"]
    sockets = list(listener._sockets)

    began = time.monotonic()
    listener.close()
    elapsed = time.monotonic() - began

    assert not thread.is_alive(), "close() returned with the receive thread alive"
    assert listener.wait_closed(WAIT_SECONDS) is True
    assert listener.bound_addresses == ()
    assert all(sock.fileno() == -1 for sock in sockets), "a socket is still open"
    assert uncaught == [], f"the receive thread died: {uncaught}"
    # The loop is woken, not left to notice on its next poll (a second).
    assert elapsed < 0.9, f"close() waited for a poll: {elapsed:.2f} s"
    threads_settle(threads_before)


@pytest.mark.parametrize("cls", SYNC_CLASSES)
def test_a_second_start_is_an_error(cls: type) -> None:
    threads_before = threading.active_count()
    listener = _make(cls)
    listener.start()
    try:
        wait_bound(listener)
        with pytest.raises(RuntimeError, match="already serving"):
            listener.start()
        with pytest.raises(RuntimeError, match="already serving"):
            listener.serve_forever()
        assert (
            sum(t.name == "pydhcp-listener" for t in threading.enumerate()) == 1
        ), "a second receive thread was started"
    finally:
        listener.close()
    threads_settle(threads_before)


@pytest.mark.parametrize("cls", SYNC_CLASSES)
def test_closed_is_final(cls: type) -> None:
    """`start()` after `close()` served again."""
    listener = _make(cls)
    listener.start()
    wait_bound(listener)
    listener.close()
    listener.close()  # repeatable

    for call in (listener.start, listener.serve_forever, listener.bind):
        with pytest.raises(RuntimeError, match="closed"):
            call()
    with pytest.raises(RuntimeError, match="closed"):
        with listener:
            pass  # pragma: no cover
    assert listener.bound_addresses == ()


@pytest.mark.parametrize("cls", SYNC_CLASSES)
def test_with_binds_and_does_not_serve(cls: type) -> None:
    threads_before = threading.active_count()
    with _make(cls) as listener:
        assert listener.bound_addresses
        assert threading.active_count() == threads_before
        assert listener._receive_thread is None
        sockets = list(listener._sockets)
    assert listener.bound_addresses == ()
    assert all(sock.fileno() == -1 for sock in sockets)
    with pytest.raises(RuntimeError, match="closed"):
        listener.start()


def test_serve_forever_blocks_until_shutdown_and_leaves_the_sockets_to_close() -> None:
    listener = _make(DHCPListener)
    listener.bind()
    returned = threading.Event()

    def serve() -> None:
        listener.serve_forever()
        returned.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        assert not returned.wait(0.3), "serve_forever() returned on its own"
        assert listener.wait_closed(0.1) is False
        listener.shutdown()
        assert returned.wait(WAIT_SECONDS), "shutdown() did not end serve_forever()"
        assert listener.wait_closed(WAIT_SECONDS) is True
        assert listener.bound_addresses, "serve_forever() released the sockets"
        # Shut down is not closed: it can serve again.
        again = threading.Thread(target=listener.serve_forever, daemon=True)
        again.start()
        wait_for(lambda: listener._serving, "a second serve_forever()")
        listener.shutdown()
        again.join(WAIT_SECONDS)
        assert not again.is_alive()
    finally:
        listener.close()
    assert listener.bound_addresses == ()


def test_shutdown_with_nothing_serving_does_nothing() -> None:
    listener = _make(DHCPListener)
    listener.shutdown()
    listener.start()
    wait_bound(listener)
    listener.close()
    listener.shutdown()


def test_wait_closed_on_the_receive_thread_would_wait_for_itself() -> None:
    seen: "list[BaseException]" = []

    class Waiting(DHCPListener):
        def handle(self, msg: _ty.Any, context: _ty.Any) -> None:
            try:
                self.wait_closed()
            except RuntimeError as exc:
                seen.append(exc)
            self.shutdown()

    with Waiting(listen=LOCAL) as listener:
        listener.start()
        _send(listener)
        wait_for(lambda: seen, "the handler's wait_closed()")
    assert "itself" in str(seen[0])


def test_close_from_a_handler_does_not_join_the_receive_thread(
    uncaught: "list[BaseException]",
) -> None:
    """`close()` on the receive thread shuts down and returns; the loop releases
    the sockets as it ends, and another thread's `wait_closed()` sees it."""
    sockets: "list[socket.socket]" = []
    returned = threading.Event()

    class Closing(DHCPListener):
        def handle(self, msg: _ty.Any, context: _ty.Any) -> None:
            sockets.extend(self._sockets)
            self.close()
            returned.set()

    listener = Closing(listen=LOCAL)
    listener.start()
    wait_bound(listener)
    try:
        _send(listener)
        assert returned.wait(WAIT_SECONDS), "close() from a handler blocked"
        assert listener.wait_closed(WAIT_SECONDS) is True
        assert listener.bound_addresses == ()
        assert sockets and all(sock.fileno() == -1 for sock in sockets)
        with pytest.raises(RuntimeError, match="closed"):
            listener.start()
    finally:
        listener.close()
    assert uncaught == []


def test_shutdown_from_a_handler_does_not_block_and_ends_the_loop() -> None:
    handled = threading.Event()

    class Stopping(DHCPListener):
        def handle(self, msg: _ty.Any, context: _ty.Any) -> None:
            self.shutdown()
            handled.set()

    with Stopping(listen=LOCAL) as listener:
        listener.start()
        _send(listener)
        assert handled.wait(WAIT_SECONDS)
        assert listener.wait_closed(WAIT_SECONDS) is True


@pytest.mark.skipif(
    not LOOPBACK_ALIAS_BINDABLE,
    reason="needs three loopback addresses; this host binds only 127.0.0.1",
)
def test_a_handler_that_shuts_down_is_not_called_again_in_the_same_turn() -> None:
    """Every socket already readable in the same `select()` was still serviced
    after the handler asked to stop: `capture --count 1` wrote 3 records on a
    wildcard bind whose three sockets went ready together. Three distinct local
    addresses are the point: one `select()` must report several sockets ready.
    """

    class Stopping(DHCPListener):
        handled = 0

        def handle(self, msg: _ty.Any, context: _ty.Any) -> None:
            self.handled += 1
            self.shutdown()

    listener = Stopping(listen=[("127.0.0.1", 0), ("127.0.0.2", 0), ("127.0.0.3", 0)])
    listener.bind()
    addresses = [(str(a.ip), a.port) for a in listener.bound_addresses]
    assert len(addresses) == 3
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = build_request().encode()
    for address in addresses:
        sender.sendto(payload, address)
    sender.close()
    # All three on the sockets before the loop starts, so one select() reports all
    # three. The listener's sockets are private; they are the only thing to ask.
    sockets = list(listener._sockets)
    wait_until(
        lambda: len(select.select(sockets, [], [], 0)[0]) == len(sockets),
        "all three datagrams to be queued",
    )

    # Serving begins with the loop; `shutdown()` needs it to have been claimed,
    # which `serve_forever()` does before it receives anything.
    thread = threading.Thread(target=listener.serve_forever, daemon=True)
    thread.start()
    thread.join(WAIT_SECONDS)
    assert not thread.is_alive()
    listener.close()
    assert listener.handled == 1, "kept draining the ready set after shutdown()"


def test_the_library_installs_no_signal_handler() -> None:
    before = signal.getsignal(signal.SIGINT)
    listener = _make(DHCPListener)
    listener.start()
    wait_bound(listener)
    assert signal.getsignal(signal.SIGINT) is before
    listener.close()
    assert signal.getsignal(signal.SIGINT) is before


def test_start_off_the_main_thread_works() -> None:
    listener = _make(DHCPListener)
    result: "dict[str, _ty.Any]" = {}

    def run() -> None:
        try:
            listener.start()
        except Exception as exc:  # pragma: no cover - the defect being pinned
            result["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    worker.join(WAIT_SECONDS)
    assert "error" not in result, result.get("error")
    wait_bound(listener)
    listener.close()


_FORGETFUL = """
import sys
sys.path.insert(0, {src!r})
from pydhcp.listener import DHCPListener

listener = DHCPListener(listen=("127.0.0.1", 0))
listener.start()
print("started", flush=True)
"""


def test_a_started_listener_does_not_keep_the_process_alive() -> None:
    """The receive loop never ends on its own, so a non-daemon thread running it
    is an interpreter that never exits (measured: still running after 8 s)."""
    source = textwrap.dedent(_FORGETFUL).format(src=str(_src_dir()))
    completed = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        # `TimeoutExpired` is the assertion; the bound is generous so that a
        # loaded machine is not what fails the suite.
        timeout=60,
    )
    assert "started" in completed.stdout
    assert completed.returncode == 0, completed.stderr


def _src_dir() -> "_ty.Any":
    import pathlib

    import pydhcp

    return pathlib.Path(pydhcp.__file__).resolve().parent.parent


# --- a start-up failure reaches the caller ---


def _held_port() -> "tuple[socket.socket, int]":
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", 0))
    return holder, holder.getsockname()[1]


def test_start_raises_the_bind_error_on_the_callers_thread(
    uncaught: "list[BaseException]",
) -> None:
    """The error comes out of `start()` itself, with nothing bound, nothing
    serving, `wait_closed()` returning, and the listener startable once the
    port is free."""
    from netimps import AddressInUseError

    holder, port = _held_port()
    listener = DHCPListener(listen=[("127.0.0.1", 0), ("127.0.0.1", port)])
    try:
        with pytest.raises(AddressInUseError):
            listener.start()
        assert listener.bound_addresses == ()
        assert listener.wait_closed(WAIT_SECONDS) is True
        assert uncaught == [], "the error was raised on the receive thread"

        holder.close()
        listener.start()
        wait_bound(listener)
        assert listener.bound_addresses
    finally:
        holder.close()
        listener.close()


def test_serve_forever_raises_the_bind_error_and_is_not_left_serving() -> None:
    holder, port = _held_port()
    listener = DHCPListener(listen=("127.0.0.1", port))
    try:
        with pytest.raises(OSError):
            listener.serve_forever()
        assert listener.wait_closed(WAIT_SECONDS) is True
        assert not listener._serving
    finally:
        holder.close()
        listener.close()


# --- the asyncio classes ---


def _run(loop_type: type, main: _ty.Callable[[], _ty.Any]) -> _ty.Any:
    """Run `main()` on a loop of `loop_type`, and check what it left behind."""
    threads_before = threading.active_count()
    loop = loop_type()
    try:
        result = loop.run_until_complete(asyncio.wait_for(main(), WAIT_SECONDS * 3))
        assert not asyncio.all_tasks(loop), "a task outlived the test"
    finally:
        loop.close()
    threads_settle(threads_before)
    return result


loop_types = pytest.mark.parametrize("loop_type", LOOPS, ids=lambda t: t.__name__)


@loop_types
@pytest.mark.parametrize("cls", ASYNC_CLASSES)
def test_async_with_binds_and_does_not_serve(cls: type, loop_type: type) -> None:
    async def main() -> None:
        async with _make(cls) as listener:
            assert listener.bound_addresses
            assert listener._tasks == []
            sockets = list(listener._sockets)
        assert listener.bound_addresses == ()
        assert all(sock.fileno() == -1 for sock in sockets)
        with pytest.raises(RuntimeError, match="closed"):
            await listener.start()

    _run(loop_type, main)


@loop_types
@pytest.mark.parametrize("cls", ASYNC_CLASSES)
def test_a_second_start_is_an_error_and_adds_no_task(
    cls: type, loop_type: type
) -> None:
    """A second `start()` added a second receive task per socket and stranded a
    `wait()` that was already pending."""

    async def main() -> None:
        listener = _make(cls)
        await listener.start()
        try:
            waiting = asyncio.ensure_future(listener.wait_closed())
            await asyncio.sleep(0)
            receiving = list(listener._tasks)
            assert len(receiving) == len(listener._sockets) == 1
            with pytest.raises(RuntimeError, match="already serving"):
                await listener.start()
            with pytest.raises(RuntimeError, match="already serving"):
                await listener.serve_forever()
            assert listener._tasks == receiving, "a receive task was added"
            assert not waiting.done()
            listener.shutdown()
            assert await asyncio.wait_for(waiting, WAIT_SECONDS) is True
            assert all(task.done() for task in receiving)
        finally:
            await listener.aclose()

    _run(loop_type, main)


@loop_types
@pytest.mark.parametrize("cls", ASYNC_CLASSES)
def test_async_closed_is_final(cls: type, loop_type: type) -> None:
    async def main() -> None:
        listener = _make(cls)
        await listener.start()
        await listener.aclose()
        await listener.aclose()  # repeatable
        assert listener.bound_addresses == ()
        for call in (listener.start, listener.serve_forever):
            with pytest.raises(RuntimeError, match="closed"):
                await call()
        with pytest.raises(RuntimeError, match="closed"):
            listener.bind()
        with pytest.raises(RuntimeError, match="closed"):
            async with listener:
                pass  # pragma: no cover

    _run(loop_type, main)


@loop_types
def test_aclose_from_another_task_ends_serve_forever_quietly(loop_type: type) -> None:
    async def main() -> None:
        listener = _make(AsyncDHCPListener)
        serving = asyncio.ensure_future(listener.serve_forever())
        await asyncio.sleep(0)  # the task runs up to the wait for `shutdown()`
        assert not serving.done()
        sockets = list(listener._sockets)
        await listener.aclose()
        assert await asyncio.wait_for(serving, WAIT_SECONDS) is None
        assert all(sock.fileno() == -1 for sock in sockets)

    _run(loop_type, main)


@loop_types
def test_serve_forever_leaves_the_sockets_to_aclose(loop_type: type) -> None:
    async def main() -> None:
        listener = _make(AsyncDHCPListener)
        serving = asyncio.ensure_future(listener.serve_forever())
        await asyncio.sleep(0)  # the task runs up to the wait for `shutdown()`
        listener.shutdown()
        await asyncio.wait_for(serving, WAIT_SECONDS)
        assert listener.bound_addresses
        assert await listener.wait_closed(0.1) is True
        await listener.aclose()
        assert listener.bound_addresses == ()

    _run(loop_type, main)


@loop_types
def test_wait_closed_times_out_while_serving(loop_type: type) -> None:
    async def main() -> None:
        listener = _make(AsyncDHCPListener)
        await listener.start()
        try:
            assert await listener.wait_closed(0.05) is False
        finally:
            await listener.aclose()

    _run(loop_type, main)


@loop_types
def test_shutdown_from_a_handler_thread_wakes_the_loop(loop_type: type) -> None:
    """`Event.set` queues a callback without waking a selector loop from another
    thread; the elapsed time is asserted, because `wait_for`'s own timer would
    wake a hung loop at its deadline and a bare completion check would pass."""
    handled = threading.Event()

    class Stopping(AsyncDHCPListener):
        def handle(self, msg: _ty.Any, context: _ty.Any) -> None:
            handled.set()
            self.shutdown()

    async def main() -> float:
        listener = _make(Stopping)
        await listener.start()
        try:
            _send(listener)
            began = time.monotonic()
            assert await listener.wait_closed(WAIT_SECONDS)
            return time.monotonic() - began
        finally:
            await listener.aclose()

    elapsed = _run(loop_type, main)
    assert handled.is_set()
    assert elapsed < 1.0, f"the loop did not wake for shutdown(): {elapsed:.2f} s"


@loop_types
def test_start_raises_the_bind_error_and_leaves_nothing_running(
    loop_type: type,
) -> None:
    holder, port = _held_port()

    async def main() -> None:
        listener = AsyncDHCPListener(listen=[("127.0.0.1", 0), ("127.0.0.1", port)])
        try:
            with pytest.raises(OSError):
                await listener.start()
            assert listener.bound_addresses == ()
            assert listener._tasks == [] and listener._worker is None
            assert await listener.wait_closed(0.1) is True
            holder.close()
            await listener.start()
            assert listener.bound_addresses
        finally:
            await listener.aclose()

    try:
        _run(loop_type, main)
    finally:
        holder.close()


def test_an_async_class_has_no_blocking_vocabulary() -> None:
    for cls in ASYNC_CLASSES:
        for name in ("listen", "stop", "wait", "close", "__enter__", "__exit__"):
            assert not hasattr(cls, name), f"{cls.__name__}.{name}"
        for name in ("start", "serve_forever", "wait_closed", "aclose", "__aenter__"):
            assert inspect.iscoroutinefunction(getattr(cls, name)), name
        assert not inspect.iscoroutinefunction(cls.shutdown), "shutdown() is sync"
    for cls in SYNC_CLASSES:
        for name in ("listen", "stop", "wait", "aclose", "__aenter__"):
            assert not hasattr(cls, name), f"{cls.__name__}.{name}"
        for name in ("start", "serve_forever", "shutdown", "wait_closed", "close"):
            assert callable(getattr(cls, name))


def test_an_interrupt_after_the_claim_and_before_the_loop_leaves_nothing_to_wait_for(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Ctrl-C can arrive at any bytecode of `serve_forever()`, claim included.

    The loop is replaced by a step that raises `KeyboardInterrupt` the moment
    the claim has been made. `close()` must then return at once and quietly: a
    claim nobody serves under must not leave the listener looking busy.
    """
    listener = DHCPListener(listen=LOCAL)

    def interrupted() -> None:
        raise KeyboardInterrupt

    # The step between the claim and the loop is private; this is its only seam.
    monkeypatch.setattr(listener, "_serve", interrupted)
    with pytest.raises(KeyboardInterrupt):
        listener.serve_forever()

    began = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        listener.close()

    assert time.monotonic() - began < 2.0, "close() waited for a loop that never ran"
    assert "did not end within" not in caplog.text
    assert listener.bound_addresses == ()


def test_an_interrupt_while_the_receive_thread_is_made_leaves_nothing_to_wait_for(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The same window in `start()`: the claim is made, the thread never is."""
    listener = DHCPListener(listen=LOCAL)

    def interrupted(*_args: _ty.Any, **_kwargs: _ty.Any) -> _ty.NoReturn:
        raise KeyboardInterrupt

    with monkeypatch.context() as patched:
        patched.setattr(threading, "Thread", interrupted)
        with pytest.raises(KeyboardInterrupt):
            listener.start()

    began = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        listener.close()

    assert time.monotonic() - began < 2.0, "close() waited for a loop that never ran"
    assert "did not end within" not in caplog.text
    assert listener.bound_addresses == ()
