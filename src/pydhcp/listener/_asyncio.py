"""The asyncio listener: the same receive path, on an event loop."""

from __future__ import annotations

import asyncio as _asyncio
import concurrent.futures as _futures
import logging as _logging
import socket as _socket
import threading as _thread
import time as _time
import typing as _ty

import netimps as _netimps

from ._core import _ListenerCore
from ._receive import _Arrival, _TruncatedDatagram, _arrival
from ._spec import ListenLike

LOGGER = _logging.getLogger(__name__)


class AsyncDHCPListener(_ListenerCore):
    """The listener on an event loop: the receive path of `DHCPListener`, one task per socket.

    `handle()` runs on a single worker thread, in arrival order, so it may block;
    at most `max_queued` datagrams wait for it and the next is dropped and counted.
    Drive it with `await serve_forever()` or `await start()`, then `shutdown()`,
    `await wait_closed()` and `await aclose()`; `async with` binds on entry.
    """

    _BIND_LABEL = "async"

    #: Datagrams that may wait for, or be in, the handler at once when
    #: `max_queued` is not given: about 3 MiB of queued 300-octet
    #: datagrams. The datagram that finds the backlog at the bound is
    #: dropped.
    MAX_QUEUED_DATAGRAMS: int = 1024

    #: Whether `handle()` runs on the one worker thread (a handler may block) or
    #: on the event loop, where it must not. A role whose handler only moves a
    #: reply into a loop-owned queue sets this to false and has no worker thread.
    _HANDLE_ON_WORKER: bool = True

    #: Seconds between reports of dropped datagrams. A flood reaches the
    #: bound once per datagram, so logging each hands the sender the log.
    BACKLOG_LOG_INTERVAL_SECONDS: float = 60.0

    def __init__(
        self,
        listen: ListenLike = None,
        *,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
        reuse_address: _ty.Optional[bool] = None,
        receive_buffer_size: _ty.Optional[int] = None,
        max_queued: _ty.Optional[int] = None,
    ) -> None:
        _ListenerCore.__init__(
            self,
            listen=listen,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
            reuse_address=reuse_address,
            receive_buffer_size=receive_buffer_size,
        )
        if max_queued is None:
            max_queued = self.MAX_QUEUED_DATAGRAMS
        if isinstance(max_queued, bool) or not isinstance(max_queued, int):
            raise ValueError(
                f"max_queued must be a positive integer, not {max_queued!r}"
            )
        if max_queued < 1:
            raise ValueError(
                f"max_queued must be a positive integer, not {max_queued!r}"
            )
        self._max_queued = max_queued
        #: Datagrams handed to the worker and not yet finished, the one
        #: running included; guarded, as the worker thread finishes them.
        self._pending = 0
        self._pending_lock = _thread.Lock()
        self._last_backlog_report = float("-inf")
        #: Set while the worker is aborted: a queued datagram is discarded.
        self._closing = False
        #: One receive task per socket; see `_receive`.
        self._tasks: "list[_asyncio.Task[None]]" = []
        self._loop: _ty.Optional[_asyncio.AbstractEventLoop] = None
        self._stopped: _ty.Optional[_asyncio.Event] = None
        self._serve_ended: "_ty.Optional[_asyncio.Future[None]]" = None
        self._serving = False
        self._serving_task: "_ty.Optional[_asyncio.Task[None]]" = None
        self._close_task: "_ty.Optional[_asyncio.Future[None]]" = None
        self._worker: _ty.Optional[_futures.ThreadPoolExecutor] = None

    async def _receive(
        self, sock: _socket.socket, endpoint: _netimps.UDPEndpoint
    ) -> None:
        """Receive from one socket until cancelled, on the event loop.

        Only the read happens here; the handler runs on the worker. netimps'
        `arecv` keeps packet info on every loop type, Windows' default proactor
        included -- which `add_reader` (absent there) and a `DatagramTransport`
        (no slot for control messages) cannot, so every loop type learns which
        interface a broadcast arrived on.

        An `arecv` loop rather than `datagrams()`: an async iterator ends at its
        first exception, and a server has to survive a datagram it cannot read.
        """
        while True:
            try:
                arrival = _arrival(
                    await endpoint.arecv(self._max_packet_size + 1),
                    self._max_packet_size,
                    self._control_truncated,
                )
            except (BlockingIOError, InterruptedError):  # spurious readability
                continue
            except RuntimeError:
                # netimps ends a wait on a closed endpoint this way. Closing is
                # how a socket that is no longer listened on is retired.
                if sock.fileno() == -1:
                    return
                raise
            except _TruncatedDatagram as e:
                self._note_truncated(e)
                continue
            except OSError as e:
                if sock.fileno() == -1:
                    return  # closed underneath us; nothing more will arrive
                self._note_receive_error("an async socket", e)
                continue
            if self._admits(arrival, sock):
                self._dispatch_received(arrival, sock)

    def _dispatch_received(self, arrival: _Arrival, sock: _socket.socket) -> None:
        """Run one datagram's handling off the event loop.

        Exactly one worker thread, so handlers still run one at a time and in
        arrival order. That matters: the lease backends are not thread-safe, so a
        pool here would trade a blocked event loop for a data race.

        At most `max_queued` datagrams wait for or are in the handler. The one
        that finds the backlog full is dropped, counted in
        `metrics.packets_dropped_backlog` and reported at most once per
        `BACKLOG_LOG_INTERVAL_SECONDS`.
        """
        worker = self._worker
        if worker is None:  # on the loop: not started, or `_HANDLE_ON_WORKER` is off
            self._handle_datagram(arrival, sock)
            return
        with self._pending_lock:
            full = self._pending >= self._max_queued
            if not full:
                self._pending += 1
        if full:
            self.metrics.packets_dropped_backlog += 1
            self._report_backlog()
            return
        try:
            future = worker.submit(self._handle_datagram, arrival, sock)
        except RuntimeError:  # the worker was shut down since it was read
            self._finished()
            return
        future.add_done_callback(self._report_worker_result)

    def _finished(self) -> None:
        with self._pending_lock:
            self._pending -= 1

    def _report_backlog(self) -> None:
        now = _time.monotonic()
        if now - self._last_backlog_report < self.BACKLOG_LOG_INTERVAL_SECONDS:
            return
        self._last_backlog_report = now
        LOGGER.warning(
            f"The handler backlog is full ({self._max_queued} datagrams, max_queued): "
            f"newly arriving datagrams are dropped. "
            f"{self.metrics.packets_dropped_backlog} dropped so far."
        )

    def _report_worker_result(self, future: "_futures.Future[None]") -> None:
        self._finished()
        if future.cancelled():  # discarded at shutdown, still queued
            self.metrics.packets_dropped_backlog += 1
            return
        error = future.exception()
        if error is not None:  # pragma: no cover - _handle_datagram catches
            LOGGER.error(
                f"Unhandled error in async handler: "
                f"{error.__class__.__name__} | {error}"
            )

    def _handle_datagram(self, arrival: _Arrival, sock: _socket.socket) -> None:
        if self._closing:  # shut down after this was queued
            self.metrics.packets_dropped_backlog += 1
            return
        self._dispatch_arrival(arrival, sock)

    # -- lifecycle ---------------------------------------------------------

    def _claim(self) -> "_asyncio.AbstractEventLoop":
        """Bind, then mark this task as the one that serves."""
        self.bind()
        if self._serving:
            raise RuntimeError(f"{type(self).__name__} is already serving")
        loop = _asyncio.get_running_loop()
        if self._worker is None and self._HANDLE_ON_WORKER:
            self._worker = _futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="pydhcp-async-handler"
            )
        self._loop = loop
        self._closing = False
        self._stopped = _asyncio.Event()
        self._serve_ended = loop.create_future()
        self._serving = True
        return loop

    async def start(self) -> None:
        """Bind, then receive in background tasks, and return once receiving.

        Raises what `bind()` raised, and `RuntimeError` when already serving or
        closed; nothing is left open or running in either case.
        """
        loop = self._claim()
        try:
            self._begin_receiving(loop)
        except BaseException:
            self._abort_claim()
            raise
        self._serving_task = loop.create_task(self._serve())

    async def serve_forever(self) -> None:
        """Bind, then receive in the calling task until `shutdown()`.

        Raises what `bind()` raised, and `RuntimeError` when already serving or
        closed. The sockets stay open on return: `aclose()` releases them.
        """
        loop = self._claim()
        try:
            self._begin_receiving(loop)
        except BaseException:
            self._abort_claim()
            raise
        await self._serve()

    def _begin_receiving(self, loop: "_asyncio.AbstractEventLoop") -> None:
        for sock in self._sockets:
            sock.setblocking(False)
            task = loop.create_task(self._receive(sock, self._endpoints[sock]))
            task.add_done_callback(self._receive_ended)
            self._tasks.append(task)

    def _abort_claim(self) -> None:
        for task in self._tasks:
            task.cancel()
        self._tasks = []
        worker, self._worker = self._worker, None
        if worker is not None:
            worker.shutdown(wait=False, cancel_futures=True)
        self._release_serving()

    def _receive_ended(self, task: "_asyncio.Task[None]") -> None:
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            LOGGER.error(
                f"A receive task ended on an unexpected error: "
                f"{error.__class__.__name__} | {error}",
                exc_info=error,
            )

    async def _serve(self) -> None:
        stopped = self._stopped
        assert stopped is not None
        try:
            await stopped.wait()
        finally:
            await self._end_receiving()

    async def _end_receiving(self) -> None:
        """Cancel the receive tasks, abort the worker and let `wait_closed()` return.

        The tasks end *before* the sockets are closed, the order netimps
        documents as a clean shutdown: a cancelled `arecv` unregisters its
        reader, so the loop is not left polling a socket about to close.
        Datagrams still queued for the handler are discarded and counted in
        `metrics.packets_dropped_backlog`; the handler already running
        finishes, and nothing waits for it, since a handler in flight may be
        doing exactly the blocking work the worker exists to keep off the loop.
        """
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            task.cancel()
        worker, self._worker = self._worker, None
        if worker is not None:
            self._closing = True
            discarded_before = self.metrics.packets_dropped_backlog
            worker.shutdown(wait=False, cancel_futures=True)
            discarded = self.metrics.packets_dropped_backlog - discarded_before
            if discarded:
                LOGGER.info(
                    f"Stopped with {discarded} datagrams still queued; "
                    f"discarded {discarded} unhandled."
                )
        try:
            await _asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self._release_serving()

    def _release_serving(self) -> None:
        ended = self._serve_ended
        self._serving = False
        self._loop = None
        self._stopped = None
        self._serve_ended = None
        if self._closed:
            self._close_sockets()
        if ended is not None and not ended.done():
            ended.set_result(None)

    def shutdown(self) -> None:
        """Ask serving to end. Returns at once, from any thread and from a handler.

        Nothing is closed here: the receive tasks end on the event loop's next
        turn and `aclose()` releases the sockets. A no-op when nothing serves.
        """
        loop, stopped = self._loop, self._stopped
        if not self._serving or loop is None or stopped is None:
            return
        try:
            # `Event.set` finishes through `loop.call_soon`, which queues a
            # callback without waking a selector loop from another thread.
            loop.call_soon_threadsafe(stopped.set)
        except RuntimeError:  # pragma: no cover - the loop closed since
            pass

    async def wait_closed(self, timeout: _ty.Optional[float] = None) -> bool:
        """Wait until serving has ended; `False` if `timeout` seconds passed first."""
        ended = self._serve_ended
        if ended is not None and not ended.done():
            try:
                await _asyncio.wait_for(_asyncio.shield(ended), timeout)
            except _asyncio.TimeoutError:
                return False
        task, self._serving_task = self._serving_task, None
        if task is not None and not task.done():
            await task
        return True

    async def aclose(self) -> None:
        """Shut down, wait for serving to end, then release every socket. Final and repeatable."""
        if self._close_task is None:
            self._close_task = _asyncio.ensure_future(self._close())
        await _asyncio.shield(self._close_task)

    async def _close(self) -> None:
        self._closed = True
        self.shutdown()
        try:
            await self.wait_closed()
        finally:
            self._close_sockets()

    async def __aenter__(self) -> "AsyncDHCPListener":
        self.bind()
        return self

    async def __aexit__(self, *_exc: _ty.Any) -> None:
        await self.aclose()
