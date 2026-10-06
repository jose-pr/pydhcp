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

from .. import constants as _const, network as _net
from ..metrics import DHCPMetrics
from ..packet import enums as _enum
from ..packet.message import DHCPMessage
from .binding import _bind_sockets, _close_socket
from .receive import (
    DHCPRequestContext,
    _TruncatedDatagram,
    _arrival,
    _context_for,
    _pktinfo_supported,
)
from .spec import ListenSpec, _parselisteners

LOGGER = _logging.getLogger(__name__)


class AsyncDHCPListener:
    DEFAULT_PORTS: _ty.Sequence[int] = tuple(p.value for p in _enum.DHCPPort)

    #: As on `DHCPListener`; see `_bind_sockets`.
    REUSE_ADDRESS: bool = False

    #: Receive buffer to ask the OS for on every listening socket, in octets;
    #: 0 keeps the OS default. 1 MiB holds about 3500 typical 300-octet DHCP
    #: datagrams, against about 220 in Windows' 64 KiB default -- a segment
    #: powering up sends its DISCOVERs together. The kernel may grant less
    #: (Linux caps at net.core.rmem_max); a shortfall is logged at INFO.
    RECEIVE_BUFFER_SIZE: int = 1 << 20

    #: Datagrams that may wait for, or be in, the handler at once when
    #: `max_queued` is not given: about 3 MiB of queued 300-octet
    #: datagrams. The datagram that finds the backlog at the bound is
    #: dropped.
    MAX_QUEUED_DATAGRAMS: int = 1024

    #: Seconds between reports of dropped datagrams. A flood reaches the
    #: bound once per datagram, so logging each hands the sender the log.
    BACKLOG_LOG_INTERVAL_SECONDS: float = 60.0

    def __init__(
        self,
        listen: ListenSpec = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
        max_queued: _ty.Optional[int] = None,
    ) -> None:
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
        self._closing = False
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._pktinfo = _pktinfo_supported(listen, per_interface)
        self._listen = _parselisteners(
            listen, self.DEFAULT_PORTS, expand_wildcard=not self._pktinfo
        )
        self._per_interface = per_interface
        self._sockets: list[_socket.socket] = []
        #: As on `DHCPListener`.
        self._endpoints: dict[_socket.socket, _netimps.UDPEndpoint] = {}
        #: One receive task per socket; see `_receive`.
        self._tasks: "list[_asyncio.Task[None]]" = []
        self._loop: _ty.Optional[_asyncio.AbstractEventLoop] = None
        self._stopped: _ty.Optional[_asyncio.Event] = None
        self._worker: _ty.Optional[_futures.ThreadPoolExecutor] = None
        self.metrics = DHCPMetrics()
        #: As on `DHCPListener`.
        self.packets_dropped_truncated = 0
        self.packets_dropped_error = 0

    async def _receive(
        self, sock: _socket.socket, endpoint: _netimps.UDPEndpoint
    ) -> None:
        """Receive from one socket until cancelled, on the event loop.

        Only the read happens here; the handler runs on the worker. netimps'
        `arecv` keeps packet info on every loop type, Windows' default proactor
        included -- which `add_reader` (absent there) and a `DatagramTransport`
        (no slot for control messages) could not, so that loop used to run
        without knowing which interface a broadcast arrived on.

        An `arecv` loop rather than `datagrams()`: an async iterator ends at its
        first exception, and a server has to survive a datagram it cannot read.
        """
        while True:
            try:
                arrival = _arrival(
                    await endpoint.arecv(self._max_packet_size + 1),
                    self._max_packet_size,
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
                self.metrics.packets_dropped_truncated += 1
                LOGGER.warning(f"Dropping a truncated datagram: {e}")
                continue
            except OSError as e:
                if sock.fileno() == -1:
                    return  # closed underneath us; nothing more will arrive
                self.metrics.packets_dropped_error += 1
                LOGGER.error(
                    f"Encounter error reading async datagram: "
                    f"{e.__class__.__name__} | {e}",
                    exc_info=True,
                )
                continue
            data, client, ifindex, local_ip = arrival
            self._dispatch_received(data, client, sock, ifindex, local_ip)

    def _dispatch_received(
        self,
        data: bytes,
        client: _net.SocketAddress,
        sock: _socket.socket,
        ifindex: "_ty.Optional[int]" = None,
        local_ip: "_ty.Optional[_net.IPv4]" = None,
    ) -> None:
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
        if worker is None:  # not started through start(); keep working anyway
            self._handle_datagram(data, client, sock, ifindex, local_ip)
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
            future = worker.submit(
                self._handle_datagram, data, client, sock, ifindex, local_ip
            )
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
        if future.cancelled():  # discarded at stop(), still queued
            self.metrics.packets_dropped_backlog += 1
            return
        error = future.exception()
        if error is not None:  # pragma: no cover - _handle_datagram catches
            LOGGER.error(
                f"Unhandled error in async handler: "
                f"{error.__class__.__name__} | {error}"
            )

    def _handle_datagram(
        self,
        data: bytes,
        client: _net.SocketAddress,
        sock: _socket.socket,
        ifindex: "_ty.Optional[int]" = None,
        local_ip: "_ty.Optional[_net.IPv4]" = None,
    ) -> None:
        if self._closing:  # stop() was called after this was queued
            self.metrics.packets_dropped_backlog += 1
            return
        # Split for the same reason as `DHCPListener._receive_one`: a packet the
        # peer malformed and a bug in a `handle()` override are different
        # events, and only the second one's traceback is worth keeping.
        try:
            msg = DHCPMessage.decode(memoryview(data))
        except Exception as e:
            self.metrics.packets_dropped_error += 1
            LOGGER.warning(
                f"Discarding an undecodable {len(data)}-octet datagram from "
                f"{client}: {e.__class__.__name__} | {e}"
            )
            return
        try:
            self.metrics.packets_received += 1
            if LOGGER.isEnabledFor(_logging.DEBUG):
                msg.log(client, _net.SocketAddress(sock), _logging.DEBUG)
            context = _context_for(
                sock, client, msg.chaddr, ifindex, local_ip, self._endpoints.get(sock)
            )
            self.handle(msg, context)
        except Exception as e:
            self.metrics.packets_dropped_error += 1
            LOGGER.error(
                f"Encounter error handling async request from {client} : "
                f"{e.__class__.__name__} | {e}",
                exc_info=True,
            )

    @property
    def bound_addresses(self) -> "tuple[_net.SocketAddress, ...]":
        """The addresses this listener is currently bound to.

        Empty before `bind()` and after `stop()` has actually run -- which is
        not necessarily when `stop()` returns; see the note on `stop()` about
        being called from the handler worker. Asking the socket rather than
        repeating `self._listen` is the point: binding port 0 gives an ephemeral
        port that only the socket knows, which is how a test or a tool discovers
        where to send. Without this the only way to find out was to reach into
        the private socket list, which the tests did in twenty-one places.
        """
        addresses = []
        for sock in self._sockets:
            try:
                addresses.append(_net.SocketAddress(sock))
            except OSError:  # pragma: no cover - socket closed underneath us
                continue
        return tuple(addresses)

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        pass

    def bind(self) -> None:
        _bind_sockets(
            self._listen,
            self._sockets,
            self._endpoints,
            self._pktinfo,
            label="async",
            reuse_address=self.REUSE_ADDRESS,
            receive_buffer=self.RECEIVE_BUFFER_SIZE,
        )

    async def wait(self) -> None:
        """Block until `stop()` is called.

        The sync counterpart is `DHCPListener.wait()`, and reaching *that* one
        through the inherited contract raised `AttributeError: _cancellation_token`
        -- the async constructor never sets one. A coroutine is the honest shape
        here: waiting synchronously inside the loop that has to run the handlers
        would deadlock.
        """
        stopped = self._stopped
        if stopped is None:  # never started, or already stopped
            return
        await stopped.wait()

    def listen(self) -> None:
        """Not available: the async listener is driven by its event loop.

        Inherited from `DHCPListener` through `AsyncDHCPServer`'s MRO, where it
        used to fail with `AttributeError: _cancellation_token` several frames
        deep instead of saying what to call.
        """
        raise NotImplementedError(
            "AsyncDHCPListener has no blocking listen(); "
            "use `await start()` and then `await wait()`."
        )

    async def start(self) -> None:
        self.bind()
        if self._worker is None:
            self._worker = _futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="pydhcp-async-handler"
            )
        loop = _asyncio.get_running_loop()
        self._loop = loop
        self._closing = False
        self._stopped = _asyncio.Event()
        for sock in self._sockets:
            sock.setblocking(False)
            self._tasks.append(
                loop.create_task(self._receive(sock, self._endpoints[sock]))
            )

    def stop(self) -> _ty.Any:
        """Close every transport and socket.

        Deliberately not a coroutine, even though `await listener.stop()` is the
        documented form and still works. The work here is entirely synchronous,
        and as `async def` this silently did nothing whenever it was reached
        through the inherited `DHCPListener` contract: `server.stop()` returned a
        coroutine nobody awaited, so the server kept running with its ports
        bound, and mypy accepted it. Returning an already-finished future keeps
        the `await` form working from inside a running loop.

        Called from the handler worker thread -- which is exactly what
        `DHCPCapture.hook_fail_fast` and the capture CLI's `--count` sink do --
        the close is handed back to the event loop instead of being run inline.
        Nothing it touches is thread-safe: `Task.cancel()` and
        `asyncio.Event.set()` both finish through `loop.call_soon`, which
        queues a callback *without* waking the loop.
        Measured with a handler calling `stop()` on its worker: the selector
        loop (Linux) never woke and `await wait()` blocked forever, while
        Windows' proactor loop returned in 7 ms -- the same
        green-on-one-platform shape as every other defect in this file.
        """
        loop = self._loop
        if loop is not None and not loop.is_closed():
            try:
                running: "_asyncio.AbstractEventLoop | None" = (
                    _asyncio.get_running_loop()
                )
            except RuntimeError:
                running = None
            if running is not loop:
                try:
                    loop.call_soon_threadsafe(self._close_endpoints)
                except RuntimeError:  # pragma: no cover - loop closed since
                    return self._close_endpoints()
                return None
        return self._close_endpoints()

    def _close_endpoints(self) -> _ty.Any:
        """The body of `stop()`, always on the event loop's own thread.

        Cancel the receive tasks, *then* close the endpoints -- the order netimps
        documents as a clean shutdown: a cancelled `arecv` unregisters its
        reader, so the loop is not left polling a socket about to close. The
        close therefore runs once the tasks have finished, and the returned
        awaitable completes then, so `await stop()` still means "closed". So
        does `await wait()`: the stop event is set only after the close, since
        `hook_fail_fast` callers check `bound_addresses` the moment it returns.
        """
        stopped, self._stopped = self._stopped, None
        self._loop = None
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            task.cancel()
        worker, self._worker = self._worker, None
        if worker is not None:
            # Abort, not drain: datagrams still queued are discarded and counted
            # in `metrics.packets_dropped_backlog`; the handler already running
            # finishes. Don't wait: stop() is called from the event loop, and a
            # handler in flight may be doing exactly the blocking work this
            # worker exists to keep off it.
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
            running = _asyncio.get_running_loop()
        except RuntimeError:
            # No running loop, so the tasks cannot be waited for and nobody can
            # be awaiting this anyway.
            self._close_sockets(stopped)
            return None
        if not tasks:
            self._close_sockets(stopped)
            future = running.create_future()
            future.set_result(None)
            return future

        async def finish() -> None:
            await _asyncio.gather(*tasks, return_exceptions=True)
            self._close_sockets(stopped)

        return running.create_task(finish())

    def _close_sockets(self, stopped: "_ty.Optional[_asyncio.Event]" = None) -> None:
        for sock in self._sockets:
            _close_socket(sock, self._endpoints)
        self._sockets.clear()
        if stopped is not None:
            stopped.set()
