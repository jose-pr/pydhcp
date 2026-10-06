"""The thread-based listener."""

from __future__ import annotations

import logging as _logging
import select as _select
import socket as _socket
import threading as _thread
import time as _time
import typing as _ty

import netimps as _netimps

from .. import _network as _net
from ._core import _ListenerCore
from ._receive import _TruncatedDatagram, _arrival
from ._spec import ListenSpec

LOGGER = _logging.getLogger(__name__)

#: Seconds `close()` waits for a receive loop that has been asked to stop; a
#: handler still running after that is abandoned (the receive thread is a daemon).
_CLOSE_WAIT = 5.0


class DHCPListener(_ListenerCore):
    """Receives DHCP datagrams on a thread and hands each to `handle()`.

    `serve_forever()` receives on the calling thread, `start()` on a daemon
    thread. `shutdown()` ends the receive loop and never blocks, so a handler
    may call it; `wait_closed()` blocks until the loop has ended; `close()` is
    both, then releases the sockets, and is final. The library installs no
    signal handler: Ctrl-C reaches `serve_forever()` as `KeyboardInterrupt`.
    """

    def __init__(
        self,
        listen: ListenSpec = None,
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
    ) -> None:
        super().__init__(
            listen=listen, max_packet_size=max_packet_size, per_interface=per_interface
        )
        #: Upper bound on one wait for a datagram: a `KeyboardInterrupt` is
        #: delivered to the main thread between waits, not during one, on Windows.
        self._select_timeout = select_timeout or 1
        self._state_lock = _thread.Lock()
        self._close_lock = _thread.Lock()
        self._serving = False
        self._stopping = False
        self._idle = _thread.Event()
        self._idle.set()
        self._serving_ident: _ty.Optional[int] = None
        self._receive_thread: _ty.Optional[_thread.Thread] = None
        self._wake_read: _ty.Optional[_socket.socket] = None
        self._wake_write: _ty.Optional[_socket.socket] = None

    # -- lifecycle ---------------------------------------------------------

    def _claim(self) -> None:
        """Bind, then mark this caller as the one that serves."""
        self.bind()
        with self._state_lock:
            if self._closed:
                raise RuntimeError(f"{type(self).__name__} is closed")
            if self._serving:
                raise RuntimeError(f"{type(self).__name__} is already serving")
            wake_read, wake_write = _socket.socketpair()
            wake_read.setblocking(False)
            wake_write.setblocking(False)
            self._wake_read, self._wake_write = wake_read, wake_write
            self._serving = True
            self._stopping = False
            self._idle.clear()

    def serve_forever(self) -> None:
        """Bind, then receive on the calling thread until `shutdown()`.

        Raises what `bind()` raised, and `RuntimeError` when already serving or
        closed. The sockets stay open on return: `close()` releases them.
        """
        self._claim()
        self._serve()

    def start(self) -> None:
        """Bind, then receive on a new daemon thread.

        Binding happens here, on the caller's thread, so an address that cannot
        be bound raises what `bind()` raised and leaves the listener unstarted
        and nothing bound. Raises `RuntimeError` when already serving or closed.
        """
        self._claim()
        # Daemon: nothing in the loop ends on its own, so a non-daemon thread
        # keeps the interpreter alive after `main` returns.
        thread = _thread.Thread(target=self._serve, name="pydhcp-listener", daemon=True)
        self._receive_thread = thread
        try:
            thread.start()
        except BaseException:
            self._finish_serving()
            raise

    def shutdown(self) -> None:
        """Ask the receive loop to end. Returns at once, from any thread and from a handler."""
        with self._state_lock:
            if not self._serving:
                return
            self._stopping = True
        self._wake()

    def wait_closed(self, timeout: _ty.Optional[float] = None) -> bool:
        """Block until the receive loop has ended; `False` if `timeout` seconds passed first.

        Raises `RuntimeError` on the receive thread, which would wait for itself.
        """
        if self._serving_ident == _thread.get_ident():
            raise RuntimeError(
                "wait_closed() on the receive thread would wait for itself"
            )
        began = _time.monotonic()
        if not self._idle.wait(timeout):
            return False
        thread = self._receive_thread
        if thread is not None and thread is not _thread.current_thread():
            thread.join(
                None
                if timeout is None
                else max(0.0, timeout - (_time.monotonic() - began))
            )
            if thread.is_alive():
                return False
        return True

    def close(self) -> None:
        """Shut down, wait for the receive loop, then release every socket. Final.

        Called on the receive thread itself (from a handler) it shuts down and
        returns: the loop releases the sockets as it ends. Repeatable.
        """
        if self._serving_ident == _thread.get_ident():
            with self._state_lock:
                self._closed = True
            self.shutdown()
            return
        with self._close_lock:
            with self._state_lock:
                self._closed = True
            self.shutdown()
            if not self.wait_closed(_CLOSE_WAIT):
                LOGGER.warning(
                    f"The receive loop did not end within {_CLOSE_WAIT} s of close(); "
                    "releasing the sockets under it."
                )
            self._close_sockets()

    def __enter__(self) -> "DHCPListener":
        self.bind()
        return self

    def __exit__(self, *_exc: _ty.Any) -> None:
        self.close()

    def _wake(self) -> None:
        """End a wait for datagrams from any thread."""
        wake = self._wake_write
        if wake is not None:
            try:
                wake.send(b"\0")
            except OSError:  # pragma: no cover - full or closed: already woken
                pass

    def _finish_serving(self) -> None:
        """Release what serving held and let `wait_closed()` return."""
        for sock in (self._wake_read, self._wake_write):
            if sock is not None:
                sock.close()
        self._wake_read = self._wake_write = None
        if self._closed:
            self._close_sockets()
        with self._state_lock:
            self._serving_ident = None
            self._serving = False
        self._idle.set()

    def _serve(self) -> None:
        self._serving_ident = _thread.get_ident()
        try:
            self._loop()
        finally:
            self._finish_serving()

    def _loop(self) -> None:
        wake = self._wake_read
        assert wake is not None
        while not self._stopping:
            try:
                rlist, _, _ = _select.select(
                    [*self._sockets, wake], [], [], self._select_timeout
                )
            except (OSError, ValueError):
                if self._stopping:  # a close() that gave up waiting
                    break
                raise
            for sock in rlist:
                if sock is wake:
                    self._drain_wake(wake)
                    continue
                if self._stopping:
                    # A handler can shut the listener down -- `DHCPCapture`'s
                    # `--count` sink and `hook_fail_fast` both do -- and the
                    # rest of the ready set must not be handled after that.
                    break
                self._receive_one(sock)

    @staticmethod
    def _drain_wake(wake: _socket.socket) -> None:
        try:
            while wake.recv(64):
                pass
        except OSError:
            pass

    def _receive_one(self, sock: _socket.socket) -> None:
        """Receive, decode and dispatch exactly one datagram.

        Split into three steps because they fail for three unrelated reasons and
        need three different reports: a malformed packet from the segment
        (routine, the peer's doing), a socket error (ours), and a bug inside a
        `handle()` override, which keeps its traceback.
        """
        try:
            # One octet over the limit, so a datagram that does not fit can be
            # told apart from one that exactly fills it. netimps reports the
            # cut on every platform, Windows included, as `truncated`.
            endpoint = self._endpoints.get(sock)
            if endpoint is None:  # pragma: no cover - not bound through bind()
                endpoint = self._endpoints[sock] = _netimps.UDPEndpoint(
                    sock, pktinfo=False
                )
            data, client, ifindex, local_ip = _arrival(
                endpoint.recv(self._max_packet_size + 1), self._max_packet_size
            )
        except _TruncatedDatagram as e:
            self.metrics.packets_dropped_truncated += 1
            LOGGER.warning(f"Dropping a truncated datagram: {e}")
            return
        except OSError as e:
            self.metrics.packets_dropped_error += 1
            LOGGER.error(
                f"Receive failed on {self._describe(sock)}: "
                f"{e.__class__.__name__} | {e}",
                exc_info=True,
            )
            return

        self._dispatch(data, client, sock, ifindex, local_ip)

    @staticmethod
    def _describe(sock: _socket.socket) -> str:
        try:
            return str(_net.SocketAddress(sock))
        except OSError:  # pragma: no cover - closed underneath us
            return "a closed socket"
