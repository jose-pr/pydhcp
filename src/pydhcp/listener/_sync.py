"""The thread-based listener."""

from __future__ import annotations

import logging as _logging
import select as _select
import socket as _socket
import threading as _thread
import typing as _ty

import netimps as _netimps

from .. import _constants as _const, _network as _net
from .._metrics import DHCPMetrics
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage
from ._binding import _bind_sockets, _close_socket
from ._receive import (
    DHCPRequestContext,
    _TruncatedDatagram,
    _arrival,
    _context_for,
    _pktinfo_supported,
)
from ._spec import ListenSpec, _parselisteners

LOGGER = _logging.getLogger(__name__)


class DHCPListener:
    DEFAULT_PORTS: _ty.Sequence[int] = tuple(p.value for p in _enum.DHCPPort)

    #: Whether to set ``SO_REUSEADDR`` on every listening socket. Off: see
    #: `_bind_sockets` for what sharing a DHCP port actually looks like when it
    #: goes wrong. A class attribute rather than a constructor argument so every
    #: subclass (server, client, relay, capture) inherits it without each
    #: constructor having to forward it.
    REUSE_ADDRESS: bool = False

    #: Receive buffer to ask the OS for on every listening socket, in octets;
    #: 0 keeps the OS default. 1 MiB holds about 3500 typical 300-octet DHCP
    #: datagrams, against about 220 in Windows' 64 KiB default -- a segment
    #: powering up sends its DISCOVERs together. The kernel may grant less
    #: (Linux caps at net.core.rmem_max); a shortfall is logged at INFO.
    RECEIVE_BUFFER_SIZE: int = 1 << 20

    def __init__(
        self,
        listen: ListenSpec = None,
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = _const.UDP_MAX_PACKET_SIZE,
        per_interface: _ty.Optional[bool] = None,
    ) -> None:
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._pktinfo = _pktinfo_supported(listen, per_interface)
        self._listen = _parselisteners(
            listen, self.DEFAULT_PORTS, expand_wildcard=not self._pktinfo
        )
        self._per_interface = per_interface
        self._sockets: list[_socket.socket] = []
        #: The netimps endpoint each socket is received through.
        self._endpoints: dict[_socket.socket, _netimps.UDPEndpoint] = {}
        self._sigint_handler: _ty.Optional[_ty.Any] = None
        self._previous_sigint: _ty.Optional[_ty.Any] = None
        self._select_timeout = select_timeout or 1
        self._cancellation_token: _thread.Event | None = None
        self.metrics = DHCPMetrics()

    @property
    def bound_addresses(self) -> "tuple[_net.SocketAddress, ...]":
        """The addresses this listener is currently bound to.

        Empty before `bind()` and after `close()`. **Not** emptied by `stop()`
        returning: `stop()` only asks the receive loop to exit, and the sockets
        are closed by `listen()` on its way out -- up to `select_timeout` later,
        on the receive thread. Join the thread `start()` handed back before
        reading this if the distinction matters. (It previously stayed populated
        indefinitely, because nothing closed the sockets at all.)

        Asking the socket rather than repeating `self._listen` is the point:
        binding port 0 gives an ephemeral port that only the socket knows, which
        is how a test or a tool discovers where to send. Without this the only
        way to find out was to reach into the private socket list, which the
        tests did in twenty-one places.
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
            reuse_address=self.REUSE_ADDRESS,
            receive_buffer=self.RECEIVE_BUFFER_SIZE,
        )

    def stop(self) -> None:
        if self._cancellation_token is not None:
            self._cancellation_token.set()

    def close(self) -> None:
        """Close every bound socket and release the SIGINT handler.

        `stop()` only ends the receive loop; without this the sockets stayed
        open, so a process that creates a listener per operation leaked a bound
        UDP socket and its port each time, and the next bind to the same port
        failed or silently shared it.
        """
        for socket in self._sockets:
            _close_socket(socket, self._endpoints)
        self._sockets.clear()
        self._restore_sigint_handler()

    def __enter__(self) -> "DHCPListener":
        self.bind()
        return self

    def __exit__(self, *_exc: _ty.Any) -> None:
        self.stop()
        self.close()

    def wait(self) -> None:
        # Read once per turn, not twice. `listen()` sets `_cancellation_token`
        # to None from the receive thread as it exits, so a token that was not
        # None at the `is not None` test could be None at the `.wait()` --
        # `AttributeError: 'NoneType' object has no attribute 'wait'` out of a
        # call whose whole job is to block until shutdown.
        while True:
            token = self._cancellation_token
            if token is None:
                return
            token.wait(self._select_timeout)

    def _install_sigint_handler(self) -> None:
        """Install a Ctrl-C handler, if this thread is allowed to.

        `signal.signal` raises off the main thread, which used to propagate out
        of `start()` *after* the cancellation token was set -- leaving the
        listener permanently 'started' and impossible to start again. Library
        code should not claim a process-wide handler as a side effect of
        starting, so failure here is not an error.
        """
        import signal

        if _thread.current_thread() is not _thread.main_thread():
            return

        def stop(*args: _ty.Any) -> None:
            self.stop()
            LOGGER.info("Stopped listening due to Ctrl-C")

        try:
            self._sigint_handler = stop
            self._previous_sigint = signal.signal(signal.SIGINT, stop)
        except (ValueError, OSError):  # pragma: no cover - platform dependent
            self._sigint_handler = None
            self._previous_sigint = None

    def _restore_sigint_handler(self) -> None:
        import signal

        if self._sigint_handler is None:
            return
        if _thread.current_thread() is not _thread.main_thread():
            # `signal.signal` raises off the main thread, so the handler cannot
            # be given back from here -- and `close()` now runs on the receive
            # thread too (from `listen()`'s teardown). Leave both the handler
            # and the bookkeeping in place so a later `close()` on the owning
            # thread can still restore it; clearing them here would make that
            # restore a silent no-op and strand the process-wide handler.
            return
        try:
            # Only give it back if nobody else has claimed it since.
            if signal.getsignal(signal.SIGINT) is self._sigint_handler:
                signal.signal(signal.SIGINT, self._previous_sigint)
        except (ValueError, OSError, TypeError):  # pragma: no cover
            pass
        self._sigint_handler = None
        self._previous_sigint = None

    def start(
        self, cancellation_token: _ty.Optional[_thread.Event] = None
    ) -> _ty.Optional[_thread.Thread]:
        """Bind, then receive on a new daemon thread, which is returned.

        Binding happens here, on the caller's thread, so an address that cannot
        be bound raises what `bind()` raised and leaves the listener unstarted
        and nothing bound. Returns `None` when it is already started.
        """
        if not self._cancellation_token:
            self.bind()
            # Daemon: a non-daemon receive thread keeps the interpreter alive
            # after `main` returns, and nothing in the loop ends on its own.
            # Measured: a process that started a listener and fell off the end
            # of `main` without `stop()` was still running after 8 s and had to
            # be killed. Shutdown is `stop()` plus `join()`, which every
            # supported entry point does; a caller that forgets now exits
            # instead of hanging.
            thread = _thread.Thread(
                target=self.listen, args=(), name="pydhcp-listener", daemon=True
            )
            self._cancellation_token = cancellation_token or _thread.Event()
            self._install_sigint_handler()
            try:
                thread.start()
            except BaseException:
                # A thread that cannot start leaves nothing bound and the
                # listener unstarted, as a bind that fails does.
                self._cancellation_token = None
                self.close()
                raise
            return thread
        return None

    def _receive_one(self, sock: _socket.socket) -> None:
        """Receive, decode and dispatch exactly one datagram.

        Split into three steps because they fail for three unrelated reasons and
        need three different reports. One `except Exception` used to cover all of
        them and log `Encounter error handling request: <class> | <str>` with no
        traceback -- so a malformed packet from the segment (routine, the peer's
        doing), a socket error (ours), and a bug inside a `handle()` override
        were indistinguishable, and the only one whose traceback matters was the
        one that lost it.
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
            raw: memoryview = memoryview(data)
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

        try:
            msg = DHCPMessage.decode(raw)
        except Exception as e:
            # The sender's fault, and routine on a shared segment: a warning
            # with the facts, not an error with a traceback of our own decoder.
            self.metrics.packets_dropped_error += 1
            LOGGER.warning(
                f"Discarding an undecodable {len(raw)}-octet datagram from "
                f"{client}: {e.__class__.__name__} | {e}"
            )
            return

        try:
            self.metrics.packets_received += 1
            context = _context_for(
                sock, client, msg.chaddr, ifindex, local_ip, self._endpoints.get(sock)
            )
            msg.log(client, _net.SocketAddress(sock), _logging.DEBUG)
            self.handle(msg, context)
        except Exception as e:
            # Ours, almost always: `handle()` is the documented override point.
            # exc_info is the whole value here -- the class name and str of, say,
            # a KeyError deep in a lease backend say nothing about where it came
            # from. `DHCPCapture.hook_fail_fast` relies on this staying a catch
            # rather than a propagate.
            self.metrics.packets_dropped_error += 1
            LOGGER.error(
                f"Encounter error handling request from {client}: "
                f"{e.__class__.__name__} | {e}",
                exc_info=True,
            )

    @staticmethod
    def _describe(sock: _socket.socket) -> str:
        try:
            return str(_net.SocketAddress(sock))
        except OSError:  # pragma: no cover - closed underneath us
            return "a closed socket"

    def listen(self) -> None:
        rlist: list[_socket.socket]
        if self._cancellation_token is None:
            self._cancellation_token = _thread.Event()
        token = self._cancellation_token
        try:
            self.bind()
            while not token.is_set():
                rlist, _, _ = _select.select(
                    list(self._sockets), [], [], self._select_timeout
                )
                if token.is_set():
                    break
                for sock in rlist:
                    if token.is_set():
                        # A handler can stop the listener -- `DHCPCapture`'s
                        # `--count` sink and `hook_fail_fast` both do -- and
                        # this loop then kept draining the rest of the ready
                        # set. Measured: `capture --count 1` wrote 3 records in
                        # 3 of 3 trials on a wildcard bind with three sockets
                        # ready in the same `select()`.
                        break
                    self._receive_one(sock)
        except KeyboardInterrupt:
            LOGGER.info("Stopped listening due to Ctrl-C")
            token.set()
        finally:
            self._cancellation_token = None
            # Release the sockets. `stop()` only ends the loop, and nothing else
            # closed them on this path: measured across three test modules, 7
            # sockets were still open at the end of the session. `close()` also
            # gives back the SIGINT handler, but only when it can -- see
            # `_restore_sigint_handler` for why that part waits for the main
            # thread.
            self.close()
