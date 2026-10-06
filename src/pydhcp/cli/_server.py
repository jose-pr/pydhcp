"""`pydhcp server`: run a DHCP server."""

from __future__ import annotations

import pathlib
import typing as _ty

from duho import Meta

from ..server._sync import DHCPServer
from ..lease import FileLeaseBackend, LeaseBackend
from ._common import _arguments, _Configured
from ._settings import listen_value


class Server(_Configured):
    """Start DHCP server"""

    _parsername_ = "server"

    listen: _ty.Annotated[
        _ty.Optional[str], Meta(env="PYDHCP_SERVER_LISTEN", type=listen_value)
    ] = None
    "Listen address/port spec, for example '*', '127.0.0.1:6767,127.0.0.1:6768' or an interface ('eth1', 'eth1:67', 'aa-bb-cc-dd-ee-ff'). Default: every address, port 67"
    ("--listen", "-l")

    per_interface: _ty.Annotated[bool, Meta(env="PYDHCP_SERVER_PER_INTERFACE")] = False
    "Bind one socket per interface address instead of the wildcard; on Linux such sockets hear no broadcast"
    ("--per-interface",)

    lease_file: _ty.Annotated[
        _ty.Optional[pathlib.Path], Meta(env="PYDHCP_SERVER_LEASE_FILE")
    ] = None
    "Persist leases to this JSON file instead of keeping them in memory. Default: in memory"
    ("--lease-file",)

    def __call__(self) -> None:
        self._begin()
        # An empty `--listen` names no address and the listener says so, rather
        # than serving the wildcard: `is None`, not falsiness.
        listen = "*" if self.listen is None else self.listen

        # A persistent backend is the difference between a restart keeping every
        # client on its address and every client renumbering. The server leaves
        # a backend it was handed open, so this command closes the one it makes.
        backend: _ty.Optional[LeaseBackend] = None
        if self.lease_file is not None:
            backend = FileLeaseBackend(str(self.lease_file))
        try:
            # Construct first, announce second: the constructor is what refuses
            # a malformed `listen`, and that is an argument error, not a
            # runtime one.
            with _arguments():
                server = DHCPServer(
                    listen=listen,
                    per_interface=self.per_interface,
                    lease_backend=backend,
                )
            if backend is not None:
                self._logger_.info("Persisting leases to %s", self.lease_file)
            self._logger_.info("Starting DHCP server, listening on: %s...", listen)
            try:
                # The library installs no signal handler: Ctrl-C arrives here
                # as `KeyboardInterrupt`, and leaving the block closes the
                # server.
                with server:
                    server.serve_forever()
            except KeyboardInterrupt:
                self._logger_.info("Stopped listening due to Ctrl-C")
        finally:
            # Flush a coalescing backend, and let the in-memory one no-op.
            close = getattr(backend, "close", None)
            if close is not None:
                close()
