"""`pydhcp server`: run a DHCP server."""

from __future__ import annotations

import pathlib
import typing as _ty

from duho import Meta

from ..server._sync import DHCPServer
from ..lease import FileLeaseBackend, LeaseBackend
from ._common import _arguments, _Listening


class Server(_Listening):
    """Start DHCP server"""

    _parsername_ = "server"
    # Not a tool: it does not return until it is stopped.
    _mcp_ = False

    lease_file: _ty.Annotated[
        _ty.Optional[pathlib.Path], Meta(env="PYDHCP_SERVER_LEASE_FILE")
    ] = None
    "Persist leases to this JSON file instead of keeping them in memory. Default: in memory"
    ("--lease-file",)

    lenient_reply_ports: _ty.Annotated[
        bool, Meta(env="PYDHCP_SERVER_LENIENT_REPLY_PORTS")
    ] = False
    "Answer to the port a request came from instead of the RFC 1542 ports (67 for a relay, 68 for a client), so a sender chooses where its reply goes. Default: the RFC's ports"
    ("--lenient-reply-ports",)

    def __call__(self) -> None:
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
            server.STRICT_REPLY_PORTS = not self.lenient_reply_ports
            if backend is not None:
                self._logger_.info("Persisting leases to %s", self.lease_file)
            self._logger_.info("Starting DHCP server, listening on: %s...", listen)
            self._serve(server)
        finally:
            # Flush a coalescing backend, and let the in-memory one no-op.
            close = getattr(backend, "close", None)
            if close is not None:
                close()
