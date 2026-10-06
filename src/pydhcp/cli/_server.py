"""`pydhcp server`: run a DHCP server."""

from __future__ import annotations

import typing as _ty

from ..server._sync import DHCPServer
from ..lease import FileLeaseBackend, LeaseBackend
from .._config import load_config
from ._common import _Command


class Server(_Command):
    """Start DHCP server"""

    _parsername_ = "server"

    config: _ty.Optional[str] = None
    "Path to config file (JSON, YAML, TOML, or INI)"
    ("--config",)

    listen: _ty.Optional[str] = None
    "Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'"
    ("--listen", "-l")

    per_interface: bool = False
    "Bind one socket per interface address instead of the wildcard; on Linux such sockets hear no broadcast"
    ("--per-interface",)

    lease_file: _ty.Optional[str] = None
    "Persist leases to this JSON file instead of keeping them in memory"
    ("--lease-file",)

    def __call__(self) -> None:
        config: _ty.Dict[str, _ty.Any] = {}
        if self.config:
            config = load_config(self.config)

        server_config = config.get("server", {})
        # An explicit flag beats the config file. The other order meant
        # `--config shared.yaml --listen 127.0.0.1:6767` bound whatever the file
        # said, which is the opposite of what every other CLI does and gives no
        # way to override a shared config for one run.
        # `is None`, not falsiness: an empty `--listen` or `listen = ""` names no
        # address and the listener says so, rather than serving the wildcard.
        listen = self.listen
        if listen is None:
            listen = server_config.get("listen")
        if listen is None:
            listen = "*"
        lease_file = self.lease_file or server_config.get("lease_file")
        unknown = sorted(set(server_config) - {"listen", "lease_file"})
        if unknown:
            self._logger_.warning(
                "Ignoring unsupported key(s) under [server] in %s: %s",
                self.config,
                ", ".join(unknown),
            )

        # A persistent backend is the difference between a restart keeping every
        # client on its address and every client renumbering. deployment.md has
        # always told operators to mount lease storage; until now the CLI had no
        # way to write to it, so the volume stayed empty.
        backend: _ty.Optional[LeaseBackend] = None
        if lease_file:
            backend = FileLeaseBackend(lease_file)
            self._logger_.info("Persisting leases to %s", lease_file)

        self._logger_.info("Starting DHCP server, listening on: %s...", listen)
        server = DHCPServer(
            listen=listen,
            per_interface=self.per_interface,
            lease_backend=backend,
        )
        try:
            # The library installs no signal handler: Ctrl-C arrives here as
            # `KeyboardInterrupt`, and leaving the block closes the server.
            with server:
                server.serve_forever()
        except KeyboardInterrupt:
            self._logger_.info("Stopped listening due to Ctrl-C")
        finally:
            # Flush a coalescing backend, and let the in-memory one no-op.
            close = getattr(server.lease_backend, "close", None)
            if close is not None:
                close()
