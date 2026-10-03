"""The DHCP server, split by responsibility into layers (see `DhcpServer`)."""

from __future__ import annotations

import netimps as _netimps

from .. import network as _net
from ..lease import DhcpLease, LeaseBackend
from ..listener import AsyncDhcpListener as _AsyncBase, ListenSpec, RequestContext
from ..packet import enums as _enum
from ..packet.message import DhcpMessage
from .handlers import _Handlers
from .policy import _NonExtendingBackend, _SERVABLE_INTERFACES, _servable_interface
from .reply import _is_loopback

# `DhcpLease`, `_net` and `_netimps` are imported only to stay importable from
# `pydhcp.server`, as they were from the single module: callers import
# `DhcpLease` from here, and tests patch attributes through the `_net`/`_netimps`
# aliases -- the shared module objects, so such a patch reaches every layer.


class DhcpServer(_Handlers):
    """A DHCP server: `DhcpListener` plus allocation and the RFC 2131 replies.

    Composed of layers -- `_ServerState` (constants and state), `_LeasePolicy`,
    `_Replies` and `_Handlers` -- each in its own module of `pydhcp.server`.
    Override any method or constant here as before.
    """

    def __init__(
        self,
        listen: ListenSpec = None,
        select_timeout: float | None = None,
        max_packet_size: int | None = None,
        lease_backend: LeaseBackend | None = None,
        per_interface: bool | None = None,
    ) -> None:
        super().__init__(
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_server_state(lease_backend)


class AsyncDhcpServer(_AsyncBase, DhcpServer):  # type: ignore[misc]
    DEFAULT_PORTS = (_enum.DhcpPort.SERVER,)

    def __init__(
        self,
        listen: ListenSpec = None,
        max_packet_size: int | None = None,
        lease_backend: LeaseBackend | None = None,
        per_interface: bool | None = None,
    ) -> None:
        _AsyncBase.__init__(
            self,
            listen=listen,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_server_state(lease_backend)

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        DhcpServer.handle(self, msg, context)


__all__ = ["AsyncDhcpServer", "DhcpServer"]
