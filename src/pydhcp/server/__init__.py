"""The DHCP server, split by responsibility into layers (see `DHCPServer`)."""

from __future__ import annotations

import typing as _ty

import netimps as _netimps

from .. import _network as _net
from ..lease import LeaseBackend
from ..listener._asyncio import AsyncDHCPListener as _AsyncBase
from ..listener._receive import DHCPRequestContext
from ..listener._spec import ListenSpec
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage
from .handlers import _Handlers
from .policy import _NonExtendingBackend, _servable_interface
from .reply import _is_loopback

# `_net` and `_netimps` are the shared module objects: a test patches an attribute
# through them and the patch reaches every layer of the server.


class DHCPServer(_Handlers):
    """A DHCP server: `DHCPListener` plus allocation and the RFC 2131 replies.

    Composed of layers -- `_ServerState` (constants and state), `_LeasePolicy`,
    `_Replies` and `_Handlers` -- each in its own module of `pydhcp.server`.
    Override any method or constant here as before.
    """

    def __init__(
        self,
        listen: ListenSpec = None,
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        lease_backend: _ty.Optional[LeaseBackend] = None,
        per_interface: _ty.Optional[bool] = None,
    ) -> None:
        super().__init__(
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_server_state(lease_backend)


class AsyncDHCPServer(_AsyncBase, DHCPServer):  # type: ignore[misc]
    DEFAULT_PORTS = (_enum.DHCPPort.SERVER,)

    def __init__(
        self,
        listen: ListenSpec = None,
        max_packet_size: _ty.Optional[int] = None,
        lease_backend: _ty.Optional[LeaseBackend] = None,
        per_interface: _ty.Optional[bool] = None,
        max_queued: _ty.Optional[int] = None,
    ) -> None:
        _AsyncBase.__init__(
            self,
            listen=listen,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
            max_queued=max_queued,
        )
        self._init_server_state(lease_backend)

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        DHCPServer.handle(self, msg, context)


__all__ = ["AsyncDHCPServer", "DHCPServer"]
