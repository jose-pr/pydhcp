"""The asyncio server: the server's rules over the asyncio listener."""

from __future__ import annotations

import typing as _ty

from ..lease import LeaseBackend
from ..listener._asyncio import AsyncDHCPListener
from ..listener._spec import ListenSpec
from ._core import _ServerCore


class AsyncDHCPServer(_ServerCore, AsyncDHCPListener):
    """A DHCP server on an event loop.

    The same rules and hooks as `DHCPServer`; the hooks are ordinary blocking
    methods and run on the one worker thread the listener hands datagrams to,
    never on the loop.
    """

    def __init__(
        self,
        listen: ListenSpec = None,
        *,
        max_packet_size: _ty.Optional[int] = None,
        lease_backend: _ty.Optional[LeaseBackend] = None,
        per_interface: _ty.Optional[bool] = None,
        reuse_address: _ty.Optional[bool] = None,
        receive_buffer_size: _ty.Optional[int] = None,
        max_queued: _ty.Optional[int] = None,
    ) -> None:
        AsyncDHCPListener.__init__(
            self,
            listen=listen,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
            reuse_address=reuse_address,
            receive_buffer_size=receive_buffer_size,
            max_queued=max_queued,
        )
        self._init_server_state(lease_backend)
