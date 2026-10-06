"""The asyncio server: the server's rules over the asyncio listener."""

from __future__ import annotations

import typing as _ty

from ..lease import LeaseBackend
from ..listener._asyncio import AsyncDHCPListener
from ..listener._spec import ListenLike
from ._core import _ServerCore


class AsyncDHCPServer(_ServerCore, AsyncDHCPListener):
    """A DHCP server on an event loop.

    The same rules and hooks as `DHCPServer`; the hooks are ordinary blocking
    methods and run on the one worker thread the listener hands datagrams to,
    never on the loop.
    """

    def __init__(
        self,
        listen: ListenLike = None,
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

    async def _close(self) -> None:
        # A lease backend the server was given is not closed: it is the caller's.
        # One the server created itself is closed here.
        try:
            await AsyncDHCPListener._close(self)
        finally:
            self._close_owned_backend()
