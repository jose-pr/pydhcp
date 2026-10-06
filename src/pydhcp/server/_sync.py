"""The thread-based server: the server's rules over the thread-based listener."""

from __future__ import annotations

import typing as _ty

from ..lease import LeaseBackend
from ..listener._spec import ListenLike
from ..listener._sync import DHCPListener
from ._core import _ServerCore


class DHCPServer(_ServerCore, DHCPListener):
    """A DHCP server: a `DHCPListener` that allocates leases and sends the RFC 2131 replies.

    Override any method or constant here: the `handle_*` hooks, `acquire_lease`,
    `release_lease`, `get_inform_options`, `get_lease_seconds` and the lease-policy
    constants. They run on the receive thread.
    """

    def __init__(
        self,
        listen: ListenLike = None,
        *,
        poll_interval: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        lease_backend: _ty.Optional[LeaseBackend] = None,
        per_interface: _ty.Optional[bool] = None,
        reuse_address: _ty.Optional[bool] = None,
        receive_buffer_size: _ty.Optional[int] = None,
    ) -> None:
        DHCPListener.__init__(
            self,
            listen=listen,
            poll_interval=poll_interval,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
            reuse_address=reuse_address,
            receive_buffer_size=receive_buffer_size,
        )
        self._init_server_state(lease_backend)
