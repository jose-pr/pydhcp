"""The thread-based server: the server's rules over the thread-based listener."""

from __future__ import annotations

import typing as _ty

from ..lease import LeaseBackend
from ..listener._spec import ListenSpec
from ..listener._sync import DHCPListener
from ._core import _ServerCore


class DHCPServer(_ServerCore, DHCPListener):
    """A DHCP server: a `DHCPListener` that allocates leases and sends the RFC 2131 replies.

    Override any method or constant here: the `handle_*` hooks, `acquire_lease`,
    `release_lease`, `get_inform_options`, `lease_seconds` and the lease-policy
    constants. They run on the receive thread.
    """

    def __init__(
        self,
        listen: ListenSpec = None,
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        lease_backend: _ty.Optional[LeaseBackend] = None,
        per_interface: _ty.Optional[bool] = None,
    ) -> None:
        DHCPListener.__init__(
            self,
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_server_state(lease_backend)
