"""The asyncio relay: the relay's rules over the asyncio listener."""

from __future__ import annotations

import typing as _ty

from ..listener._asyncio import AsyncDHCPListener
from ..listener._spec import ListenSpec
from ._core import DEFAULT_MAX_HOPS, ServerAddress, _RelayCore


class AsyncDHCPRelay(_RelayCore, AsyncDHCPListener):
    """The relay on an event loop.

    The same rules as `DHCPRelay`. The pending-client table is unguarded, as
    there: what keeps it safe is that `AsyncDHCPListener` runs handlers on a
    single worker thread, so `handle()` is serialised and in arrival order.
    """

    def __init__(
        self,
        listen: ListenSpec = None,
        server_addresses: _ty.Sequence[ServerAddress] = (),
        max_hops: int = DEFAULT_MAX_HOPS,
        insert_relay_agent_info: bool = False,
        circuit_id: _ty.Optional[bytes] = None,
        remote_id: _ty.Optional[bytes] = None,
        trust_client_relay_agent_info: bool = False,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
        max_queued: _ty.Optional[int] = None,
    ) -> None:
        AsyncDHCPListener.__init__(
            self,
            listen=listen,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
            max_queued=max_queued,
        )
        self._init_relay_state(
            server_addresses,
            max_hops=max_hops,
            insert_relay_agent_info=insert_relay_agent_info,
            circuit_id=circuit_id,
            remote_id=remote_id,
            trust_client_relay_agent_info=trust_client_relay_agent_info,
        )
