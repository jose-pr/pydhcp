"""The thread-based relay: the relay's rules over the thread-based listener."""

from __future__ import annotations

import typing as _ty

from ..listener._spec import ListenSpec
from ..listener._sync import DHCPListener
from ._core import DEFAULT_MAX_HOPS, ServerAddress, _RelayCore


class DHCPRelay(_RelayCore, DHCPListener):
    """RFC 1542 / RFC 2131 4.1 / RFC 3046 DHCP relay agent on a receive thread.

    Forwards client requests to the configured upstream servers and their
    replies back; see `_RelayCore` for the rules.
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
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
    ) -> None:
        DHCPListener.__init__(
            self,
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_relay_state(
            server_addresses,
            max_hops=max_hops,
            insert_relay_agent_info=insert_relay_agent_info,
            circuit_id=circuit_id,
            remote_id=remote_id,
            trust_client_relay_agent_info=trust_client_relay_agent_info,
        )
