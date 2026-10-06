"""DHCP listeners and transports.

Split by responsibility, one private module each:

- `_transport`  -- how a reply leaves (`UDPTransport`, `PktInfoUDPTransport`)
- `_spec`       -- the `listen` argument and the addresses it expands to
- `_interfaces` -- which host interface a datagram arrived on
- `_receive`    -- packet-info support and turning a netimps datagram into a
  `DHCPRequestContext`
- `_binding`    -- claiming the ports, and the errors when that fails
- `_sync`       -- `DHCPListener`
- `_asyncio`    -- `AsyncDHCPListener`
"""

from __future__ import annotations

from ._asyncio import AsyncDHCPListener
from ._binding import _REQUESTED_ADDRESS, _bind_sockets, _close_socket
from ._interfaces import _network_interface, _resolve_interface
from ._receive import (
    Arrival,
    DHCPRequestContext,
    _TruncatedDatagram,
    _arrival,
    _context_for,
    _pktinfo_supported,
)
from ._spec import (
    ListenAddress,
    ListenBinding,
    ListenPort,
    ListenSpec,
    _binding_host,
    _iter_listen_bindings,
    _listen_uses_wildcard,
    _parselisteners,
    _split_host_port,
    _split_listen_string,
)
from ._sync import DHCPListener
from ._transport import (
    BROADCAST_ADDRESS,
    PktInfoUDPTransport,
    DHCPTransport,
    UDPTransport,
    _dest_string,
)

__all__ = [
    "AsyncDHCPListener",
    "BROADCAST_ADDRESS",
    "DHCPListener",
    "ListenAddress",
    "ListenBinding",
    "ListenPort",
    "ListenSpec",
    "PktInfoUDPTransport",
    "DHCPRequestContext",
    "DHCPTransport",
    "UDPTransport",
]
