"""DHCP listeners and transports.

Split by responsibility; every name is importable from here as it always was:

- `transport`  -- how a reply leaves (`UDPTransport`, `PktInfoUDPTransport`)
- `spec`       -- the `listen` argument and the addresses it expands to
- `interfaces` -- which host interface a datagram arrived on
- `receive`    -- packet-info support and turning a netimps datagram into a
  `DHCPRequestContext`
- `binding`    -- claiming the ports, and the errors when that fails
- `sync`       -- `DHCPListener`
- `aio`        -- `AsyncDHCPListener`
"""

from __future__ import annotations

from .aio import AsyncDHCPListener
from .binding import _REQUESTED_ADDRESS, _bind_sockets, _close_socket, _raise_bind_error
from .interfaces import _network_interface, _resolve_interface
from .receive import (
    Arrival,
    DHCPRequestContext,
    _TruncatedDatagram,
    _arrival,
    _context_for,
    _pktinfo_supported,
)
from .spec import (
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
from .sync import DHCPListener
from .transport import (
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
