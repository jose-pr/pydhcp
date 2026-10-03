"""DHCP listeners and transports.

Split by responsibility; every name is importable from here as it always was:

- `transport`  -- how a reply leaves (`UdpTransport`, `PktInfoUdpTransport`)
- `spec`       -- the `listen` argument and the addresses it expands to
- `interfaces` -- which host interface a datagram arrived on
- `receive`    -- packet-info support and turning a netimps datagram into a
  `RequestContext`
- `binding`    -- claiming the ports, and the errors when that fails
- `sync`       -- `DhcpListener`
- `aio`        -- `AsyncDhcpListener`
"""

from __future__ import annotations

from .aio import AsyncDhcpListener
from .binding import _REQUESTED_ADDRESS, _bind_sockets, _close_socket, _raise_bind_error
from .interfaces import _network_interface, _resolve_interface
from .receive import (
    Arrival,
    RequestContext,
    _TruncatedDatagram,
    _WSAEMSGSIZE,
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
from .sync import DhcpListener
from .transport import (
    BROADCAST_ADDRESS,
    PktInfoUdpTransport,
    Transport,
    UdpTransport,
    _dest_string,
)

__all__ = [
    "AsyncDhcpListener",
    "BROADCAST_ADDRESS",
    "DhcpListener",
    "ListenAddress",
    "ListenBinding",
    "ListenPort",
    "ListenSpec",
    "PktInfoUdpTransport",
    "RequestContext",
    "Transport",
    "UdpTransport",
]
