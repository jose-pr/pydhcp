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

from .._metrics import DHCPMetrics
from ._asyncio import AsyncDHCPListener
from ._receive import DHCPRequestContext
from ._spec import ListenLike
from ._sync import DHCPListener
from ._transport import (
    BROADCAST_ADDRESS,
    PktInfoUDPTransport,
    DHCPTransport,
    UDPTransport,
)

__all__ = [
    "AsyncDHCPListener",
    "BROADCAST_ADDRESS",
    "DHCPListener",
    "DHCPMetrics",
    "ListenLike",
    "PktInfoUDPTransport",
    "DHCPRequestContext",
    "DHCPTransport",
    "UDPTransport",
]
