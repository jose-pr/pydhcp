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

import typing as _ty

from .._lazy import bind as _bind
from .._metrics import DHCPMetrics
from ._receive import DHCPRequestContext
from ._spec import ListenLike
from ._sync import DHCPListener
from ._transport import (
    BROADCAST_ADDRESS,
    PktInfoUDPTransport,
    DHCPTransport,
    UDPTransport,
)

if _ty.TYPE_CHECKING:
    from ._asyncio import AsyncDHCPListener

#: Bound on first use: the module that defines it imports asyncio.
_ASYNCIO = {"AsyncDHCPListener": "._asyncio"}

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


def __getattr__(name: str) -> _ty.Any:
    """Bind an asyncio class on first use, so importing this package does not import asyncio."""
    return _bind(__name__, globals(), _ASYNCIO, name)


def __dir__() -> "list[str]":
    return sorted(set(globals()) | set(__all__))
