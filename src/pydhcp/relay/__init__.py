"""The DHCP relay agent: `DHCPRelay` on threads and `AsyncDHCPRelay` on an event loop."""

from __future__ import annotations

from ._asyncio import AsyncDHCPRelay
from ._core import (
    DEFAULT_MAX_HOPS,
    RFC1542_MAX_HOPS,
    ServerAddress,
)
from ._sync import DHCPRelay

__all__ = [
    "AsyncDHCPRelay",
    "DEFAULT_MAX_HOPS",
    "DHCPRelay",
    "RFC1542_MAX_HOPS",
    "ServerAddress",
]
