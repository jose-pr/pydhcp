"""The DHCP relay agent: `DHCPRelay` on threads and `AsyncDHCPRelay` on an event loop."""

from __future__ import annotations

import typing as _ty

from ._core import (
    DEFAULT_MAX_HOPS,
    RFC1542_MAX_HOPS,
    ServerAddressLike,
)
from ._sync import DHCPRelay
from .._lazy import bind as _bind

if _ty.TYPE_CHECKING:
    from ._asyncio import AsyncDHCPRelay

#: Bound on first use: the module that defines it imports asyncio.
_ASYNCIO = {"AsyncDHCPRelay": "._asyncio"}

__all__ = [
    "AsyncDHCPRelay",
    "DEFAULT_MAX_HOPS",
    "DHCPRelay",
    "RFC1542_MAX_HOPS",
    "ServerAddressLike",
]


def __getattr__(name: str) -> _ty.Any:
    """Bind an asyncio class on first use, so importing this package does not import asyncio."""
    return _bind(__name__, globals(), _ASYNCIO, name)


def __dir__() -> "list[str]":
    return sorted(set(globals()) | set(__all__))
