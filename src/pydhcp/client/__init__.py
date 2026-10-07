"""The DHCPv4 client: `DHCPClient` on threads and `AsyncDHCPClient` on an event loop."""

from __future__ import annotations

import typing as _ty

from ._core import ClientIdentifierLike
from ._sync import DHCPClient
from .._lazy import bind as _bind

if _ty.TYPE_CHECKING:
    from ._asyncio import AsyncDHCPClient

#: Bound on first use: the module that defines it imports asyncio.
_ASYNCIO = {"AsyncDHCPClient": "._asyncio"}

__all__ = [
    "AsyncDHCPClient",
    "ClientIdentifierLike",
    "DHCPClient",
]


def __getattr__(name: str) -> _ty.Any:
    """Bind an asyncio class on first use, so importing this package does not import asyncio."""
    return _bind(__name__, globals(), _ASYNCIO, name)


def __dir__() -> "list[str]":
    return sorted(set(globals()) | set(__all__))
