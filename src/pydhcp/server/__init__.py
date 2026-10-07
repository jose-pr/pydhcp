"""The DHCP server: `DHCPServer` on threads and `AsyncDHCPServer` on an event loop."""

from __future__ import annotations

import typing as _ty

import netimps as _netimps

# `_net` and `_netimps` are the shared module objects: a test patches an attribute
# through them and the patch reaches every layer of the server.
from .. import _network as _net
from .._lazy import bind as _bind
from ._policy import _servable_interface
from ._sync import DHCPServer

if _ty.TYPE_CHECKING:
    from ._asyncio import AsyncDHCPServer

#: Bound on first use: the module that defines it imports asyncio.
_ASYNCIO = {"AsyncDHCPServer": "._asyncio"}

__all__ = ["AsyncDHCPServer", "DHCPServer"]


def __getattr__(name: str) -> _ty.Any:
    """Bind an asyncio class on first use, so importing this package does not import asyncio."""
    return _bind(__name__, globals(), _ASYNCIO, name)


def __dir__() -> "list[str]":
    return sorted(set(globals()) | set(__all__))
