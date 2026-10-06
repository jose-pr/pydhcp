"""The DHCP server: `DHCPServer` on threads and `AsyncDHCPServer` on an event loop."""

from __future__ import annotations

import netimps as _netimps

from .. import _network as _net
from ._asyncio import AsyncDHCPServer
from ._policy import _servable_interface
from ._sync import DHCPServer

# `_net` and `_netimps` are the shared module objects: a test patches an attribute
# through them and the patch reaches every layer of the server.

__all__ = ["AsyncDHCPServer", "DHCPServer"]
