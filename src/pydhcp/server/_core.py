"""The server's rules: allocation, lease policy, replies and one handler per message type.

No socket, thread, loop or clock lives here. A listener driver (`_sync`,
`_asyncio`) receives a datagram, decodes it, stamps the context with the time
it arrived and calls `handle()`; a reply leaves through the transport the
context carries.
"""

from __future__ import annotations

from ._handlers import _Handlers

__all__: list[str] = []


class _ServerCore(_Handlers):
    """Everything a `DHCPServer` or an `AsyncDHCPServer` does that is not I/O.

    Override any method or constant on the public class as before: the hooks
    (`handle_discover`, `handle_request`, `handle_decline`, `handle_release`,
    `handle_inform`, `acquire_lease`, `release_lease`, `get_inform_options`,
    `get_lease_seconds`, `quarantine_address`) run synchronously on the one handler
    thread of either driver.
    """
