"""The relay's table of forwarded requests: the port a reply has to go to.

A reply carries `xid` and `chaddr` but not the port the client's request came
from. A client on the standard port 68 needs no entry, so the table holds only
the clients that are not on it (a harness, an unusual deployment), and a reply
for an exchange with no entry goes to port 68. The interface a reply leaves by
is not remembered here: the reply's `giaddr` names it.

At the cap the oldest entry is evicted. An evicted entry costs one client's
replies the port, nothing else; a flood from port 68 occupies no entry at all.
"""

from __future__ import annotations

import logging as _logging
import typing as _ty

from .._clock import _Timed
from .._metrics import DHCPMetrics
from ..listener._limit import _LogLimit
from ..listener._receive import DHCPRequestContext
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage
from .. import _network as _net

LOGGER = _logging.getLogger(__name__)


class PendingClient(_ty.NamedTuple):
    """The client a request was forwarded for, when it is not on port 68."""

    client: _net.SocketAddress
    #: When it was recorded, on the monotonic clock. The table is written in
    #: this order, so the oldest entry is the first.
    recorded_at: float


class _PendingClients(_Timed):
    """The pending table and its bounds, under the relay's rules."""

    metrics: DHCPMetrics
    _log_limit: _LogLimit

    #: Upper bound on in-flight `xid -> client address` entries.
    MAX_PENDING_CLIENTS = 1024

    #: How long a recorded client stays usable. An exchange is over in seconds,
    #: so this only has to outlive a retransmit; entries are kept rather than
    #: popped on the first reply, because several configured servers each send
    #: one and they all go to the same client.
    PENDING_TTL_SECONDS = 60.0

    def _init_pending(self) -> None:
        self._pending_clients: _ty.OrderedDict[tuple[int, bytes], PendingClient] = (
            _ty.OrderedDict()
        )

    def _pending_key(self, msg: DHCPMessage) -> tuple[int, bytes]:
        """Identify an exchange by transaction *and* client.

        The xid alone is not an identity: it travels in cleartext in a broadcast
        DISCOVER, so any host on the segment can read it and send its own
        request carrying the same one. Keyed by xid alone, that overwrote the
        victim's entry and the relay then sent the victim's OFFER to the
        attacker's port -- the victim never saw it.
        """
        return msg.xid, bytes(msg.chaddr[: msg.hlen or len(msg.chaddr)])

    def _record_pending(self, msg: DHCPMessage, context: DHCPRequestContext) -> bool:
        """Note the port a reply for this exchange has to go to; whether to forward.

        A request that reuses the transaction of a live entry from a different
        source address is refused (`False`): it is neither recorded nor
        forwarded, and counted. The same address with another port replaces the
        entry, since an unconfigured client has source address 0.0.0.0 and the
        address is all that tells a client with a new socket from another host.
        """
        key = self._pending_key(msg)
        now = self._instant(context).monotonic
        self._expire_pending(now)
        existing = self._pending_clients.get(key)
        if existing is not None and existing.client.ip != context.client.ip:
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "reused transaction",
                "[XID=%08x] Dropping a request from %s that reuses the "
                "transaction of %s",
                msg.xid,
                context.client,
                existing.client,
                now=now,
            )
            self.metrics.packets_dropped_reused_transaction += 1
            return False
        if context.client.port == _enum.DHCPPort.CLIENT:
            self._pending_clients.pop(key, None)
            return True
        self._pending_clients[key] = PendingClient(context.client, now)
        self._pending_clients.move_to_end(key)
        self._expire_pending(now)
        return True

    def _lookup_pending(
        self, msg: DHCPMessage, now: float
    ) -> _ty.Optional[PendingClient]:
        """Find where this reply goes, leaving the entry for any further ones.

        Popping on the first reply meant that with more than one server
        configured, the second server's reply had lost the tracked port and fell
        back to 68 -- so which reply reached the client depended on which server
        answered first.

        `now` is seconds on the monotonic clock, the one the table is kept on.
        """
        self._expire_pending(now)
        return self._pending_clients.get(self._pending_key(msg))

    def _expire_pending(self, now: float) -> None:
        """Drop the entries past their TTL, oldest first, then any over the cap.

        The table is ordered by `recorded_at`, so this stops at the first live
        entry and costs the same whatever a flood left in the table.
        """
        table = self._pending_clients
        while table:
            oldest = next(iter(table.values()))
            if now - oldest.recorded_at < self.PENDING_TTL_SECONDS:
                break
            table.popitem(last=False)
        while len(table) > self.MAX_PENDING_CLIENTS:
            table.popitem(last=False)
