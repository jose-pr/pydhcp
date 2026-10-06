"""The relay's table of forwarded requests: where each reply has to go.

A reply carries `xid` and `chaddr` but never the port the client's request came
from, so the relay remembers, per exchange, the client it forwarded for.
"""

from __future__ import annotations

import logging as _logging
import typing as _ty

from .._clock import _Timed
from .._metrics import DHCPMetrics
from ..listener._limit import _LogLimit
from ..listener._receive import DHCPRequestContext
from ..packet._message import DHCPMessage
from .. import _network as _net
import ipaddress as _ipaddress

LOGGER = _logging.getLogger(__name__)


class PendingClient(_ty.NamedTuple):
    """Where a forwarded request came from, so its reply can be sent back there.

    The reply arrives on the *server*-facing interface, but has to leave on the
    client-facing one. On a wildcard bind that is not something the kernel can
    work out: a broadcast would go out the default route and never reach the
    client's segment. The ingress interface recorded here is what pins it back.
    """

    client: _net.SocketAddress
    ifindex: _ty.Optional[int] = None
    local_ip: _ty.Optional[_ipaddress.IPv4Address] = None
    #: When it was recorded, so a stale entry ages out instead of being popped
    #: by whichever reply happens to arrive first.
    recorded_at: float = 0.0


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

    def _record_pending(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Note where a reply for this exchange has to go.

        Recorded for every client, including one on the standard port 68. It is
        tempting to skip those, since 68 is the fallback anyway -- but the entry
        also carries the ingress interface, and that is what pins the reply back
        onto the client's segment on a wildcard bind. Skipping it would send
        every ordinary client's reply out the default route instead.

        An entry is never replaced by a request from a *different* source
        address: that takeover is what this tracking has to survive.
        """
        key = self._pending_key(msg)
        now = self._instant(context).monotonic
        existing = self._pending_clients.get(key)
        if (
            existing is not None
            and existing.client.ip != context.client.ip
            and now - existing.recorded_at < self.PENDING_TTL_SECONDS
        ):
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "reused transaction",
                "[XID=%08x] Ignoring a request from %s that reuses the "
                "transaction of %s",
                msg.xid,
                context.client,
                existing.client,
                now=now,
            )
            return
        self._pending_clients[key] = PendingClient(
            context.client, context.ifindex, context.local_ip, now
        )
        self._pending_clients.move_to_end(key)
        self._expire_pending(now)

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
        """Drop entries past their TTL, then anything over the cap."""
        for key in list(self._pending_clients):
            if now - self._pending_clients[key].recorded_at >= self.PENDING_TTL_SECONDS:
                del self._pending_clients[key]
        while len(self._pending_clients) > self.MAX_PENDING_CLIENTS:
            self._pending_clients.popitem(last=False)
