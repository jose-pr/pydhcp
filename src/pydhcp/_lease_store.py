"""The lease store contract and the in-memory store (public as `pydhcp.lease`)."""

from __future__ import annotations

import logging as _logging
import datetime as _dt
import ipaddress as _ipaddress
import time as _time
import threading as _threading
import typing as _ty
from math import inf as _inf

from ._lease import DHCPLease
from .options import DHCPOptions

__all__ = ["InMemoryLeaseBackend", "LeaseBackend"]

LOGGER = _logging.getLogger(__name__)


class LeaseBackend(_ty.Protocol):
    """Where leases live. `ttl` is seconds, or `math.inf` for no expiry (a lease
    whose `expires` is `None`).

    A client's record is in one of two states, told apart by `DHCPLease.offered`.
    **Offered**: the address is held for that client for `hold_seconds` after a
    DHCPDISCOVER, and `expires` is the end of the hold. **Bound**: the client
    accepted it, and `expires` is the end of the lease. An offer that is not
    committed in time is an expired record: `lookup` returns `None` for it and
    the address is free for another client. Every method is atomic against the
    others, and each treats a record whose `expires` has passed as absent.

    `ttl` is typed `float` rather than `int` because `math.inf` is a float and
    the implementations have always accepted it. An `int` is still accepted:
    every int is a float to the type system.
    """

    def allocate(
        self,
        client_id: str,
        ip: _ipaddress.IPv4Address,
        ttl: float,
        options: _ty.Optional[DHCPOptions] = None,
    ) -> _ty.Optional[DHCPLease]:
        """An offer and its commit in one call: a bound lease for `ttl`.

        Replaces whatever record `client_id` has. `None` when another client
        holds `ip`, or when the store is full and `client_id` is new.
        """
        ...

    def offer(
        self,
        client_id: str,
        ip: _ipaddress.IPv4Address,
        hold_seconds: float,
        options: _ty.Optional[DHCPOptions] = None,
    ) -> _ty.Optional[DHCPLease]:
        """Hold `ip` for `client_id` for `hold_seconds` and return the offered lease.

        `None` when another client holds `ip` (offered or bound), when the store
        is full and `client_id` is new, or when `client_id` holds a bound lease
        on another address (an offer never replaces a binding). A client that
        holds a bound lease on `ip` is returned that lease unchanged. A client
        with an outstanding offer has it replaced.
        """
        ...

    def commit(self, client_id: str, ttl: float) -> _ty.Optional[DHCPLease]:
        """Turn the client's offered lease into a bound one lasting `ttl`.

        `None` when the client has no offered lease (none, expired, or already
        bound).
        """
        ...

    def lookup(self, client_id: str) -> _ty.Optional[DHCPLease]:
        """The client's lease, offered or bound, or `None`."""
        ...

    def release(self, client_id: str) -> bool:
        """Drop the client's record, in either state; whether there was one."""
        ...

    def renew(self, client_id: str, ttl: float) -> _ty.Optional[DHCPLease]:
        """Extend a **bound** lease to `ttl` from now; `None` for no lease or an offer."""
        ...


class InMemoryLeaseBackend:
    """Leases in a dict, guarded by a re-entrant lock.

    The lock makes each operation atomic against the others: a server started
    with `start()` handles packets on a background thread, the async server on a
    worker thread, and one backend can be shared by several of them. It does
    **not** make a caller's compound operation atomic -- "is this address free,
    and if so allocate it" is two calls, and two threads can still interleave
    across them. Hold `self._lock` around such a sequence if that matters.

    The store is bounded by `MAX_LEASES`. Nothing about a DHCP client is
    authenticated, so a flood of forged client identifiers is otherwise an
    unbounded allocation -- and, for `FileLeaseBackend`, a whole-file rewrite
    per forged identity, which is quadratic.
    """

    #: Upper bound on stored leases. At the cap, expired entries are reclaimed
    #: first and a *new* client is then refused; established bindings are never
    #: evicted to make room. Evicting the least-recently-used would be exactly
    #: backwards under a flood -- the forged identities are the newest, so LRU
    #: would drop the long-lived real clients and keep the attacker's.
    MAX_LEASES = 10_000

    def __init__(self) -> None:
        self._leases: _ty.Dict[str, DHCPLease] = {}
        #: The client holding each address, in either state: `lookup_by_ip`
        #: answers from it instead of walking the store.
        self._by_ip: _ty.Dict[_ipaddress.IPv4Address, str] = {}
        #: Re-entrant: `lookup_by_ip` and `renew` call `lookup` while holding it.
        self._lock = _threading.RLock()
        #: New clients turned away because the store was full. Visible so an
        #: operator can tell "nobody is asking" from "everybody is refused".
        self.refused_while_full = 0
        self._last_full_log = float("-inf")

    def _now(self) -> _dt.datetime:
        """The instant every expiry is read on: aware, UTC."""
        return _dt.datetime.now(_dt.timezone.utc)

    def _put(self, client_id: str, lease: DHCPLease) -> None:
        """Store `lease` for `client_id` and keep the address index true."""
        leases = self._leases
        old = leases.get(client_id)
        if old is not None and self._by_ip.get(old.ip) == client_id:
            del self._by_ip[old.ip]
        leases[client_id] = lease
        self._by_ip[lease.ip] = client_id

    def _drop(self, client_id: str) -> _ty.Optional[DHCPLease]:
        """Remove `client_id`'s record and its index entry; the record, if any."""
        old = self._leases.pop(client_id, None)
        if old is not None and self._by_ip.get(old.ip) == client_id:
            del self._by_ip[old.ip]
        return old

    def _other_holder(
        self, client_id: str, ip: _ipaddress.IPv4Address
    ) -> _ty.Optional[str]:
        """The client other than `client_id` holding `ip`, in either state."""
        holder = self.lookup_by_ip(ip)
        return holder if holder is not None and holder != client_id else None

    def allocate(
        self,
        client_id: str,
        ip: _ipaddress.IPv4Address,
        ttl: float,
        options: _ty.Optional[DHCPOptions] = None,
    ) -> _ty.Optional[DHCPLease]:
        with self._lock:
            if self._other_holder(client_id, ip) is not None:
                return None
            if self.lookup(client_id) is None and not self._make_room():
                self._report_full()
                return None
            lease = DHCPLease(ip=ip, expires=self._expiry(ttl), options=options)
            self._put(client_id, lease)
            return lease

    def offer(
        self,
        client_id: str,
        ip: _ipaddress.IPv4Address,
        hold_seconds: float,
        options: _ty.Optional[DHCPOptions] = None,
    ) -> _ty.Optional[DHCPLease]:
        if not 0 < hold_seconds < _inf:
            raise ValueError(
                f"an offer is held for a finite positive time, not {hold_seconds!r}"
            )
        with self._lock:
            if self._other_holder(client_id, ip) is not None:
                return None
            existing = self.lookup(client_id)
            if existing is not None and not existing.offered:
                return existing if existing.ip == ip else None
            if existing is None and not self._make_room():
                self._report_full()
                return None
            lease = DHCPLease(
                ip=ip,
                expires=self._expiry(hold_seconds),
                options=options,
                offered=True,
            )
            self._put(client_id, lease)
            return lease

    def commit(self, client_id: str, ttl: float) -> _ty.Optional[DHCPLease]:
        with self._lock:
            lease = self.lookup(client_id)
            if lease is None or not lease.offered:
                return None
            bound = lease.replace(expires=self._expiry(ttl), offered=False)
            self._put(client_id, bound)
            return bound

    def _expiry(self, ttl: float) -> _ty.Optional[_dt.datetime]:
        """The instant `ttl` seconds from now, or `None` for no expiry."""
        if ttl == _inf:
            return None
        return self._now() + _dt.timedelta(seconds=ttl)

    #: Seconds between "store is full" reports. The condition is reached once
    #: per refused packet, and the thing that fills the store is a flood -- so
    #: logging each one hands the attacker the log as a second target, which is
    #: the trap the per-packet unknown-htype warning fell into.
    FULL_LOG_INTERVAL_SECONDS = 60.0

    def _report_full(self) -> None:
        """Report a full store at most once per interval. Caller holds the lock."""
        self.refused_while_full += 1
        now = _time.monotonic()
        if now - self._last_full_log < self.FULL_LOG_INTERVAL_SECONDS:
            return
        self._last_full_log = now
        LOGGER.warning(
            f"Lease store is full ({len(self._leases)}/{self.MAX_LEASES}); refusing "
            f"new clients. {self.refused_while_full} refused so far. Established "
            "bindings are kept; raise MAX_LEASES if this is legitimate demand."
        )

    def _make_room(self) -> bool:
        """Whether there is room for one more client. Caller holds the lock.

        Reclaims expired leases before answering: under a flood most of the
        store is forged entries that expire on their own, so a sweep usually
        makes room without touching anyone real.
        """
        if len(self._leases) < self.MAX_LEASES:
            return True
        now = self._now()
        for client_id in list(self._leases):
            expires = self._leases[client_id].expires
            if expires is not None and expires <= now:
                self._drop(client_id)
        return len(self._leases) < self.MAX_LEASES

    def lookup(self, client_id: str) -> _ty.Optional[DHCPLease]:
        with self._lock:
            lease = self._leases.get(client_id)
            if lease is None:
                return None
            # `<=`, not `<`: a lease whose expiry instant has arrived is over,
            # not live for one more tick. With `<`, a zero-second TTL survived
            # whenever both clock reads landed in the same tick, which the
            # coarse clock of the 3.9 floor makes routine.
            if lease.expires is not None and lease.expires <= self._now():
                self._drop(client_id)
                return None
            return lease

    def lookup_by_ip(self, ip: _ipaddress.IPv4Address) -> _ty.Optional[str]:
        """Return the client currently holding `ip`, offered or bound, if any.

        Optional backend extension, not part of the `LeaseBackend` Protocol: a
        backend that does not provide it simply skips the allocator's
        already-in-use check. Answered from an index, so the cost does not grow
        with the number of leases.
        """
        with self._lock:
            self._leases  # a file-backed store loads here, before the index is read
            client_id = self._by_ip.get(ip)
            if client_id is None:
                return None
            lease = self.lookup(client_id)
            if lease is not None and lease.ip == ip:
                return client_id
            return None

    def release(self, client_id: str) -> bool:
        return self._release(client_id) is not None

    def _release(self, client_id: str) -> _ty.Optional[DHCPLease]:
        with self._lock:
            return self._drop(client_id)

    def renew(self, client_id: str, ttl: float) -> _ty.Optional[DHCPLease]:
        with self._lock:
            lease = self.lookup(client_id)
            if lease is None or lease.offered:
                return None
            renewed = lease.replace(expires=self._expiry(ttl))
            self._put(client_id, renewed)
            return renewed
