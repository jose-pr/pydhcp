"""The state and policy constants every `DHCPServer` layer reads."""

from __future__ import annotations

import ipaddress as _ipaddress
import typing as _ty


from .._clock import _Timed
from .._metrics import DHCPMetrics
from ..listener._limit import _LogLimit
from ..lease import LeaseBackend
from ..packet import _enums as _enum

_BACKEND_METHODS = ("allocate", "offer", "commit", "lookup", "release", "renew")


def _check_backend(backend: object) -> None:
    """Refuse a lease backend that lacks a method of `LeaseBackend`, naming each.

    Without this a backend that lacks `offer` and `commit` fails on the first
    DHCPDISCOVER, in a handler, with an `AttributeError` that names no interface.
    """
    missing = [
        name for name in _BACKEND_METHODS if not callable(getattr(backend, name, None))
    ]
    if missing:
        raise TypeError(
            f"lease_backend {type(backend).__name__} does not implement "
            f"LeaseBackend: it has no {', '.join(missing)} "
            "(see pydhcp.lease.LeaseBackend)"
        )


class _ServerState(_Timed):
    """Constants and per-instance state shared by the server layers.

    The server's rules are composed of layers, each subclassing the last --
    `_ServerState`, `_LeasePolicy`, `_Replies`, `_Handlers` -- so each is
    type-checked against exactly what it uses. A subclass overriding a
    constant or a method does so on `DHCPServer` as before. None of them owns
    a socket, a thread or a clock: the listener driver the server is composed
    with supplies `metrics`, the contexts and the time.
    """

    metrics: DHCPMetrics
    #: The listener's limit on lines a sender can provoke.
    _log_limit: _LogLimit

    DEFAULT_PORTS: _ty.Sequence[int] = (_enum.DHCPPort.SERVER,)

    #: How long a DHCPDECLINEd address stays out of the pool.
    DECLINE_QUARANTINE_SECONDS: float = 600.0

    #: Upper bound on quarantined addresses, so a DECLINE flood cannot grow
    #: memory without limit. At the bound an entry that has run out is dropped
    #: and, failing that, a new address is refused (counted in
    #: `quarantines_refused`): a flood does not push a genuine report out.
    MAX_DECLINED_ADDRESSES = 1024

    #: Whether to unicast a reply to a client that has no address yet.
    #:
    #: RFC 2131 4.1 says the server unicasts OFFER/ACK "to the client's hardware
    #: address and 'yiaddr'" when the client leaves the broadcast flag clear.
    #: That is an L2 send: the client cannot answer ARP for an address it has not
    #: been given, so on a plain UDP socket the kernel drops the reply with no
    #: error at all. Measured against ISC dhclient 4.4.3 on a veth pair: every
    #: OFFER was logged as sent to yiaddr:68 and the client saw none of them,
    #: retransmitting DISCOVER until it gave up. Broadcasting is how the reply
    #: actually arrives. Set this True only with a transport that can address the
    #: client's hardware address directly (a raw/AF_PACKET socket), or where the
    #: neighbour entry is installed out of band.
    UNICAST_TO_UNCONFIGURED_CLIENT = False

    #: Lease length granted when the client asks for none.
    DEFAULT_LEASE_SECONDS: float = 3600

    #: Upper bound on a client-requested lease time. Without one, a client that
    #: asks for 0xFFFFFFFE holds the address until 2162.
    MAX_LEASE_SECONDS: float = 86400

    #: How long an address offered in a DHCPOFFER is held for the client
    #: that was offered it, in seconds. A client that does not REQUEST it
    #: in that time loses it, so a DHCPDISCOVER from a forged identity
    #: holds an address for this long and no longer.
    OFFER_HOLD_SECONDS: float = 120.0

    #: Lower bound, so a client cannot ask for a one-second lease and turn
    #: itself into a renewal flood.
    MIN_LEASE_SECONDS: float = 60

    #: Whether to grant an actually-infinite lease when a client sends the
    #: RFC 2132 s3.3 sentinel. Off by default: an address that is never
    #: reclaimed is a policy decision, not something a client gets to take.
    ALLOW_INFINITE_LEASE = False

    def _init_server_state(
        self, lease_backend: _ty.Optional[LeaseBackend] = None
    ) -> None:
        """Set up the state every server driver needs.

        Each driver's constructor takes its own listener arguments and calls
        this for the rest, so the two cannot drift apart.
        """
        from ..lease import InMemoryLeaseBackend

        # `is None`, not truthiness: a backend that reports its size through
        # `__len__` is falsy while it is empty, and is still the caller's.
        if lease_backend is not None:
            _check_backend(lease_backend)
        self._owns_backend = lease_backend is None
        self.lease_backend = (
            InMemoryLeaseBackend() if lease_backend is None else lease_backend
        )
        #: Address -> the `time.monotonic()` second its quarantine ends.
        self._declined: _ty.Dict[_ipaddress.IPv4Address, float] = {}

    def _close_owned_backend(self) -> None:
        """Close the backend this server created; one it was given is the caller's."""
        if not self._owns_backend:
            return
        close = getattr(self.lease_backend, "close", None)
        if callable(close):
            close()
