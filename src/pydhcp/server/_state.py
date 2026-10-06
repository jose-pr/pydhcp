"""The state and policy constants every `DHCPServer` layer reads."""

from __future__ import annotations

import ipaddress as _ipaddress
import typing as _ty


from ..lease import LeaseBackend
from ..listener import DHCPListener as _Base
from ..packet import _enums as _enum


class _ServerState(_Base):
    """Constants and per-instance state shared by the server layers.

    `DHCPServer` is composed of layers, each subclassing the last --
    `_ServerState`, `_LeasePolicy`, `_Replies`, `_Handlers` -- so each is
    type-checked against exactly what it uses. A subclass overriding a
    constant or a method does so on `DHCPServer` as before.
    """

    DEFAULT_PORTS = (_enum.DHCPPort.SERVER,)

    #: How long a DHCPDECLINEd address stays out of the pool.
    DECLINE_QUARANTINE_SECONDS: float = 600.0

    #: Upper bound on quarantined addresses, so a DECLINE flood cannot grow
    #: memory without limit; the oldest entry is evicted first.
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
        """Set up the state every server variant needs.

        AsyncDHCPServer cannot call this class's `__init__` (its own base takes a
        different argument set), so it re-implemented the body -- and then drifted
        from it: `_declined` was added here and not there, which made every
        DHCPDECLINE an AttributeError on the async server. One method both
        constructors call is what keeps that from happening again.
        """
        from ..lease import InMemoryLeaseBackend

        self.lease_backend = lease_backend or InMemoryLeaseBackend()
        self._declined: _ty.OrderedDict[_ipaddress.IPv4Address, float] = (
            _ty.OrderedDict()
        )
