"""Lease policy: which interface serves, what to allocate, for how long, and who holds what."""

from __future__ import annotations

import ipaddress as _ipaddress
import logging as _logging
import datetime as _dt
import netimps as _netimps
import time as _time
import typing as _ty

from .. import _constants as _const, _network as _net
from ..lease import DHCPLease, LeaseBackend
from ..options._codes import DHCPOptionCode
from ..options import DHCPOptions
from ..options import _codecs as _type
from ..packet._message import DHCPMessage
from math import inf as _inf
from ._state import _ServerState

__all__: list[str] = []

LOGGER = _logging.getLogger(__name__)


def _servable_interface(
    server_id: _ipaddress.IPv4Address,
) -> _ty.Optional[_net.NetworkInterface]:
    """The host IPv4 interface holding `server_id`, or None if there is none to
    serve from -- in which case there is no network to derive a lease from.

    The APIPA exclusion is spelled out here rather than left to
    `host_ip_interfaces`' default, because passing a predicate **replaces** that
    default rather than composing with it. That is documented behaviour of the
    enumerator and it silently un-filtered this path: measured, looking up a
    link-local address returned the adapter holding it. A server whose interface
    holds only a 169.254/16 address would then have allocated leases from that
    network, which RFC 3927 s1.5 excludes from DHCP assignment -- an address in
    that range is self-assigned by definition, so a lease for one collides with
    whatever already picked it.

    `_is_our_server_id` asks a *different* question -- "do we hold this address
    at all" -- and deliberately does not filter, because identity is not
    selection.
    """
    # Asked of every allocating and every DHCPINFORM packet, so through
    # netimps' enumeration cache: measured before any cache, the enumeration
    # was 1181 us of a 1539 us `handle()` on a DHCPDISCOVER. Deliberately not
    # answered from `context.interface`: `_resolve_interface` never returns
    # None -- it invents an `unknown[<ip>]` /32 -- and the allocator reads
    # SUBNET_MASK and BROADCAST_ADDRESS off this interface, so substituting it
    # would hand a client a 255.255.255.255 mask. None keeps the server silent.
    return next(
        _net.host_ip_interfaces(
            lambda interface: interface.ip == server_id
            and interface.ip not in _netimps.LINK_LOCAL_V4,
            cache=True,
        ),
        None,
    )


class _NonExtendingBackend:
    """A lease backend view that will not push an existing lease further out.

    RFC 2131 s4.3.1 makes DHCPDISCOVER a probe: the server checks for a binding
    and offers it, but nothing is agreed until the client REQUESTs. `renew` ran
    anyway on that path -- measured: a DISCOVER carrying option 51 = 999999
    pushed an existing 60-second lease twelve days out and incremented
    `leases_renewed`. A DHCPREQUEST about to be NAKed renewed for the same
    reason, so a client asking for the wrong address still got its old address
    held longer, and `FileLeaseBackend` rewrote the file for each such packet.

    Only *extension* is suppressed, which is the whole of the measured defect.
    `allocate` still passes straight through, because reserving the address you
    are about to offer is ordinary server behaviour and the base allocator only
    ever allocates the address the client asked for -- so on the base
    implementation the allocating path is exactly the path that goes on to ACK.
    Suppressing it too would also mean offering an address a full store could
    not actually hand over, turning today's honest silence into an offer
    followed by silence.

    `acquire_lease` reads the store through this view when its `commit`
    argument is false. `__getattr__` forwards `lookup_by_ip` and any
    backend-specific helper so a custom backend keeps working.
    """

    def __init__(self, inner: LeaseBackend) -> None:
        self._inner = inner

    def lookup(self, client_id: str) -> _ty.Optional[DHCPLease]:
        return self._inner.lookup(client_id)

    def allocate(
        self,
        client_id: str,
        ip: _ipaddress.IPv4Address,
        ttl: float,
        options: _ty.Optional[DHCPOptions] = None,
    ) -> _ty.Optional[DHCPLease]:
        return self._inner.allocate(client_id, ip, ttl, options)

    def renew(self, client_id: str, ttl: float) -> _ty.Optional[DHCPLease]:
        """Report the binding as it stands, unextended and unwritten.

        Returning the very object `lookup` gave is what lets `acquire_lease`
        tell a real renewal from this one without knowing which backend it is
        talking to -- see the identity check there.
        """
        return self._inner.lookup(client_id)

    def release(self, client_id: str) -> bool:
        return False

    def __getattr__(self, name: str) -> _ty.Any:
        return getattr(self._inner, name)


class _LeasePolicy(_ServerState):
    """Allocation, lease time, address ownership, quarantine and release."""

    def lease_seconds(self, msg: DHCPMessage) -> float:
        """Lease length to grant for `msg`, applying this server's policy.

        RFC 2131 s4.3.1 lets the server honour a client's requested lease time
        only "if acceptable to local policy" -- a MAY, so there has to be a
        policy. There was none: the requested value went straight through, and
        any client could hold an address for 136 years by asking for one.

        RFC 2132 s3.3 also makes 0xFFFFFFFF mean *infinity*, not 4294967295
        seconds. Taken literally it became a finite expiry in 2162, and the
        reply then advertised 4294967294 -- a different number than the client
        asked for, one second short of the sentinel.

        Override this, or set the class attributes, to change the policy.
        """
        requested = msg.options.get(
            DHCPOptionCode.IP_ADDRESS_LEASE_TIME, decode=_type.U32
        )
        if requested is None:
            return float(self.DEFAULT_LEASE_SECONDS)
        value = int(requested)
        if value == _const.INFINITE_LEASE_TIME:
            return _inf if self.ALLOW_INFINITE_LEASE else float(self.MAX_LEASE_SECONDS)
        return float(max(self.MIN_LEASE_SECONDS, min(value, self.MAX_LEASE_SECONDS)))

    def _is_our_server_id(
        self,
        server_id: _ipaddress.IPv4Address,
        actual_server_id: _ipaddress.IPv4Address,
    ) -> bool:
        """Whether option 54 names *this* server, on any of its addresses.

        It used to be compared against the receiving interface alone, so on a
        host with two addresses on one broadcast domain -- a secondary IP, or
        two NICs on one VLAN, which is the Windows default binding and what
        `per_interface=True` produces -- both sockets saw the client's broadcast
        REQUEST. Socket A ACKed; socket B then read the same option 54 as a
        *foreign* server and deleted the binding the client had just accepted,
        freeing the address for someone else. Measured on a three-address host:
        the binding was present after A and gone after B.

        The lease backend is shared across every socket, so the comparison has
        to be against every address this host holds, not the one the packet
        happened to arrive on.
        """
        if server_id == actual_server_id:
            return True
        # "Do we hold this address at all" -- loopback or assigned to a local
        # adapter, link-local included -- which is exactly netimps'
        # `is_local_address`. Not `host_ip_interfaces()`: its default filter
        # hides APIPA, and identity is not selection.
        return bool(_netimps.is_local_address(server_id, cache=True))

    @staticmethod
    def _has_time_left(lease: DHCPLease) -> bool:
        """Whether `lease` still has a lease time worth advertising.

        `_create_response` sets yiaddr and option 51 only when the remaining
        time is positive, but sent the reply either way -- so a lease that had
        expired within the second produced a DHCPACK carrying neither an address
        nor a lease time. RFC 2131 Table 3 makes option 51 a MUST in an ACK to a
        REQUEST; clients either reject that reply or configure 0.0.0.0.

        `lease_seconds` enforces MIN_LEASE_SECONDS, so the base server cannot
        reach this. An overriding `acquire_lease` can, which is exactly why the
        check lives on the reply path rather than in the allocator.
        """
        expires = lease.expires
        if expires is None:
            return False
        if expires == _inf or not isinstance(expires, _dt.datetime):
            return True
        return (expires - _dt.datetime.now()).total_seconds() > 0

    def acquire_lease(
        self,
        client_id: str,
        server_id: _ipaddress.IPv4Address,
        msg: DHCPMessage,
        *,
        commit: bool = True,
    ) -> _ty.Optional[DHCPLease]:
        """Return a lease for a client message.

        This is the extension point for address pools, reservations, policy
        checks and custom response options. It is an ordinary method of this
        server, called on the server itself from the handler thread (the one
        worker thread on the async server), so an attribute it keeps -- the
        next free host, a cache -- is the server's own.

        `commit` says what kind of call this is. False: the server is deciding
        what to offer or whether to ACK (RFC 2131 s4.3.1 makes DHCPDISCOVER a
        probe), so the call must not extend an existing binding or add state
        that a client declining the offer would leave behind. True: the answer
        is being committed. A DHCPDISCOVER makes one call with `commit=False`; a
        DHCPREQUEST makes two, `commit=False` to decide and then `commit=True`
        if it is ACKed. An override honours `commit` itself, including in what
        it does to `self.lease_backend`, which is the real backend on both
        calls: only this base implementation reads through a view that does not
        extend a binding when `commit` is false.

        The base implementation is intentionally small: it renews existing
        leases and allocates only when the client supplies `REQUESTED_IP` or
        `ciaddr`.
        """
        _server = _servable_interface(server_id)
        if _server is None:
            return None

        backend = (
            self.lease_backend
            if commit
            else _ty.cast(LeaseBackend, _NonExtendingBackend(self.lease_backend))
        )
        existing = backend.lookup(client_id)
        if existing:
            renewed = backend.renew(client_id, self.lease_seconds(msg))
            if renewed:
                # `_NonExtendingBackend.renew` hands back the object `lookup`
                # returned, so identity is what separates a real renewal from a
                # probe that merely looked. Counting the probe is how a DISCOVER
                # came to inflate `leases_renewed`.
                if renewed is not existing:
                    self.metrics.leases_renewed += 1
                return renewed
            return existing

        requested_ip = msg.options.get(
            DHCPOptionCode.REQUESTED_IP, decode=_type.IPv4AddressOption
        )
        ttl = self.lease_seconds(msg)

        ip: _ty.Optional[_ipaddress.IPv4Address] = None
        if requested_ip:
            ip = requested_ip
        elif msg.ciaddr != _const.WILDCARD_V4:
            ip = msg.ciaddr

        if ip is None:
            return None

        refusal = self._address_refusal(ip, _server, client_id)
        if refusal is not None:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Refusing {ip} for {client_id}: {refusal}"
            )
            return None

        options = DHCPOptions()
        options[DHCPOptionCode.SUBNET_MASK] = _server.network.netmask
        options[DHCPOptionCode.BROADCAST_ADDRESS] = _server.network.broadcast_address
        # No ROUTER and no DNS. They used to be set to this host's own address,
        # which is a guess and usually a wrong one: running the server on an
        # ordinary machine then told every client to send all off-link traffic
        # and every name lookup to a host that routes and resolves nothing.
        # Omitting them leaves the client with whatever it already has -- a
        # statically configured resolver, another router on the segment -- which
        # is recoverable, where being pointed at a black hole is not.
        # Override `acquire_lease` to supply the real ones.

        LOGGER.debug(f"[XID={msg.xid:08x}] Allocating {ip} for {client_id}")
        lease = backend.allocate(client_id, ip, ttl, options)
        if lease is not None:
            self.metrics.leases_allocated += 1
        return lease

    def _address_refusal(
        self,
        ip: _ipaddress.IPv4Address,
        interface: _net.NetworkInterface,
        client_id: str,
    ) -> _ty.Optional[str]:
        """Say why `ip` must not be handed to `client_id`, or None if it may be.

        The base allocator takes the client's requested address, and took it on
        trust: any client could claim the server's own address, the broadcast
        address, something on a different subnet, or an address another client is
        already using -- and the server would record the binding and confirm it.
        """
        network = interface.network
        if ip not in network:
            return f"outside the served network {network}"
        if ip == interface.ip:
            return "this is the server's own address"
        if network.prefixlen < 31:
            # /31 and /32 have no network or broadcast address to reserve
            # (RFC 3021), so the check would wrongly exclude both usable hosts.
            if ip == network.network_address:
                return "this is the network address"
            if ip == network.broadcast_address:
                return "this is the broadcast address"

        declined_until = self._declined.get(ip)
        if declined_until is not None:
            if declined_until > _time.monotonic():
                return "address is quarantined after a DHCPDECLINE"
            del self._declined[ip]

        lookup_by_ip = getattr(self.lease_backend, "lookup_by_ip", None)
        if lookup_by_ip is not None:
            holder = lookup_by_ip(ip)
            if holder is not None and holder != client_id:
                return f"already leased to {holder}"
        return None

    def quarantine_address(self, ip: _ipaddress.IPv4Address) -> None:
        """Stop offering `ip` for `DECLINE_QUARANTINE_SECONDS`.

        RFC 2131 4.3.3: a DHCPDECLINE says the client found the address already
        in use, so the server MUST NOT hand it out again. Releasing the binding
        alone left it first in line to be offered to the next client, which
        would collide with whatever is really using it. The map is bounded, and
        entries expire, so a DECLINE flood cannot exhaust memory or permanently
        consume a pool.
        """
        self._declined[ip] = _time.monotonic() + self.DECLINE_QUARANTINE_SECONDS
        self._declined.move_to_end(ip)
        while len(self._declined) > self.MAX_DECLINED_ADDRESSES:
            self._declined.popitem(last=False)

    def release_lease(
        self, client_id: str, server_id: _ipaddress.IPv4Address, msg: DHCPMessage
    ) -> bool:
        """Release any lease associated with `client_id`; True if one went away.

        Override this method when lease release needs to update an external store
        or emit custom audit records. Quarantining a declined address is handled
        by `quarantine_address`, which `handle_decline` calls before this.

        Counting is the *caller's* job, not this method's, because only the
        caller knows why: an orderly DHCPRELEASE, a DHCPDECLINE reporting an
        address conflict, and a reclaim after the client chose another server
        are three different events that all arrive here.
        """
        return self.lease_backend.release(client_id)

    def get_inform_options(
        self, server_id: _ipaddress.IPv4Address, msg: DHCPMessage
    ) -> DHCPOptions:
        """Return configuration options for DHCPINFORM responses.

        DHCPINFORM does not allocate an address. Override this method when clients
        should receive site-specific options without touching lease allocation.
        """
        options = DHCPOptions()
        _server = _servable_interface(server_id)
        if _server is not None:
            options[DHCPOptionCode.SUBNET_MASK] = _server.network.netmask
            options[DHCPOptionCode.BROADCAST_ADDRESS] = (
                _server.network.broadcast_address
            )
            # As in `acquire_lease`: this host is not known to be a router or a
            # resolver, so it does not claim to be either.
        return options
