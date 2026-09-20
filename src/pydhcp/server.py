from __future__ import annotations

import copy as _copy
import math as _math
import socket as _socket
from .packet.message import DhcpMessage, NoClientIdentity
from .listener import DhcpListener as _Base, ListenSpec, RequestContext
from . import constants as _const, network as _net
from .packet import enums as _enum
from .options import DhcpOptionCode, DhcpOptions
from .options import type as _type
from .log import LOGGER
import logging as _logging
import datetime as _dt
import time as _time
import typing as _ty
from math import inf as _inf

from .lease import DhcpLease, LeaseBackend


def _is_loopback(context: RequestContext) -> bool:
    """Whether this exchange is happening over loopback.

    Loopback inverts both halves of the unicast/broadcast trade-off: there is no
    ARP, so a unicast to an address the client has not configured still arrives,
    and POSIX refuses a broadcast from a socket bound to 127.0.0.1 outright
    (Windows allows it, which is how a loopback harness can pass on one platform
    and hang on the other).
    """
    for candidate in (context.local_ip, context.interface.ip, context.client.ip):
        if candidate is not None:
            return bool(candidate.is_loopback)
    return False


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

    The view is swapped in rather than `acquire_lease` being split, because
    `acquire_lease` is the documented extension point for pools and
    reservations: an override must still get to decide what to offer, and must
    still not extend anything while deciding. `__getattr__` forwards
    `lookup_by_ip` and any backend-specific helper so a custom backend keeps
    working.
    """

    def __init__(self, inner: LeaseBackend) -> None:
        self._inner = inner

    def lookup(self, client_id: str) -> _ty.Optional[DhcpLease]:
        return self._inner.lookup(client_id)

    def allocate(
        self,
        client_id: str,
        ip: _net.IPv4,
        ttl: float,
        options: _ty.Optional[DhcpOptions] = None,
    ) -> _ty.Optional[DhcpLease]:
        return self._inner.allocate(client_id, ip, ttl, options)

    def renew(self, client_id: str, ttl: float) -> _ty.Optional[DhcpLease]:
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


class DhcpServer(_Base):
    DEFAULT_PORTS = (_enum.DhcpPort.SERVER,)

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

    def __init__(
        self,
        listen: ListenSpec = None,
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        lease_backend: _ty.Optional[LeaseBackend] = None,
        per_interface: bool | None = None,
    ) -> None:
        super().__init__(
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_server_state(lease_backend)

    def _init_server_state(
        self, lease_backend: _ty.Optional[LeaseBackend] = None
    ) -> None:
        """Set up the state every server variant needs.

        AsyncDhcpServer cannot call this class's `__init__` (its own base takes a
        different argument set), so it re-implemented the body -- and then drifted
        from it: `_declined` was added here and not there, which made every
        DHCPDECLINE an AttributeError on the async server. One method both
        constructors call is what keeps that from happening again.
        """
        from .lease import InMemoryLeaseBackend

        self.lease_backend = lease_backend or InMemoryLeaseBackend()
        self._declined: _ty.OrderedDict[_net.IPv4, float] = _ty.OrderedDict()

    def lease_seconds(self, msg: DhcpMessage) -> float:
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
            DhcpOptionCode.IP_ADDRESS_LEASE_TIME, decode=_type.U32
        )
        if requested is None:
            return float(self.DEFAULT_LEASE_SECONDS)
        value = int(requested)
        if value == _const.INFINITE_LEASE_TIME:
            return _inf if self.ALLOW_INFINITE_LEASE else float(self.MAX_LEASE_SECONDS)
        return float(max(self.MIN_LEASE_SECONDS, min(value, self.MAX_LEASE_SECONDS)))

    @staticmethod
    def _has_time_left(lease: DhcpLease) -> bool:
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

    def _probe_lease(
        self, client_id: str, server_id: _net.IPv4, msg: DhcpMessage
    ) -> _ty.Optional[DhcpLease]:
        """`acquire_lease` on a path that has not agreed anything yet.

        A shallow copy of the server carries the non-extending backend view, so
        an overridden `acquire_lease` -- which reaches the store through
        `self.lease_backend` -- is bound by it too, and nothing is mutated on
        the real server. A copy rather than swapping the attribute in place and
        restoring it: the attribute swap is visible to any other thread handling
        a packet, and the base backend is explicitly documented as shareable
        between several running servers.
        """
        probe = _copy.copy(self)
        probe.lease_backend = _ty.cast(
            LeaseBackend, _NonExtendingBackend(self.lease_backend)
        )
        return probe.acquire_lease(client_id, server_id, msg)

    def acquire_lease(
        self, client_id: str, server_id: _net.IPv4, msg: DhcpMessage
    ) -> _ty.Optional[DhcpLease]:
        """Return a lease for a client message.

        The base implementation is intentionally small: it renews existing leases and
        allocates only when the client supplies `REQUESTED_IP` or `ciaddr`. Override
        this method to implement address pools, reservations, policy checks, or custom
        response options.
        """
        _server = next(
            _net.host_ip_interfaces(lambda interface: interface.ip == server_id), None
        )
        if _server is None:
            return None

        existing = self.lease_backend.lookup(client_id)
        if existing:
            renewed = self.lease_backend.renew(client_id, self.lease_seconds(msg))
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
            DhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
        )
        ttl = self.lease_seconds(msg)

        ip: _ty.Optional[_net.IPv4] = None
        if requested_ip:
            ip = requested_ip
        elif msg.ciaddr != _net.WILDCARD_IPv4:
            ip = msg.ciaddr

        if ip is None:
            return None

        refusal = self._address_refusal(ip, _server, client_id)
        if refusal is not None:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Refusing {ip} for {client_id}: {refusal}"
            )
            return None

        options = DhcpOptions()
        options[DhcpOptionCode.SUBNET_MASK] = _server.network.netmask
        options[DhcpOptionCode.BROADCAST_ADDRESS] = _server.network.broadcast_address
        # No ROUTER and no DNS. They used to be set to this host's own address,
        # which is a guess and usually a wrong one: running the server on an
        # ordinary machine then told every client to send all off-link traffic
        # and every name lookup to a host that routes and resolves nothing.
        # Omitting them leaves the client with whatever it already has -- a
        # statically configured resolver, another router on the segment -- which
        # is recoverable, where being pointed at a black hole is not.
        # Override `acquire_lease` to supply the real ones.

        LOGGER.debug(f"[XID={msg.xid:08x}] Allocating {ip} for {client_id}")
        lease = self.lease_backend.allocate(client_id, ip, ttl, options)
        if lease is not None:
            self.metrics.leases_allocated += 1
        return lease

    def _address_refusal(
        self,
        ip: _net.IPv4,
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

    def quarantine_address(self, ip: _net.IPv4) -> None:
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
        self, client_id: str, server_id: _net.IPv4, msg: DhcpMessage
    ) -> None:
        """Release any lease associated with `client_id`.

        Override this method when lease release needs to update an external store
        or emit custom audit records. Quarantining a declined address is handled
        by `quarantine_address`, which `handle_decline` calls before this.
        """
        if self.lease_backend.release(client_id):
            self.metrics.leases_released += 1

    def get_inform_options(self, server_id: _net.IPv4, msg: DhcpMessage) -> DhcpOptions:
        """Return configuration options for DHCPINFORM responses.

        DHCPINFORM does not allocate an address. Override this method when clients
        should receive site-specific options without touching lease allocation.
        """
        options = DhcpOptions()
        _server = next(
            _net.host_ip_interfaces(lambda interface: interface.ip == server_id), None
        )
        if _server is not None:
            options[DhcpOptionCode.SUBNET_MASK] = _server.network.netmask
            options[DhcpOptionCode.BROADCAST_ADDRESS] = (
                _server.network.broadcast_address
            )
            # As in `acquire_lease`: this host is not known to be a router or a
            # resolver, so it does not claim to be either.
        return options

    def handle(
        self,
        msg: DhcpMessage,
        context: RequestContext,
    ) -> None:
        if msg.op != _enum.OpCode.BOOTREQUEST:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Received a reply msg from {context.client} ignoring it."
            )
            return
        try:
            client_id = msg.client_id()
        except NoClientIdentity as e:
            # Nothing to key a lease on, and RFC 2131 s4.2 requires the client to
            # supply one. Serving it would hand out an address under an identity
            # every other such client shares.
            LOGGER.warning(f"[XID={msg.xid:08x}] Ignoring unidentifiable client: {e}")
            return
        msg_ty = msg.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
        msg_ty_name = (
            msg_ty.name
            if (msg_ty is not None and hasattr(msg_ty, "name"))
            else str(msg_ty)
        )
        LOGGER.debug(
            f"[XID={msg.xid:08x}] Received {msg_ty_name} from {context.client.ip}"
        )
        server_id: _ty.Optional[_net.IPv4] = msg.options.get(
            DhcpOptionCode.SERVER_IDENTIFIER, decode=_type.IPv4Address
        )
        msg_ty = msg.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)

        if server_id is not None and server_id != actual_server_id:
            if msg_ty is _enum.DhcpMessageType.DHCPREQUEST:
                self.release_lease(client_id, server_id, msg)
            else:
                LOGGER.warning(
                    f"[XID={msg.xid:08x}] Received a message for {server_id} by {context.client}|{client_id} at {actual_server_id} ignoring"
                )
            return

        if msg_ty is _enum.DhcpMessageType.DHCPDISCOVER:
            self.handle_discover(msg, context)
        elif msg_ty is _enum.DhcpMessageType.DHCPREQUEST:
            self.handle_request(msg, context)
        elif msg_ty is _enum.DhcpMessageType.DHCPDECLINE:
            self.handle_decline(msg, context)
        elif msg_ty is _enum.DhcpMessageType.DHCPRELEASE:
            self.handle_release(msg, context)
        elif msg_ty is _enum.DhcpMessageType.DHCPINFORM:
            self.handle_inform(msg, context)
        else:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Received a DHCP Message with message type: {msg_ty} from: {context.client}|{client_id} at: {actual_server_id}, which we don't handle"
            )

    def handle_discover(self, msg: DhcpMessage, context: RequestContext) -> None:
        """Handle DHCPDISCOVER by offering a lease returned from `acquire_lease`."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.info(
            f"[XID={msg.xid:08x}] DHCPDISCOVER from {context.client}|{client_id}"
        )
        # A DISCOVER is a probe, so it may look and reserve but must not extend
        # an existing binding -- see `_NonExtendingBackend`.
        lease = self._probe_lease(client_id, actual_server_id, msg)
        if not lease or not self._has_time_left(lease):
            LOGGER.info(
                f"[XID={msg.xid:08x}] No lease available for {context.client}|{client_id} at {actual_server_id} ignoring"
            )
            return
        resp = self._create_response(
            msg, lease, actual_server_id, _enum.DhcpMessageType.DHCPOFFER
        )
        self._filter_and_send(msg, resp, context, _enum.DhcpMessageType.DHCPOFFER)

    def handle_request(self, msg: DhcpMessage, context: RequestContext) -> None:
        """Handle DHCPREQUEST by ACKing or NAKing the lease returned from `acquire_lease`."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.info(
            f"[XID={msg.xid:08x}] DHCPREQUEST from {context.client}|{client_id}"
        )

        # INIT-REBOOT: no server identifier, a requested address, and ciaddr 0.
        # RFC 2131 4.3.2 -- "If the server has no record of this client, then it
        # MUST remain silent, and MAY output a warning". Allocating here instead
        # makes the server answer for clients that belong to another server on
        # the same segment, i.e. behave as a rogue.
        if (
            msg.options.get(DhcpOptionCode.SERVER_IDENTIFIER, decode=_type.IPv4Address)
            is None
            and msg.options.get(DhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address)
            is not None
            and msg.ciaddr == _net.WILDCARD_IPv4
            and self.lease_backend.lookup(client_id) is None
        ):
            LOGGER.warning(
                f"[XID={msg.xid:08x}] INIT-REBOOT from {context.client}|{client_id} "
                "with no record of this client, remaining silent"
            )
            return

        # Decide first, on a view that cannot extend the binding: a REQUEST for
        # the wrong address is about to be NAKed, and renewing the address it is
        # being refused was exactly backwards.
        lease = self._probe_lease(client_id, actual_server_id, msg)
        if not lease:
            LOGGER.info(
                f"[XID={msg.xid:08x}] No lease available for {context.client}|{client_id} at {actual_server_id} ignoring"
            )
            return
        ip_req: _ty.Optional[_net.IPv4] = msg.options.get(
            DhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
        )
        if not ip_req:
            ip_req = msg.ciaddr
        if ip_req == lease.ip and self._has_time_left(lease):
            resp_ty = _enum.DhcpMessageType.DHCPACK
            # Only now is anything agreed, so this is where the lease time the
            # ACK advertises is actually committed.
            committed = self.acquire_lease(client_id, actual_server_id, msg)
            if committed is not None:
                lease = committed
        else:
            # A lease with no time left NAKs rather than ACKing nothing: the
            # client is told to start over, which is recoverable, instead of
            # being handed an ACK with no address in it.
            resp_ty = _enum.DhcpMessageType.DHCPNAK
        resp = self._create_response(msg, lease, actual_server_id, resp_ty)
        self._filter_and_send(msg, resp, context, resp_ty)

    def handle_decline(self, msg: DhcpMessage, context: RequestContext) -> None:
        """Handle DHCPDECLINE by releasing the client's lease through `release_lease`."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.warning(
            f"[XID={msg.xid:08x}] DHCPDECLINE from {context.client}|{client_id}"
        )
        declined: _ty.Optional[_net.IPv4] = msg.options.get(
            DhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
        )
        if declined is None and msg.ciaddr != _net.WILDCARD_IPv4:
            declined = msg.ciaddr
        if declined is None:
            existing = self.lease_backend.lookup(client_id)
            declined = existing.ip if existing is not None else None
        if declined is not None:
            self.quarantine_address(declined)
        self.release_lease(client_id, actual_server_id, msg)

    def handle_release(self, msg: DhcpMessage, context: RequestContext) -> None:
        """Handle DHCPRELEASE by releasing the client's lease through `release_lease`."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.info(
            f"[XID={msg.xid:08x}] DHCPRELEASE from {context.client}|{client_id}"
        )
        self.release_lease(client_id, actual_server_id, msg)

    def handle_inform(self, msg: DhcpMessage, context: RequestContext) -> None:
        """Handle DHCPINFORM without requiring address allocation."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.info(f"[XID={msg.xid:08x}] DHCPINFORM from {context.client}|{client_id}")
        # RFC 2131 4.3.5: a DHCPINFORM client already has its address and is
        # asking only for configuration. Routing this through acquire_lease
        # created or renewed a binding for a client that never asked for one --
        # so an INFORM flood grew the lease store -- and bypassed the
        # allocation-free hook documented for exactly this path whenever a
        # binding happened to exist.
        lease = DhcpLease(
            _net.WILDCARD_IPv4,
            _inf,
            self.get_inform_options(actual_server_id, msg),
        )
        resp = self._create_response(
            msg, lease, actual_server_id, _enum.DhcpMessageType.DHCPACK
        )
        if DhcpOptionCode.IP_ADDRESS_LEASE_TIME in resp.options:
            del resp.options[DhcpOptionCode.IP_ADDRESS_LEASE_TIME]
        resp.yiaddr = _net.WILDCARD_IPv4
        self._filter_and_send(msg, resp, context, _enum.DhcpMessageType.DHCPACK)

    def _create_response(
        self,
        msg: DhcpMessage,
        lease: DhcpLease,
        actual_server_id: _net.IPv4,
        resp_ty: _enum.DhcpMessageType,
    ) -> DhcpMessage:
        resp = DhcpMessage(**msg.__dict__.copy())
        # Never alias the stored lease's options: the response pipeline injects
        # bookkeeping options and PARAMETER_REQUEST_LIST filtering deletes
        # entries, which would otherwise write straight through to the backend.
        resp.options = lease.options.copy()
        resp.op = _enum.OpCode.BOOTREPLY
        resp.hops = 0
        resp.secs = _dt.timedelta(seconds=0)
        # The reply is cloned from the request, so every header field not
        # overwritten below is still the client's. RFC 2131 Table 3 says what a
        # reply carries, and three of these were the sender's to choose:
        #
        #   siaddr  the *next bootstrap server*, which is the server's to name.
        #           Echoing it let a client nominate its own next-server and get
        #           the answer back stamped with the server's identifier.
        #   sname   ditto, as text: an OFFER came back carrying whatever host
        #           name the client had put in the request.
        #   file    the boot file name, same problem -- and this is the pair a
        #           PXE client acts on.
        #
        # giaddr is deliberately *not* reset: Table 3 says a reply echoes it,
        # and it is what lets the relay route the answer back to the segment the
        # request came from. Clearing it would strand every relayed client.
        resp.siaddr = _net.WILDCARD_IPv4
        resp.sname = ""
        resp.file = ""
        if resp_ty is _enum.DhcpMessageType.DHCPOFFER:
            # Table 3: ciaddr is 0 in a DHCPOFFER. In a DHCPACK it is the
            # ciaddr from the DHCPREQUEST, so the clone is right there and this
            # must not be widened to cover both.
            resp.ciaddr = _net.WILDCARD_IPv4
        if resp_ty is _enum.DhcpMessageType.DHCPNAK:
            # RFC 2131 Table 3: a DHCPNAK carries no address and no lease time --
            # it refuses the client's. Cloning the request left ciaddr set and
            # the lease's address in yiaddr, i.e. a refusal that still looked
            # like an offer of the very address being refused.
            resp.yiaddr = _net.WILDCARD_IPv4
            resp.ciaddr = _net.WILDCARD_IPv4
            resp.siaddr = _net.WILDCARD_IPv4
            resp.sname = ""
            resp.file = ""
        elif lease.ip:
            if (
                lease.expires is None
                or lease.expires == _inf
                or not isinstance(lease.expires, _dt.datetime)
            ):
                expires = _const.INFINITE_LEASE_TIME
            else:
                # Round up, not down. Truncating sent a 3600-second lease as
                # 3599 -- a different number than the one granted, every time.
                expires = _math.ceil(
                    (lease.expires - _dt.datetime.now()).total_seconds()
                )
                expires = min(expires, _const.INFINITE_LEASE_TIME)
            if expires > 0:
                resp.options[DhcpOptionCode.IP_ADDRESS_LEASE_TIME] = expires
                resp.yiaddr = lease.ip
        resp.options[DhcpOptionCode.SERVER_IDENTIFIER] = actual_server_id
        resp.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = resp_ty
        relay_info = msg.options.get(
            DhcpOptionCode.RELAY_AGENT_INFORMATION, decode=False
        )
        if relay_info is not None:
            resp.options[DhcpOptionCode.RELAY_AGENT_INFORMATION] = relay_info
        client_identifier = msg.options.get(
            DhcpOptionCode.CLIENT_IDENTIFIER, decode=False
        )
        if client_identifier is not None:
            # RFC 6842 updates RFC 2131: when the client sends a client
            # identifier the server MUST return it unchanged. Clients that key
            # their state on it otherwise cannot match the reply to the request.
            resp.options[DhcpOptionCode.CLIENT_IDENTIFIER] = client_identifier
        return resp

    def _filter_and_send(
        self,
        msg: DhcpMessage,
        resp: DhcpMessage,
        context: RequestContext,
        resp_ty: _enum.DhcpMessageType,
    ) -> None:
        requests_params_raw = msg.options.get(
            DhcpOptionCode.PARAMETER_REQUEST_LIST,
            decode=_type.DhcpOptionCodes[DhcpOptionCode],
        )
        # Options the server controls rather than the client requesting them, so
        # the parameter request list must never filter them out: RFC 2131 4.3.1
        # (message type, server identifier, lease time) and RFC 3046 2.2, which
        # says a server supporting the relay agent option SHALL echo it in all
        # replies -- and practically every client sends a request list, so
        # filtering by it alone dropped the echo on every single reply.
        always_send = [
            DhcpOptionCode.DHCP_MESSAGE_TYPE,
            DhcpOptionCode.SERVER_IDENTIFIER,
            DhcpOptionCode.IP_ADDRESS_LEASE_TIME,
            DhcpOptionCode.RELAY_AGENT_INFORMATION,
            DhcpOptionCode.CLIENT_IDENTIFIER,
        ]
        requests_params: _ty.List[DhcpOptionCode] = []
        if requests_params_raw:
            requests_params = [*requests_params_raw, *always_send]
        if resp_ty is _enum.DhcpMessageType.DHCPNAK:
            requests_params = [
                DhcpOptionCode.DHCP_MESSAGE,
                DhcpOptionCode.CLIENT_IDENTIFIER,
                DhcpOptionCode.VENDOR_CLASS_IDENTIFIER,
                DhcpOptionCode.SERVER_IDENTIFIER,
                DhcpOptionCode.DHCP_MESSAGE_TYPE,
                DhcpOptionCode.RELAY_AGENT_INFORMATION,
            ]
            resp.options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray.fromhex(
                msg.client_id().replace(":", "")
            )
        if requests_params:

            def _paramfilter(opt: tuple[int, bytearray]) -> bool:
                return opt[0] in requests_params

            resp.options._options = _ty.OrderedDict(
                filter(_paramfilter, resp.options.items(decoded=False))
            )
        resp.options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = resp_ty

        max_size_opt = msg.options.get(
            DhcpOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE,
            default=_const.DHCP_MIN_LEGAL_PACKET_SIZE,
            decode=_type.U16,
        )
        max_size = (
            int(max_size_opt)
            if max_size_opt is not None
            else _const.DHCP_MIN_LEGAL_PACKET_SIZE
        )
        if max_size < _const.DHCP_MIN_LEGAL_PACKET_SIZE:
            # RFC 2132 s9.10 sets 576 as the minimum legal value of option 57.
            # Below 268 `encode` raises outright, so a client advertising 200
            # got no reply at all and every such packet logged an error with no
            # XID -- log spam driven from the network. Between 268 and 575 it
            # succeeds but overloads sname/file for no reason.
            #
            # Debug, not warning: the value is the client's to choose and a
            # wrong one is not this server's error, while a warning here is
            # attacker-drivable -- the same trap the per-packet unknown-htype
            # warning fell into.
            LOGGER.debug(
                f"[XID={msg.xid:08x}] Client advertised a maximum message size of "
                f"{max_size}, below the RFC 2132 minimum of "
                f"{_const.DHCP_MIN_LEGAL_PACKET_SIZE}; using the minimum"
            )
            max_size = _const.DHCP_MIN_LEGAL_PACKET_SIZE
        # No upper clamp: what the reply costs is decided by what this server
        # has to say, not by the ceiling the client offers, so an inflated 57
        # buys an attacker nothing and clamping it to a guessed MTU would break
        # a jumbo-frame segment that legitimately asked for more.
        data = resp.encode(max_size)

        dest: _net.IPv4
        dest_port: int = context.client.port

        if resp_ty is _enum.DhcpMessageType.DHCPNAK:
            # RFC 2131 4.3.2: with giaddr 0 the server MUST broadcast the NAK to
            # 255.255.255.255, because the client may hold no usable address or
            # subnet mask; with giaddr set it MUST set the broadcast bit and send
            # to the relay. Falling through to the normal rules unicast the
            # refusal to the very address the client was told it may not use, so
            # the client never saw it and retried until its timers expired.
            if msg.giaddr != _net.WILDCARD_IPv4:
                resp.flags = _enum.Flags.BROADCAST
                data = resp.encode(max_size)
                dest = msg.giaddr
                dest_port = 67 if context.client.port == 68 else context.client.port
            else:
                dest = _net.IPv4("255.255.255.255")
        elif msg.giaddr != _net.WILDCARD_IPv4:
            dest = msg.giaddr
            dest_port = 67 if context.client.port == 68 else context.client.port
        elif msg.ciaddr != _net.WILDCARD_IPv4:
            dest = msg.ciaddr
        elif msg.flags is _enum.Flags.BROADCAST:
            dest = _net.IPv4("255.255.255.255")
        else:
            # The client has no address yet (ciaddr 0) and did not ask for a
            # broadcast. See UNICAST_TO_UNCONFIGURED_CLIENT: a plain UDP socket
            # cannot deliver to yiaddr before the client owns it. Loopback is the
            # exception both ways -- there is no ARP to fail, and POSIX refuses a
            # broadcast from a socket bound to 127.0.0.1 outright.
            if resp.yiaddr != _net.WILDCARD_IPv4 and (
                self.UNICAST_TO_UNCONFIGURED_CLIENT or _is_loopback(context)
            ):
                dest = resp.yiaddr
            else:
                dest = _net.IPv4("255.255.255.255")

        resp.log(
            context.interface.ip, _net.SocketAddress(dest, dest_port), _logging.INFO
        )
        if __debug__:
            # Diagnostic only: a reply we cannot re-decode is a real bug, but it must be
            # reported, never allowed to suppress the send.
            try:
                _check = DhcpMessage.decode(memoryview(data))
            except Exception:
                LOGGER.warning(
                    "Encoded reply does not decode cleanly -- sending it anyway",
                    exc_info=True,
                )
            else:
                _check.log(
                    context.interface.ip,
                    _net.SocketAddress(dest, dest_port),
                    _logging.DEBUG,
                )
        context.transport.send(data, dest, dest_port, context.client_mac)
        self.metrics.packets_sent += 1


from .listener import AsyncDhcpListener as _AsyncBase


class AsyncDhcpServer(_AsyncBase, DhcpServer):  # type: ignore[misc]
    DEFAULT_PORTS = (_enum.DhcpPort.SERVER,)

    def __init__(
        self,
        listen: ListenSpec = None,
        max_packet_size: _ty.Optional[int] = None,
        lease_backend: _ty.Optional[LeaseBackend] = None,
        per_interface: bool | None = None,
    ) -> None:
        _AsyncBase.__init__(
            self,
            listen=listen,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_server_state(lease_backend)

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        DhcpServer.handle(self, msg, context)
