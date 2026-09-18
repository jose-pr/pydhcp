from __future__ import annotations

import socket as _socket
from .packet.message import DhcpMessage
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
            requested_ttl = msg.options.get(
                DhcpOptionCode.IP_ADDRESS_LEASE_TIME, decode=_type.U32
            )
            ttl = int(requested_ttl) if requested_ttl is not None else 3600
            renewed = self.lease_backend.renew(client_id, ttl)
            if renewed:
                self.metrics.leases_renewed += 1
                return renewed
            return existing

        requested_ip = msg.options.get(
            DhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
        )
        requested_ttl = msg.options.get(
            DhcpOptionCode.IP_ADDRESS_LEASE_TIME, decode=_type.U32
        )
        ttl = int(requested_ttl) if requested_ttl is not None else 3600

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
        options[DhcpOptionCode.ROUTER] = [server_id]
        options[DhcpOptionCode.DNS] = [server_id]

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
            options[DhcpOptionCode.ROUTER] = [server_id]
            options[DhcpOptionCode.DNS] = [server_id]
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
        client_id = msg.client_id()
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
        lease = self.acquire_lease(client_id, actual_server_id, msg)
        if not lease:
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

        lease = self.acquire_lease(client_id, actual_server_id, msg)
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
        if ip_req == lease.ip:
            resp_ty = _enum.DhcpMessageType.DHCPACK
        else:
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
                expires = int((lease.expires - _dt.datetime.now()).total_seconds())
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
