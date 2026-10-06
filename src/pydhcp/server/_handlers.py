"""Dispatching a request to the handler for its message type."""

from __future__ import annotations

import ipaddress as _ipaddress
import logging as _logging
import typing as _ty

from .. import _constants as _const
from ..exceptions import DHCPDecodeError, NoClientIdentityError
from ..lease import DHCPLease
from ..listener._receive import DHCPRequestContext
from ..options._codes import DHCPOptionCode
from ..options import _codecs as _type
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage
from math import inf as _inf
from ._reply import _Replies

__all__: list[str] = []

LOGGER = _logging.getLogger(__name__)


class _Handlers(_Replies):
    """`handle()` and one override point per DHCP message type."""

    def handle(
        self,
        msg: DHCPMessage,
        context: DHCPRequestContext,
    ) -> None:
        if msg.op != _enum.DHCPOpcode.BOOTREQUEST:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Received a reply msg from {context.client} ignoring it."
            )
            return
        try:
            client_id = msg.client_id()
        except NoClientIdentityError as e:
            # Nothing to key a lease on, and RFC 2131 s4.2 requires the client to
            # supply one. Serving it would hand out an address under an identity
            # every other such client shares.
            LOGGER.warning(f"[XID={msg.xid:08x}] Ignoring unidentifiable client: {e}")
            return
        # Decoded once, and guarded. `DHCPMessageType` has no pseudo-member for
        # an unassigned value, so option 53 = 99 raised straight out of
        # `handle()`. The listener's catch-all caught it, but its log line
        # carries no XID, client or type -- so the one packet an operator would
        # want to identify produced the one message that cannot identify it.
        try:
            msg_ty = msg.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
        except DHCPDecodeError as e:
            raw = msg.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE, decode=False)
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Dropping a message from "
                f"{context.client}|{client_id} with an unusable DHCP message "
                f"type (option 53 = {bytes(raw).hex() if raw else '<absent>'}): {e}"
            )
            return
        msg_ty_name = (
            msg_ty.name
            if (msg_ty is not None and hasattr(msg_ty, "name"))
            else str(msg_ty)
        )
        # Lazy %-style rather than an f-string because this one runs for every
        # request, and an f-string is built whether or not DEBUG is enabled.
        # Measured with DEBUG off: 0.373 us eager against 0.157 us lazy, so
        # 0.216 us a packet. That is 0.19% of `handle()` -- which is why the
        # other eager call sites are left alone rather than churned; they fire
        # per lease, per drop or per error, not per packet.
        LOGGER.debug(
            "[XID=%08x] Received %s from %s", msg.xid, msg_ty_name, context.client.ip
        )
        server_id: _ty.Optional[_ipaddress.IPv4Address] = msg.options.get(
            DHCPOptionCode.SERVER_IDENTIFIER, decode=_type.IPv4AddressOption
        )
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)

        if server_id is not None and not self._is_our_server_id(
            server_id, actual_server_id
        ):
            if msg_ty is _enum.DHCPMessageType.DHCPREQUEST:
                # The client selected a different server, so give the
                # reservation back (RFC 2131 4.3.2).
                if self.release_lease(client_id, server_id, msg):
                    self.metrics.leases_released += 1
            else:
                LOGGER.warning(
                    f"[XID={msg.xid:08x}] Received a message for {server_id} by {context.client}|{client_id} at {actual_server_id} ignoring"
                )
            return

        if msg_ty is _enum.DHCPMessageType.DHCPDISCOVER:
            self.handle_discover(msg, context)
        elif msg_ty is _enum.DHCPMessageType.DHCPREQUEST:
            self.handle_request(msg, context)
        elif msg_ty is _enum.DHCPMessageType.DHCPDECLINE:
            self.handle_decline(msg, context)
        elif msg_ty is _enum.DHCPMessageType.DHCPRELEASE:
            self.handle_release(msg, context)
        elif msg_ty is _enum.DHCPMessageType.DHCPINFORM:
            self.handle_inform(msg, context)
        else:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Received a DHCP Message with message type: {msg_ty} from: {context.client}|{client_id} at: {actual_server_id}, which we don't handle"
            )

    def handle_discover(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Handle DHCPDISCOVER by offering a lease returned from `acquire_lease`."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        LOGGER.info(
            f"[XID={msg.xid:08x}] DHCPDISCOVER from {context.client}|{client_id}"
        )
        # A DISCOVER is a probe, so it may look and reserve but must not extend
        # an existing binding -- see `_NonExtendingBackend`.
        lease = self.acquire_lease(client_id, actual_server_id, msg, commit=False)
        now = self._instant(context).wall
        if not lease or not self._has_time_left(lease, now):
            LOGGER.info(
                f"[XID={msg.xid:08x}] No lease available for {context.client}|{client_id} at {actual_server_id} ignoring"
            )
            return
        resp = self._create_response(
            msg, lease, actual_server_id, _enum.DHCPMessageType.DHCPOFFER, now=now
        )
        self._filter_and_send(msg, resp, context, _enum.DHCPMessageType.DHCPOFFER)

    def handle_request(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Handle DHCPREQUEST by ACKing or NAKing the lease returned from `acquire_lease`."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        LOGGER.info(
            f"[XID={msg.xid:08x}] DHCPREQUEST from {context.client}|{client_id}"
        )

        # INIT-REBOOT: no server identifier, a requested address, and ciaddr 0.
        # RFC 2131 4.3.2 -- "If the server has no record of this client, then it
        # MUST remain silent, and MAY output a warning". Allocating here instead
        # makes the server answer for clients that belong to another server on
        # the same segment, i.e. behave as a rogue.
        if (
            msg.options.get(
                DHCPOptionCode.SERVER_IDENTIFIER, decode=_type.IPv4AddressOption
            )
            is None
            and msg.options.get(
                DHCPOptionCode.REQUESTED_IP, decode=_type.IPv4AddressOption
            )
            is not None
            and msg.ciaddr == _const.WILDCARD_V4
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
        lease = self.acquire_lease(client_id, actual_server_id, msg, commit=False)
        if not lease:
            LOGGER.info(
                f"[XID={msg.xid:08x}] No lease available for {context.client}|{client_id} at {actual_server_id} ignoring"
            )
            return
        ip_req: _ty.Optional[_ipaddress.IPv4Address] = msg.options.get(
            DHCPOptionCode.REQUESTED_IP, decode=_type.IPv4AddressOption
        )
        if not ip_req:
            ip_req = msg.ciaddr
        now = self._instant(context).wall
        if ip_req == lease.ip and self._has_time_left(lease, now):
            resp_ty = _enum.DHCPMessageType.DHCPACK
            # Only now is anything agreed, so this is where the lease time the
            # ACK advertises is actually committed.
            committed = self.acquire_lease(
                client_id, actual_server_id, msg, commit=True
            )
            if committed is not None:
                lease = committed
        else:
            # A lease with no time left NAKs rather than ACKing nothing: the
            # client is told to start over, which is recoverable, instead of
            # being handed an ACK with no address in it.
            resp_ty = _enum.DHCPMessageType.DHCPNAK
        resp = self._create_response(msg, lease, actual_server_id, resp_ty, now=now)
        self._filter_and_send(msg, resp, context, resp_ty)

    def handle_decline(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Handle DHCPDECLINE by releasing the client's lease through `release_lease`."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        LOGGER.warning(
            f"[XID={msg.xid:08x}] DHCPDECLINE from {context.client}|{client_id}"
        )
        declined: _ty.Optional[_ipaddress.IPv4Address] = msg.options.get(
            DHCPOptionCode.REQUESTED_IP, decode=_type.IPv4AddressOption
        )
        if declined is None and msg.ciaddr != _const.WILDCARD_V4:
            declined = msg.ciaddr
        if declined is None:
            existing = self.lease_backend.lookup(client_id)
            declined = existing.ip if existing is not None else None
        if declined is not None:
            self.quarantine_address(declined)
        # Counted as a decline, not a release: the client found the address
        # already in use, which is the opposite of an orderly hand-back. Both
        # landing in `leases_released` made an address-conflict storm read as
        # normal client shutdowns.
        self.metrics.leases_declined += 1
        self.release_lease(client_id, actual_server_id, msg)

    def handle_release(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Handle DHCPRELEASE, but only for the address the client actually holds."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        LOGGER.info(
            f"[XID={msg.xid:08x}] DHCPRELEASE from {context.client}|{client_id}"
        )
        # RFC 2131 4.4.6: the client puts the address being given up in ciaddr.
        # Releasing on client identifier alone meant a late or duplicated
        # RELEASE naming an *old* address deleted whatever binding that client
        # holds now -- and the address then went to someone else while the
        # client was still using it.
        existing = self.lease_backend.lookup(client_id)
        if existing is not None and msg.ciaddr != _const.WILDCARD_V4:
            if existing.ip != msg.ciaddr:
                LOGGER.warning(
                    f"[XID={msg.xid:08x}] Ignoring DHCPRELEASE from "
                    f"{context.client}|{client_id} for {msg.ciaddr}: it holds "
                    f"{existing.ip}"
                )
                self.metrics.releases_ignored += 1
                return
        if self.release_lease(client_id, actual_server_id, msg):
            self.metrics.leases_released += 1

    def handle_inform(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Handle DHCPINFORM without requiring address allocation."""
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        LOGGER.info(f"[XID={msg.xid:08x}] DHCPINFORM from {context.client}|{client_id}")
        # RFC 2131 4.3.5: a DHCPINFORM client already has its address and is
        # asking only for configuration. Routing this through acquire_lease
        # created or renewed a binding for a client that never asked for one --
        # so an INFORM flood grew the lease store -- and bypassed the
        # allocation-free hook documented for exactly this path whenever a
        # binding happened to exist.
        lease = DHCPLease(
            _const.WILDCARD_V4,
            _inf,
            self.get_inform_options(actual_server_id, msg),
        )
        resp = self._create_response(
            msg,
            lease,
            actual_server_id,
            _enum.DHCPMessageType.DHCPACK,
            now=self._instant(context).wall,
        )
        if DHCPOptionCode.IP_ADDRESS_LEASE_TIME in resp.options:
            del resp.options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME]
        resp.yiaddr = _const.WILDCARD_V4
        self._filter_and_send(msg, resp, context, _enum.DHCPMessageType.DHCPACK)
