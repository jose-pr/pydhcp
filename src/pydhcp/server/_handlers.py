"""Dispatching a request to the handler for its message type."""

from __future__ import annotations

import ipaddress as _ipaddress
import logging as _logging
import typing as _ty

from .. import _constants as _const
from ..exceptions import DHCPDecodeError, NoClientIdentityError
from ..lease import DHCPLease
from ..listener._limit import _brief
from ..listener._receive import DHCPRequestContext
from ..options._codes import DHCPOptionCode
from ..options import _codecs as _type
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage
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
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "BOOTREPLY received",
                "[XID=%08x] Received a reply msg from %s ignoring it.",
                msg.xid,
                context.client,
                now=self._instant(context).monotonic,
            )
            return
        try:
            client_id = msg.get_client_id()
        except NoClientIdentityError as e:
            # Nothing to key a lease on, and RFC 2131 s4.2 requires the client to
            # supply one. Serving it would hand out an address under an identity
            # every other such client shares.
            self.metrics.packets_dropped_no_client_id += 1
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "unidentifiable client",
                "[XID=%08x] Ignoring unidentifiable client: %s",
                msg.xid,
                _brief(e),
                now=self._instant(context).monotonic,
            )
            return
        # Read once, guarded: `message_type` is `None` for an option 53 of the
        # wrong size, and an unassigned number is an unnamed member that no
        # handler below takes. Either way the line carries the XID and the
        # client, which the listener's catch-all line does not.
        msg_ty = msg.message_type
        if msg_ty is None and DHCPOptionCode.DHCP_MESSAGE_TYPE in msg.options:
            raw = msg.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE, decode=False)
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "unusable message type",
                "[XID=%08x] Dropping a message from %s|%s with an unusable DHCP "
                "message type (option 53 = %s)",
                msg.xid,
                context.client,
                _brief(client_id),
                bytes(raw).hex() if raw else "<empty>",
                now=self._instant(context).monotonic,
            )
            return
        if not self._acted_on_options_usable(msg, client_id, context):
            return
        msg_ty_name = msg_ty.label() if msg_ty is not None else str(msg_ty)
        # Lazy %-style rather than an f-string because this one runs for every
        # request, and an f-string is built whether or not DEBUG is enabled.
        # The other eager call sites fire per lease, per drop or per error, not
        # per packet, so they are left alone.
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
                # The client selected a different server, so the address held
                # for it by an offer is given back (RFC 2131 4.3.2). A binding
                # the client accepted stays: anyone can name another server.
                held = self.lookup_lease(client_id)
                if (
                    held is not None
                    and held.offered
                    and self.release_lease(client_id, actual_server_id, msg)
                ):
                    self.metrics.offers_withdrawn += 1
            else:
                self.metrics.packets_dropped_other_server += 1
                self._log_limit.log(
                    LOGGER,
                    _logging.WARNING,
                    "message for another server",
                    "[XID=%08x] Received a message for %s by %s|%s at %s ignoring",
                    msg.xid,
                    server_id,
                    context.client,
                    _brief(client_id),
                    actual_server_id,
                    now=self._instant(context).monotonic,
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
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "message type not handled",
                "[XID=%08x] Received a DHCP Message with message type: %s from: "
                "%s|%s at: %s, which is not handled",
                msg.xid,
                msg_ty_name,
                context.client,
                _brief(client_id),
                actual_server_id,
                now=self._instant(context).monotonic,
            )

    def handle_discover(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Handle DHCPDISCOVER by offering a lease returned from `acquire_lease`."""
        client_id = msg.get_client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        LOGGER.info(
            f"[XID={msg.xid:08x}] DHCPDISCOVER from {context.client}|{client_id}"
        )
        # A DISCOVER is a probe: it may hold an address as an offer but must
        # not extend an existing binding or commit one.
        lease = self.acquire_lease(client_id, actual_server_id, msg, commit=False)
        now = self._instant(context).utc
        if lease and self._refused_as_quarantined(msg, lease, client_id, context):
            return
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
        """Handle DHCPREQUEST by ACKing or NAKing the lease returned from `acquire_lease`.

        RFC 2131 s4.3.2 and Table 4 tell the four shapes apart, and each is
        answered from the record `acquire_lease` returns for the client:

        - SELECTING (option 54 names this server): a lease for the address asked
          for is ACKed; a request this server cannot satisfy is NAKed (s3.1
          step 4), never left unanswered.
        - INIT-REBOOT (option 50, no option 54, `ciaddr` 0), RENEWING (`ciaddr`,
          unicast to this server) and REBINDING (`ciaddr`, broadcast): a lease
          for the address is ACKed, a lease for another address is NAKed, and
          no lease at all is silence, because the client may belong to another
          server on the same wire.
        """
        client_id = msg.get_client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        LOGGER.info(
            f"[XID={msg.xid:08x}] DHCPREQUEST from {context.client}|{client_id}"
        )
        server_id = msg.options.get(
            DHCPOptionCode.SERVER_IDENTIFIER, decode=_type.IPv4AddressOption
        )
        requested: _ty.Optional[_ipaddress.IPv4Address] = msg.options.get(
            DHCPOptionCode.REQUESTED_IP, decode=_type.IPv4AddressOption
        )
        if server_id is not None:
            shape = "SELECTING"
        elif msg.ciaddr != _const.WILDCARD_V4:
            shape = "RENEWING" if context.is_unicast is not False else "REBINDING"
        elif requested is not None:
            shape = "INIT-REBOOT"
        else:
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "REQUEST of no address",
                "[XID=%08x] DHCPREQUEST from %s|%s names no address: no "
                "server identifier, no requested address and no ciaddr",
                msg.xid,
                context.client,
                _brief(client_id),
                now=self._instant(context).monotonic,
            )
            return
        ip_req = requested if requested is not None else msg.ciaddr

        # Decide first, on a call that cannot extend the binding: a REQUEST for
        # the wrong address is about to be NAKed, and renewing the address it is
        # being refused was exactly backwards.
        lease = self.acquire_lease(client_id, actual_server_id, msg, commit=False)
        if not lease:
            if shape == "SELECTING":
                self._nak(msg, context, "the address is not available")
                return
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                f"{shape} from an unknown client",
                "[XID=%08x] %s from %s|%s with no record of this client, "
                "remaining silent",
                msg.xid,
                shape,
                context.client,
                _brief(client_id),
                now=self._instant(context).monotonic,
            )
            return
        now = self._instant(context).utc
        if self._refused_as_quarantined(msg, lease, client_id, context):
            self._nak(msg, context, "the address is not available")
            return
        if ip_req != lease.ip:
            self._nak(msg, context, "the requested address is not the client's")
            return
        if not self._has_time_left(lease, now):
            # A lease with no time left NAKs rather than ACKing nothing: the
            # client is told to start over, which is recoverable, instead of
            # being handed an ACK with no address in it.
            self._nak(msg, context, "the lease has expired")
            return
        # Only now is anything agreed, so this is where the lease time the ACK
        # advertises is actually committed.
        committed = self.acquire_lease(client_id, actual_server_id, msg, commit=True)
        if committed is not None:
            lease = committed
        elif lease.offered:
            # The hold lapsed between the decision and the commit.
            self._nak(msg, context, "the offer has lapsed")
            return
        resp = self._create_response(
            msg, lease, actual_server_id, _enum.DHCPMessageType.DHCPACK, now=now
        )
        self._filter_and_send(msg, resp, context, _enum.DHCPMessageType.DHCPACK)

    def _nak(self, msg: DHCPMessage, context: DHCPRequestContext, reason: str) -> None:
        """Send a DHCPNAK to `msg`, with `reason` as its message option."""
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        resp = self._create_nak(msg, actual_server_id, reason)
        self._filter_and_send(msg, resp, context, _enum.DHCPMessageType.DHCPNAK)

    def handle_decline(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Handle DHCPDECLINE: quarantine the address the sender holds, and release it.

        RFC 2131 s4.3.3 makes the server mark a declined address unavailable.
        Nothing authenticates the sender, so only the address the sender itself
        holds, as a binding or an outstanding offer, is marked: a DECLINE
        naming any other address, one outside the served network, or one that
        names another server in option 54 changes nothing and is counted in
        `declines_ignored`.
        """
        client_id = msg.get_client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        held = self.lookup_lease(client_id)
        declined: _ty.Optional[_ipaddress.IPv4Address] = msg.options.get(
            DHCPOptionCode.REQUESTED_IP, decode=_type.IPv4AddressOption
        )
        if declined is None and msg.ciaddr != _const.WILDCARD_V4:
            declined = msg.ciaddr
        if declined is None and held is not None:
            declined = held.ip
        refusal = self._decline_refusal(msg, declined, held, actual_server_id)
        if refusal is not None or declined is None:
            self.metrics.declines_ignored += 1
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "DHCPDECLINE ignored",
                "[XID=%08x] Ignoring DHCPDECLINE from %s|%s: %s",
                msg.xid,
                context.client,
                _brief(client_id),
                _brief(refusal),
                now=self._instant(context).monotonic,
            )
            return
        self._log_limit.log(
            LOGGER,
            _logging.WARNING,
            "DHCPDECLINE",
            "[XID=%08x] DHCPDECLINE of %s from %s|%s",
            msg.xid,
            declined,
            context.client,
            _brief(client_id),
            now=self._instant(context).monotonic,
        )
        self.quarantine_address(declined)
        # Counted as a decline, not a release: the client found the address
        # already in use, which is the opposite of an orderly hand-back.
        self.metrics.leases_declined += 1
        self.release_lease(client_id, actual_server_id, msg)

    def _refused_as_quarantined(
        self,
        msg: DHCPMessage,
        lease: DHCPLease,
        client_id: str,
        context: DHCPRequestContext,
    ) -> bool:
        """Whether `lease`, whatever hook returned it, is for a quarantined address.

        Counted in `addresses_refused` and logged through the rate limit.
        """
        now = self._instant(context).monotonic
        if not self.is_quarantined(lease.ip, now=now):
            return False
        self.metrics.addresses_refused += 1
        self._log_limit.log(
            LOGGER,
            _logging.WARNING,
            "quarantined address",
            "[XID=%08x] Refusing %s for %s|%s: it is quarantined after a DHCPDECLINE",
            msg.xid,
            lease.ip,
            context.client,
            _brief(client_id),
            now=now,
        )
        return True

    def handle_release(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Handle DHCPRELEASE, but only for the address the client actually holds."""
        client_id = msg.get_client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        LOGGER.info(
            f"[XID={msg.xid:08x}] DHCPRELEASE from {context.client}|{client_id}"
        )
        # RFC 2131 4.4.6: the client puts the address being given up in ciaddr.
        # Releasing on client identifier alone meant a late or duplicated
        # RELEASE naming an *old* address deleted whatever binding that client
        # holds now -- and the address then went to someone else while the
        # client was still using it.
        existing = self.lookup_lease(client_id)
        if existing is not None and msg.ciaddr != _const.WILDCARD_V4:
            if existing.ip != msg.ciaddr:
                self._log_limit.log(
                    LOGGER,
                    _logging.WARNING,
                    "DHCPRELEASE for an address not held",
                    "[XID=%08x] Ignoring DHCPRELEASE from %s|%s for %s: it holds %s",
                    msg.xid,
                    context.client,
                    _brief(client_id),
                    msg.ciaddr,
                    existing.ip,
                    now=self._instant(context).monotonic,
                )
                self.metrics.releases_ignored += 1
                return
        if self.release_lease(client_id, actual_server_id, msg):
            self.metrics.leases_released += 1

    def handle_inform(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Handle DHCPINFORM without requiring address allocation."""
        client_id = msg.get_client_id()
        actual_server_id = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)
        LOGGER.info(f"[XID={msg.xid:08x}] DHCPINFORM from {context.client}|{client_id}")
        # RFC 2131 4.3.5: a DHCPINFORM client already has its address and is
        # asking only for configuration. Routing this through acquire_lease
        # created or renewed a binding for a client that never asked for one --
        # so an INFORM flood grew the lease store -- and bypassed the
        # allocation-free hook documented for exactly this path whenever a
        # binding happened to exist.
        refusal = self._inform_refusal(msg, context.client.ip, actual_server_id)
        if refusal is not None:
            self.metrics.informs_ignored += 1
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "DHCPINFORM refused",
                "[XID=%08x] Ignoring DHCPINFORM from %s|%s: %s",
                msg.xid,
                context.client,
                _brief(client_id),
                _brief(refusal),
                now=self._instant(context).monotonic,
            )
            return
        resp = self._create_inform_response(
            msg, self.get_inform_options(actual_server_id, msg), actual_server_id
        )
        self._filter_and_send(msg, resp, context, _enum.DHCPMessageType.DHCPACK)
