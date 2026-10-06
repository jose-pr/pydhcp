"""Building a reply and deciding where it goes."""

from __future__ import annotations

import ipaddress as _ipaddress
import datetime as _dt
import logging as _logging
import math as _math
import typing as _ty

from .. import constants as _const, network as _net
from ..lease import DHCPLease
from ..listener import DHCPRequestContext
from ..options import DHCPOptionCode, type as _type
from ..packet import enums as _enum
from ..packet.message import DHCPMessage
from math import inf as _inf
from .policy import _LeasePolicy

LOGGER = _logging.getLogger(__name__)


def _is_loopback(context: DHCPRequestContext) -> bool:
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


class _Replies(_LeasePolicy):
    """Reply construction (`_create_response`) and delivery (`_filter_and_send`)."""

    def _create_response(
        self,
        msg: DHCPMessage,
        lease: DHCPLease,
        actual_server_id: _ipaddress.IPv4Address,
        resp_ty: _enum.DHCPMessageType,
    ) -> DHCPMessage:
        resp = DHCPMessage(**msg.__dict__.copy())
        # Never alias the stored lease's options: the response pipeline injects
        # bookkeeping options and PARAMETER_REQUEST_LIST filtering deletes
        # entries, which would otherwise write straight through to the backend.
        resp.options = lease.options.copy()
        resp.op = _enum.DHCPOpcode.BOOTREPLY
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
        resp.siaddr = _const.WILDCARD_V4
        resp.sname = ""
        resp.file = ""
        if resp_ty is _enum.DHCPMessageType.DHCPOFFER:
            # Table 3: ciaddr is 0 in a DHCPOFFER. In a DHCPACK it is the
            # ciaddr from the DHCPREQUEST, so the clone is right there and this
            # must not be widened to cover both.
            resp.ciaddr = _const.WILDCARD_V4
        if resp_ty is _enum.DHCPMessageType.DHCPNAK:
            # RFC 2131 Table 3: a DHCPNAK carries no address and no lease time --
            # it refuses the client's. Cloning the request left ciaddr set and
            # the lease's address in yiaddr, i.e. a refusal that still looked
            # like an offer of the very address being refused.
            resp.yiaddr = _const.WILDCARD_V4
            resp.ciaddr = _const.WILDCARD_V4
            resp.siaddr = _const.WILDCARD_V4
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
                resp.options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = expires
                resp.yiaddr = lease.ip
        resp.options[DHCPOptionCode.SERVER_IDENTIFIER] = actual_server_id
        resp.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = resp_ty
        relay_info = msg.options.get(
            DHCPOptionCode.RELAY_AGENT_INFORMATION, decode=False
        )
        if relay_info is not None:
            resp.options[DHCPOptionCode.RELAY_AGENT_INFORMATION] = relay_info
        client_identifier = msg.options.get(
            DHCPOptionCode.CLIENT_IDENTIFIER, decode=False
        )
        if client_identifier is not None:
            # RFC 6842 updates RFC 2131: when the client sends a client
            # identifier the server MUST return it unchanged. Clients that key
            # their state on it otherwise cannot match the reply to the request.
            resp.options[DHCPOptionCode.CLIENT_IDENTIFIER] = client_identifier
        return resp

    def _filter_and_send(
        self,
        msg: DHCPMessage,
        resp: DHCPMessage,
        context: DHCPRequestContext,
        resp_ty: _enum.DHCPMessageType,
    ) -> None:
        requests_params_raw = msg.options.get(
            DHCPOptionCode.PARAMETER_REQUEST_LIST,
            decode=_type.DHCPOptionCodes[DHCPOptionCode],
        )
        # Options the server controls rather than the client requesting them, so
        # the parameter request list must never filter them out: RFC 2131 4.3.1
        # (message type, server identifier, lease time) and RFC 3046 2.2, which
        # says a server supporting the relay agent option SHALL echo it in all
        # replies -- and practically every client sends a request list, so
        # filtering by it alone dropped the echo on every single reply.
        always_send = [
            DHCPOptionCode.DHCP_MESSAGE_TYPE,
            DHCPOptionCode.SERVER_IDENTIFIER,
            DHCPOptionCode.IP_ADDRESS_LEASE_TIME,
            DHCPOptionCode.RELAY_AGENT_INFORMATION,
            DHCPOptionCode.CLIENT_IDENTIFIER,
        ]
        requests_params: _ty.List[DHCPOptionCode] = []
        if requests_params_raw:
            requests_params = [*requests_params_raw, *always_send]
        if resp_ty is _enum.DHCPMessageType.DHCPNAK:
            requests_params = [
                DHCPOptionCode.DHCP_MESSAGE,
                DHCPOptionCode.CLIENT_IDENTIFIER,
                DHCPOptionCode.VENDOR_CLASS_IDENTIFIER,
                DHCPOptionCode.SERVER_IDENTIFIER,
                DHCPOptionCode.DHCP_MESSAGE_TYPE,
                DHCPOptionCode.RELAY_AGENT_INFORMATION,
            ]
            resp.options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray.fromhex(
                msg.client_id().replace(":", "")
            )
        if requests_params:

            def _paramfilter(opt: tuple[int, bytearray]) -> bool:
                return opt[0] in requests_params

            resp.options._options = _ty.OrderedDict(
                filter(_paramfilter, resp.options.items(decoded=False))
            )
        resp.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = resp_ty

        max_size_opt = msg.options.get(
            DHCPOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE,
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

        dest: _ipaddress.IPv4Address
        dest_port: int = context.client.port

        if resp_ty is _enum.DHCPMessageType.DHCPNAK:
            # RFC 2131 4.3.2: with giaddr 0 the server MUST broadcast the NAK to
            # 255.255.255.255, because the client may hold no usable address or
            # subnet mask; with giaddr set it MUST set the broadcast bit and send
            # to the relay. Falling through to the normal rules unicast the
            # refusal to the very address the client was told it may not use, so
            # the client never saw it and retried until its timers expired.
            if msg.giaddr != _const.WILDCARD_V4:
                resp.flags = _enum.DHCPFlags.BROADCAST
                data = resp.encode(max_size)
                dest = msg.giaddr
                dest_port = 67 if context.client.port == 68 else context.client.port
            else:
                dest = _ipaddress.IPv4Address("255.255.255.255")
        elif msg.giaddr != _const.WILDCARD_V4:
            dest = msg.giaddr
            dest_port = 67 if context.client.port == 68 else context.client.port
        elif msg.ciaddr != _const.WILDCARD_V4:
            dest = msg.ciaddr
        elif msg.flags is _enum.DHCPFlags.BROADCAST:
            dest = _ipaddress.IPv4Address("255.255.255.255")
        else:
            # The client has no address yet (ciaddr 0) and did not ask for a
            # broadcast. See UNICAST_TO_UNCONFIGURED_CLIENT: a plain UDP socket
            # cannot deliver to yiaddr before the client owns it. Loopback is the
            # exception both ways -- there is no ARP to fail, and POSIX refuses a
            # broadcast from a socket bound to 127.0.0.1 outright.
            if resp.yiaddr != _const.WILDCARD_V4 and (
                self.UNICAST_TO_UNCONFIGURED_CLIENT or _is_loopback(context)
            ):
                dest = resp.yiaddr
            else:
                dest = _ipaddress.IPv4Address("255.255.255.255")

        resp.log(
            context.interface.ip, _net.SocketAddress(dest, dest_port), _logging.INFO
        )
        if __debug__:
            # Diagnostic only: a reply we cannot re-decode is a real bug, but it must be
            # reported, never allowed to suppress the send.
            try:
                _check = DHCPMessage.decode(memoryview(data))
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
