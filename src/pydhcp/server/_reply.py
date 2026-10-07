"""Building a reply and deciding where it goes."""

from __future__ import annotations

import ipaddress as _ipaddress
import datetime as _dt
import logging as _logging
import math as _math
import typing as _ty

from .. import _constants as _const, _network as _net
from ..lease import DHCPLease
from ..listener._receive import DHCPRequestContext, _is_loopback
from ..listener._transport import _Datagram
from ..options import DHCPOptions
from ..options._codes import DHCPOptionCode
from ..options import _codecs as _type
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage
from ._policy import _LeasePolicy

__all__: list[str] = []

LOGGER = _logging.getLogger(__name__)

#: Where the options field starts: the fixed header and the magic cookie.
_OPTIONS_OFFSET = 240


def _overloads(data: bytes) -> bool:
    """Whether the encoded message carries the option-overload option (52).

    The options field is read to its END; the option is placed in it whenever
    `sname` or `file` carries options.
    """
    view = memoryview(data)
    index = _OPTIONS_OFFSET
    while index < len(view):
        code = view[index]
        if code == 255:
            return False
        if code == 0:
            index += 1
            continue
        if code == int(DHCPOptionCode.OPTION_OVERLOAD):
            return True
        if index + 1 >= len(view):
            return False
        index += 2 + view[index + 1]
    return False


class _Replies(_LeasePolicy):
    """Reply construction (`_create_response`) and delivery (`_filter_and_send`)."""

    def _create_response(
        self,
        msg: DHCPMessage,
        lease: DHCPLease,
        actual_server_id: _ipaddress.IPv4Address,
        resp_ty: _enum.DHCPMessageType,
        *,
        now: "_ty.Optional[_dt.datetime]" = None,
    ) -> DHCPMessage:
        """The reply to `msg`, cloned from it.

        `now` is an aware instant, the clock `lease.expires` is read on;
        omitted, the driver's reading is used.
        """
        if now is None:
            now = self._read_clock().utc
        return self._build_reply(
            msg, lease.options, actual_server_id, resp_ty, lease=lease, now=now
        )

    def _create_nak(
        self,
        msg: DHCPMessage,
        actual_server_id: _ipaddress.IPv4Address,
        reason: str,
    ) -> DHCPMessage:
        """The DHCPNAK to `msg`: only what RFC 2131 Table 3 gives a NAK."""
        return self._build_reply(
            msg,
            DHCPOptions(),
            actual_server_id,
            _enum.DHCPMessageType.DHCPNAK,
            lease=None,
            now=None,
            text=reason,
        )

    def _create_inform_response(
        self,
        msg: DHCPMessage,
        options: DHCPOptions,
        actual_server_id: _ipaddress.IPv4Address,
    ) -> DHCPMessage:
        """The DHCPACK to a DHCPINFORM: the options, and no address or lease time."""
        return self._build_reply(
            msg,
            options,
            actual_server_id,
            _enum.DHCPMessageType.DHCPACK,
            lease=None,
            now=None,
        )

    def _build_reply(
        self,
        msg: DHCPMessage,
        options: DHCPOptions,
        actual_server_id: _ipaddress.IPv4Address,
        resp_ty: _enum.DHCPMessageType,
        *,
        lease: "_ty.Optional[DHCPLease]",
        now: "_ty.Optional[_dt.datetime]",
        text: "_ty.Optional[str]" = None,
    ) -> DHCPMessage:
        resp = DHCPMessage(**msg.__dict__.copy())
        # A copy, never the stored lease's own bag: the response pipeline injects
        # bookkeeping options and PARAMETER_REQUEST_LIST filtering deletes
        # entries, and a lease's options are read-only. A NAK takes none of
        # them: Table 3 allows it only the options added below.
        resp.options = (
            DHCPOptions()
            if resp_ty is _enum.DHCPMessageType.DHCPNAK
            else options.copy()
        )
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
        elif lease is None:
            resp.yiaddr = _const.WILDCARD_V4
        else:
            if lease.offered:
                # What the OFFER promises is the lease the ACK would grant, not
                # how long the address is held for while the client decides.
                granted = self.get_lease_seconds(msg)
                expires = (
                    _const.INFINITE_LEASE_TIME
                    if granted == _math.inf
                    else min(_math.ceil(granted), _const.INFINITE_LEASE_TIME)
                )
            elif lease.expires is None:
                expires = _const.INFINITE_LEASE_TIME
            else:
                assert now is not None
                # To the nearest second, not down: truncating sent a 3600-second
                # lease as 3599. Not up either: `now` is when the datagram
                # arrived, so a lease made while it was handled has a few
                # milliseconds more than its lease time left. A lease with time
                # left is never advertised as none.
                remaining = (lease.expires - now).total_seconds()
                expires = max(1, round(remaining)) if remaining > 0 else 0
                expires = min(expires, _const.INFINITE_LEASE_TIME)
            if expires > 0:
                resp.options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = expires
                resp.yiaddr = lease.ip
                if self.RENEWAL_TIMES and expires != _const.INFINITE_LEASE_TIME:
                    self._fill_renewal_times(resp.options, expires)
        resp.options[DHCPOptionCode.SERVER_IDENTIFIER] = actual_server_id
        resp.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = resp_ty
        if text is not None:
            resp.options[DHCPOptionCode.DHCP_MESSAGE] = text
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

    @staticmethod
    def _fill_renewal_times(options: DHCPOptions, lease_time: int) -> None:
        """Add options 58 and 59 for `lease_time`, each only if absent (RFC 2131 s4.4.5).

        T1 is half and T2 seven eighths of the lease time the same reply
        carries, in whole seconds rounded down, so a renewal follows the time
        left. No random fuzz: a reply is a function of its input.
        """
        if DHCPOptionCode.RENEWAL_TIME not in options:
            options[DHCPOptionCode.RENEWAL_TIME] = lease_time // 2
        if DHCPOptionCode.REBINDING_TIME not in options:
            options[DHCPOptionCode.REBINDING_TIME] = lease_time * 7 // 8

    def _filter_and_send(
        self,
        msg: DHCPMessage,
        resp: DHCPMessage,
        context: DHCPRequestContext,
        resp_ty: _enum.DHCPMessageType,
    ) -> None:
        datagram = self._reply_datagram(msg, resp, context, resp_ty)
        context.transport.send(
            datagram.data,
            datagram.dst,
            port=datagram.port,
            client_mac=datagram.client_mac,
        )
        self.metrics.packets_sent += 1

    def _reply_port(self, context: DHCPRequestContext, to_relay: bool) -> int:
        """The UDP destination port of a reply (`STRICT_REPLY_PORTS`)."""
        if self.STRICT_REPLY_PORTS:
            # RFC 1542 s5.4: set by the kind of destination, never taken from
            # the request's source port, which the sender chooses.
            return self.REPLY_TO_RELAY_PORT if to_relay else self.REPLY_TO_CLIENT_PORT
        source = context.client.port
        if to_relay and source == int(_enum.DHCPPort.CLIENT):
            return int(_enum.DHCPPort.SERVER)
        return source

    def _reply_datagram(
        self,
        msg: DHCPMessage,
        resp: DHCPMessage,
        context: DHCPRequestContext,
        resp_ty: _enum.DHCPMessageType,
    ) -> _Datagram:
        """Filter and encode `resp`, and decide where it goes. Sends nothing."""
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
        if self.RENEWAL_TIMES:
            always_send += [
                DHCPOptionCode.RENEWAL_TIME,
                DHCPOptionCode.REBINDING_TIME,
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
        if requests_params:

            resp.options.retain(requests_params)
        resp.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = resp_ty
        # RFC 3046 s2.2: the echoed relay agent information goes last.
        relay_info = resp.options.get(
            DHCPOptionCode.RELAY_AGENT_INFORMATION, decode=False
        )
        if relay_info is not None:
            del resp.options[DHCPOptionCode.RELAY_AGENT_INFORMATION]
            resp.options[DHCPOptionCode.RELAY_AGENT_INFORMATION] = relay_info
        if (
            resp_ty is _enum.DHCPMessageType.DHCPNAK
            and msg.giaddr != _const.WILDCARD_V4
        ):
            # RFC 2131 s4.3.2: through a relay the server MUST set the broadcast
            # bit, so that the relay broadcasts the NAK to the client; the
            # client's other flag bits (Table 3: 'flags' from the client) stay.
            resp.flags = resp.flags | _enum.DHCPFlags.BROADCAST

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
        try:
            data = resp.encode(max_size)
            without_relay_info = relay_info is not None and _overloads(data)
        except OverflowError:
            # Even with `sname` and `file`, the options do not fit.
            if relay_info is None:
                raise
            without_relay_info = True
        if without_relay_info:
            # RFC 3046 s2.2: the option is never placed in the overloaded `sname`
            # or `file`; a reply that cannot carry it in the options field is
            # sent without it, and counted.
            del resp.options[DHCPOptionCode.RELAY_AGENT_INFORMATION]
            data = resp.encode(max_size)
            self.metrics.relay_info_omitted += 1
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "relay information omitted",
                "[XID=%08x] Sending %s without the relay agent information "
                "option: it does not fit in the options field of %d octets",
                msg.xid,
                resp_ty.label(),
                max_size,
                now=self._instant(context).monotonic,
            )

        dest: _ipaddress.IPv4Address
        to_relay = False

        if resp_ty is _enum.DHCPMessageType.DHCPNAK:
            # RFC 2131 4.3.2: with giaddr 0 the server MUST broadcast the NAK to
            # 255.255.255.255, because the client may hold no usable address or
            # subnet mask; with giaddr set it MUST set the broadcast bit and send
            # to the relay. Falling through to the normal rules unicast the
            # refusal to the very address the client was told it may not use, so
            # the client never saw it and retried until its timers expired.
            if msg.giaddr != _const.WILDCARD_V4:
                dest = msg.giaddr
                to_relay = True
            else:
                dest = _ipaddress.IPv4Address("255.255.255.255")
        elif msg.giaddr != _const.WILDCARD_V4:
            dest = msg.giaddr
            to_relay = True
        elif msg.ciaddr != _const.WILDCARD_V4:
            dest = msg.ciaddr
        elif msg.broadcast:
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

        dest_port = self._reply_port(context, to_relay)

        resp.log(
            context.interface.ip, _net.SocketAddress(dest, dest_port), _logging.INFO
        )
        if LOGGER.isEnabledFor(_logging.DEBUG):
            # Diagnostic only, paid only when DEBUG is on: a reply that does not
            # decode is a real bug, but it must be reported, never allowed to
            # suppress the send.
            try:
                _check = DHCPMessage.decode(memoryview(data))
            except Exception:
                self._log_limit.log(
                    LOGGER,
                    _logging.WARNING,
                    "reply does not decode",
                    "Encoded reply does not decode cleanly -- sending it anyway",
                    now=self._instant(context).monotonic,
                    exc_info=True,
                )
            else:
                _check.log(
                    context.interface.ip,
                    _net.SocketAddress(dest, dest_port),
                    _logging.DEBUG,
                )
        return _Datagram(data, dest, dest_port, context.client_mac)
