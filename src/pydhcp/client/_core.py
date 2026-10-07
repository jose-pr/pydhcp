"""The client's rules: what it sends, which replies it accepts, how it backs off.

No socket, thread, task or clock lives here. A driver (`_sync`, `_asyncio`)
owns the socket and the waiting, reads the clock and passes the elapsed time in;
the core builds messages, matches a reply to an exchange and yields the
retransmission schedule as a plain sequence.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress as _ipaddress
import logging as _logging
import secrets as _secrets
import typing as _ty

import netimps as _netimps

from .. import _constants as _const
from .._network import IPv4AddressLike
from .._metrics import DHCPMetrics
from ..exceptions import DHCPDecodeError, DHCPRefusedError, DHCPTimeoutError
from ..listener._limit import _brief, _LogLimit
from ..listener._receive import DHCPRequestContext
from ..options import DHCPOptions
from ..options import _codecs as _type
from ..options._codes import DHCPOptionCode
from ..packet import _enums as _enum
from ..packet._message import DHCPMessage

LOGGER = _logging.getLogger(__name__)

#: What a function accepts as a client identifier: the octets of option 61.
ClientIdentifierLike = _ty.Union[bytes, bytearray]

#: Where a message goes when the caller names no destination.
BROADCAST_DESTINATION = _ipaddress.IPv4Address("255.255.255.255")

#: The reply a driver holds for one exchange, or queues for `next_reply`.
Reply = tuple[DHCPMessage, DHCPRequestContext]


class _ClientCore:
    """DHCPv4 client rules, without their I/O.

    Builds the client messages, accepts the replies that belong to an exchange
    and ignores the rest. A driver composes it with a listener, which delivers
    each decoded datagram to `handle()`.
    """

    metrics: DHCPMetrics
    _log_limit: _LogLimit

    DEFAULT_PORTS: _ty.Sequence[int] = (_enum.DHCPPort.CLIENT,)

    #: Upper bound on undrained replies. An idle client accepts every BOOTREPLY
    #: on the segment so that `start()` + `on_reply` works as an observer, which
    #: on a busy network is unbounded growth when nobody calls `drain_replies()`.
    #: Past this the oldest is discarded and counted in
    #: `metrics.replies_dropped_overflow`.
    MAX_QUEUED_REPLIES = 1024

    #: Ceiling on the retransmission interval, from RFC 2131 s4.1: the delay
    #: "SHOULD be doubled with subsequent retransmissions up to a maximum of 64
    #: seconds".
    RETRANSMIT_MAX_INTERVAL = 64.0

    #: RFC 2131 s4.1 randomizes each interval "by the value of a uniform random
    #: number chosen from the range -1 to +1" -- seconds, both ways. netimps'
    #: `backoff_delays(jitter_seconds=)` applies it after the cap, as the RFC
    #: does, so a backed-off client spends its time spread across 63-65 s rather
    #: than clamped one-sidedly below 64 (which re-synchronises a fleet exactly
    #: where it spends nearly all its time). The amplitude is capped at the
    #: current delay, so a sub-second test `timeout` cannot go negative.
    RETRANSMIT_JITTER_SECONDS = 1.0

    if _ty.TYPE_CHECKING:

        def _deliver(
            self, key: tuple[int, bytes], msg: DHCPMessage, context: DHCPRequestContext
        ) -> None: ...

    def _init_client_state(self) -> None:
        self._pending_keys: set[tuple[int, bytes]] = set()

    def build_discover(
        self,
        chaddr: bytes,
        *,
        xid: _ty.Optional[int] = None,
        client_identifier: _ty.Optional[ClientIdentifierLike] = None,
        parameter_request_list: _ty.Optional[_ty.Iterable[DHCPOptionCode]] = None,
        broadcast: bool = True,
    ) -> DHCPMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=broadcast)
        msg.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = (
            _enum.DHCPMessageType.DHCPDISCOVER
        )
        self._add_client_options(msg, client_identifier, parameter_request_list)
        return msg

    def build_request(
        self,
        chaddr: bytes,
        *,
        xid: _ty.Optional[int] = None,
        requested_ip: _ty.Optional[IPv4AddressLike] = None,
        server_identifier: _ty.Optional[IPv4AddressLike] = None,
        ciaddr: _ty.Optional[IPv4AddressLike] = None,
        client_identifier: _ty.Optional[ClientIdentifierLike] = None,
        parameter_request_list: _ty.Optional[_ty.Iterable[DHCPOptionCode]] = None,
        broadcast: bool = True,
    ) -> DHCPMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=broadcast)
        msg.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = (
            _enum.DHCPMessageType.DHCPREQUEST
        )
        if ciaddr is not None:
            msg.ciaddr = _ipaddress.IPv4Address(ciaddr)
        if requested_ip is not None:
            msg.options[DHCPOptionCode.REQUESTED_IP] = _ipaddress.IPv4Address(
                requested_ip
            )
        if server_identifier is not None:
            msg.options[DHCPOptionCode.SERVER_IDENTIFIER] = _ipaddress.IPv4Address(
                server_identifier
            )
        self._add_client_options(msg, client_identifier, parameter_request_list)
        return msg

    def build_inform(
        self,
        chaddr: bytes,
        *,
        ciaddr: IPv4AddressLike,
        xid: _ty.Optional[int] = None,
        client_identifier: _ty.Optional[ClientIdentifierLike] = None,
        parameter_request_list: _ty.Optional[_ty.Iterable[DHCPOptionCode]] = None,
    ) -> DHCPMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=False)
        msg.ciaddr = _ipaddress.IPv4Address(ciaddr)
        msg.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = _enum.DHCPMessageType.DHCPINFORM
        self._add_client_options(msg, client_identifier, parameter_request_list)
        return msg

    def build_release(
        self,
        chaddr: bytes,
        *,
        ciaddr: IPv4AddressLike,
        server_identifier: _ty.Optional[IPv4AddressLike] = None,
        xid: _ty.Optional[int] = None,
        client_identifier: _ty.Optional[ClientIdentifierLike] = None,
    ) -> DHCPMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=False)
        msg.ciaddr = _ipaddress.IPv4Address(ciaddr)
        msg.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = (
            _enum.DHCPMessageType.DHCPRELEASE
        )
        if server_identifier is not None:
            msg.options[DHCPOptionCode.SERVER_IDENTIFIER] = _ipaddress.IPv4Address(
                server_identifier
            )
        self._add_client_options(msg, client_identifier, None)
        return msg

    def build_decline(
        self,
        chaddr: bytes,
        *,
        requested_ip: IPv4AddressLike,
        server_identifier: _ty.Optional[IPv4AddressLike] = None,
        xid: _ty.Optional[int] = None,
        client_identifier: _ty.Optional[ClientIdentifierLike] = None,
    ) -> DHCPMessage:
        msg = self._base_request(chaddr, xid=xid, broadcast=True)
        msg.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = (
            _enum.DHCPMessageType.DHCPDECLINE
        )
        msg.options[DHCPOptionCode.REQUESTED_IP] = _ipaddress.IPv4Address(requested_ip)
        if server_identifier is not None:
            msg.options[DHCPOptionCode.SERVER_IDENTIFIER] = _ipaddress.IPv4Address(
                server_identifier
            )
        self._add_client_options(msg, client_identifier, None)
        return msg

    @staticmethod
    def _pending_key(msg: DHCPMessage) -> tuple[int, bytes]:
        """Identify an exchange by transaction *and* client, as the relay does.

        Matching on the xid alone is wrong in both directions. Outward: a reply
        carrying a seen xid but a foreign `chaddr` would be accepted, and the
        xid travels in cleartext in a broadcast DISCOVER, so any host on the
        segment can read one and answer it. Inward: two exchanges from one client
        share the reply stream, so the one that happened to be waiting would
        consume and discard the other's reply, and the other would time out.

        Same shape as `DHCPRelay._pending_key`, including the `hlen` slice: a
        decoded message already trims `chaddr` to `hlen`, an in-memory one need
        not have.
        """
        return msg.xid, bytes(msg.chaddr[: msg.hlen or len(msg.chaddr)])

    def _reply_key(self, msg: DHCPMessage) -> _ty.Optional[tuple[int, bytes]]:
        """The exchange a datagram answers, or `None` when it is not for this client."""
        if msg.op != _enum.DHCPOpcode.BOOTREPLY:
            return None
        key = self._pending_key(msg)
        if self._pending_keys and key not in self._pending_keys:
            return None
        return key

    @staticmethod
    def _server_identifier(msg: DHCPMessage) -> _ty.Optional[_ipaddress.IPv4Address]:
        """Option 54 of a reply, or `None` when it is absent or unreadable."""
        try:
            return msg.options.get(
                DHCPOptionCode.SERVER_IDENTIFIER,
                default=None,
                decode=_type.IPv4AddressOption,
            )
        except DHCPDecodeError:
            return None

    def _take(
        self,
        msg: DHCPMessage,
        msg_type: _enum.DHCPMessageType,
        server: _ty.Optional[_ipaddress.IPv4Address],
        now: float,
    ) -> _ty.Optional[DHCPMessage]:
        """What an exchange waiting for `msg_type` does with a reply that matched it.

        Returns the reply when it is the answer, `None` when it is to be ignored
        and the wait goes on, and raises `DHCPRefusedError` for a DHCPNAK. `server`
        is the server a DHCPREQUEST selected (RFC 2131 s4.4.1), `None` for a
        DHCPDISCOVER, and `now` the driver's monotonic reading, for the limited
        warnings. This is the only thing standing between a DHCPNAK and a caller
        that believes it holds `yiaddr`.

        - A DHCPNAK refuses a DHCPREQUEST (s3.1 step 5): it ends the exchange,
          unless it names a server other than the selected one.
        - A DHCPOFFER is usable when it offers an address (`yiaddr`) and names its
          server: s4.3.2 has the REQUEST that selects it carry option 54.
        - A DHCPACK from a server other than the selected one is not the answer
          to this REQUEST.
        """
        kind = msg.message_type
        named = self._server_identifier(msg)
        if kind is _enum.DHCPMessageType.DHCPNAK:
            if msg_type is not _enum.DHCPMessageType.DHCPACK:
                return None
            if server is not None and named is not None and named != server:
                return None
            text = msg.options.get(
                DHCPOptionCode.DHCP_MESSAGE, default=None, decode=_type.String
            )
            raise DHCPRefusedError(
                "the server refused the request with a DHCPNAK"
                + (f": {_brief(text)}" if text else ""),
                msg,
            )
        if kind is not msg_type:
            return None
        if msg_type is _enum.DHCPMessageType.DHCPOFFER:
            if msg.yiaddr == _const.WILDCARD_V4:
                self._log_limit.log(
                    LOGGER,
                    _logging.WARNING,
                    "DHCPOFFER without an address",
                    "[XID=%08x] Ignoring a DHCPOFFER that offers no address",
                    msg.xid,
                    now=now,
                )
                return None
            if named is None:
                # RFC 2131 s4.3.2: a REQUEST in SELECTING state MUST carry the
                # server identifier, and the server uses it to tell "this offer
                # is mine" from "another server's offer was chosen". Selecting
                # an offer that does not name its server would send one without.
                self._log_limit.log(
                    LOGGER,
                    _logging.WARNING,
                    "DHCPOFFER without a server identifier",
                    "[XID=%08x] Ignoring a DHCPOFFER with no SERVER_IDENTIFIER; "
                    "a conforming DHCPREQUEST cannot be built from it",
                    msg.xid,
                    now=now,
                )
                return None
        elif (
            msg_type is _enum.DHCPMessageType.DHCPACK
            and server is not None
            and named is not None
            and named != server
        ):
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "DHCPACK from another server",
                "[XID=%08x] Ignoring a DHCPACK from %s: the request selected %s",
                msg.xid,
                named,
                server,
                now=now,
            )
            return None
        return msg

    @staticmethod
    def _deadline_end(
        started_at: float, deadline: _ty.Optional[float]
    ) -> _ty.Optional[float]:
        """The monotonic reading a call with this `deadline` must be over by."""
        if deadline is None:
            return None
        if not deadline > 0:
            raise ValueError(
                f"deadline must be a positive number of seconds, got {deadline!r}"
            )
        return started_at + deadline

    @staticmethod
    def _timed_out(
        msg_type: _enum.DHCPMessageType, attempts: int, ends: _ty.Optional[float]
    ) -> DHCPTimeoutError:
        """The error for an exchange whose retransmissions or deadline ran out."""
        return DHCPTimeoutError(
            f"no usable {msg_type.label()} arrived after {attempts} "
            f"{'attempt' if attempts == 1 else 'attempts'}"
            + (" within the deadline" if ends is not None else "")
        )

    def _retransmit_intervals(
        self, timeout: float, retries: int
    ) -> _ty.Iterator[float]:
        """How long to wait for a reply after each of ``retries + 1`` sends.

        RFC 2131 s4.1: the delay doubles with each retransmission up to 64
        seconds, randomized each time by +/-1 s. The randomization is not
        decoration -- a fleet of clients that back off in lock-step retransmits
        in lock-step, which is the collision the jitter exists to break up.
        netimps owns the schedule; `backoff_delays` yields ``attempts - 1``
        values, one per wait. A `timeout` above the cap starts at the cap:
        `backoff_delays` refuses a ceiling below its first delay.
        """
        return _netimps.backoff_delays(
            attempts=retries + 2,
            delay=min(timeout, self.RETRANSMIT_MAX_INTERVAL),
            multiplier=2.0,
            max_delay=self.RETRANSMIT_MAX_INTERVAL,
            jitter_seconds=self.RETRANSMIT_JITTER_SECONDS,
        )

    @staticmethod
    def _stamp_secs(message: DHCPMessage, elapsed: float) -> None:
        """Set `secs` to the time since acquisition began.

        `elapsed` is measured from when *acquisition* began, not from when this
        message was built: RFC 2131 s2 defines `secs` as "seconds elapsed since
        client began address acquisition or renewal process", so a DORA's
        REQUEST continues the DISCOVER's clock rather than restarting it.
        Servers and relays prioritise a long-suffering client on that field.
        """
        message.secs = _dt.timedelta(seconds=max(0.0, elapsed))

    @staticmethod
    def _encode(message: DHCPMessage) -> bytes:
        return message.encode(_const.DHCP_MIN_LEGAL_PACKET_SIZE)

    def _note_sent(self) -> None:
        self.metrics.packets_sent += 1

    def _selected_server(self, offer: DHCPMessage) -> _ipaddress.IPv4Address:
        """The server a DHCPOFFER names, which `_take` required it to."""
        server = self._server_identifier(offer)
        if server is None:
            raise ValueError("the DHCPOFFER names no server (option 54)")
        return server

    def _request_after(
        self,
        offer: DHCPMessage,
        server_identifier: _ipaddress.IPv4Address,
        chaddr: bytes,
        *,
        client_identifier: _ty.Optional[ClientIdentifierLike],
        parameter_request_list: _ty.Optional[_ty.Iterable[DHCPOptionCode]],
        broadcast: bool,
    ) -> DHCPMessage:
        """The DHCPREQUEST that selects `offer`, made by `server_identifier`."""
        return self.build_request(
            chaddr,
            xid=offer.xid,
            requested_ip=offer.yiaddr,
            server_identifier=server_identifier,
            broadcast=broadcast,
            # RFC 2131 s4.2 and s4.4.1 both say MUST: the same client
            # identifier in every subsequent message, and the same parameter
            # list in any subsequent REQUEST. Omitting the identifier would key
            # the REQUEST under htype+chaddr while the OFFER was allocated under
            # the supplied one, so the server would see two different clients.
            client_identifier=client_identifier,
            parameter_request_list=parameter_request_list,
        )

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        key = self._reply_key(msg)
        if key is None:
            return
        # An idle client (nothing sent yet) deliberately still accepts: that is
        # what makes `start()` + `on_reply` usable as an observer.
        self._deliver(key, msg, context)
        self.on_reply(msg, context)

    def on_reply(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        """Hook called after a BOOTREPLY is accepted and queued."""

    def _base_request(
        self,
        chaddr: bytes,
        *,
        xid: _ty.Optional[int],
        broadcast: bool,
    ) -> DHCPMessage:
        return DHCPMessage(
            op=_enum.DHCPOpcode.BOOTREQUEST,
            htype=_enum.HardwareAddressType.ETHERNET,
            hlen=len(chaddr),
            hops=0,
            xid=_secrets.randbits(32) if xid is None else int(xid),
            # A freshly built message has no acquisition behind it yet;
            # an exchange stamps the real elapsed time before each send.
            secs=_dt.timedelta(seconds=0),
            flags=_enum.DHCPFlags.BROADCAST if broadcast else _enum.DHCPFlags.UNICAST,
            ciaddr=_const.WILDCARD_V4,
            yiaddr=_const.WILDCARD_V4,
            siaddr=_const.WILDCARD_V4,
            giaddr=_const.WILDCARD_V4,
            chaddr=bytes(chaddr),
            sname="",
            file="",
            options=DHCPOptions(),
        )

    def _add_client_options(
        self,
        msg: DHCPMessage,
        client_identifier: _ty.Optional[ClientIdentifierLike],
        parameter_request_list: _ty.Optional[_ty.Iterable[DHCPOptionCode]],
    ) -> None:
        if client_identifier is not None:
            msg.options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray(client_identifier)
        if parameter_request_list is not None:
            msg.options[DHCPOptionCode.PARAMETER_REQUEST_LIST] = list(
                parameter_request_list
            )
