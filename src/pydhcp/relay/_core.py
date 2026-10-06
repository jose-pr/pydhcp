"""The relay's rules: what to forward, to whom, and how a reply finds its client.

No socket, thread or clock lives here. A listener driver (`_sync`, `_asyncio`)
receives a datagram, stamps the context with the time it arrived and calls
`handle()`; what the relay sends leaves through the transport the context
carries.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import logging as _logging
import typing as _ty

import netimps as _netimps

from .._metrics import DHCPMetrics
from ..packet._message import DHCPMessage
from ..listener._transport import (
    PktInfoUDPTransport as _PktInfoUDPTransport,
    DHCPTransport as _DHCPTransport,
    UDPTransport as _UDPTransport,
)
from ..listener._limit import _brief, _LogLimit
from ..listener._receive import DHCPRequestContext, _is_loopback
from .. import _constants as _const, _network as _net
from ..packet import _enums as _enum
from ..options._codes import DHCPOptionCode
from ..options import _codecs as _type
from . import _info
from ._pending import _PendingClients

LOGGER = _logging.getLogger(__name__)

#: What the relay accepts for a server: an address, or an address and a port.
ServerAddressLike = _ty.Union[_net.IPv4AddressLike, tuple[_net.IPv4AddressLike, int]]

#: Hard ceiling from RFC 1542 4.1.1: "The relay agent MUST silently discard
#: BOOTREQUEST messages whose `hops` field exceeds the value 16." A threshold
#: above this could never be reached anyway -- and past 254 the incremented
#: value overflows the one-octet field and makes `encode` raise.
RFC1542_MAX_HOPS = 16

#: Default threshold. The same clause: "The default setting for a configurable
#: threshold SHOULD be 4." This was 16 -- the absolute ceiling used as though it
#: were the default. Four relays deep is already an unusual topology; a
#: deployment that genuinely needs more passes `max_hops` explicitly.
DEFAULT_MAX_HOPS = 4


def _normalize_server_address(
    address: ServerAddressLike,
) -> tuple[_ipaddress.IPv4Address, int]:
    """Coerce one upstream server entry to `(IPv4, port)`.

    The error says what is wrong and what is accepted. `IPv4()`'s own message
    is "Expected 4 octets in '::1'", which is true and tells an operator who
    passed an IPv6 address or a hostname neither which argument was at fault
    nor that only IPv4 is supported -- and it arrives *after* the "Starting
    DHCP relay" line, so it reads as a runtime failure rather than a bad
    argument.
    """
    ip, port = (
        address if isinstance(address, tuple) else (address, _enum.DHCPPort.SERVER)
    )
    try:
        return _ipaddress.IPv4Address(ip), int(port)
    except (ValueError, TypeError) as e:
        raise ValueError(
            f"upstream server address {ip!r} is not an IPv4 address ({e}). "
            "This relay forwards over IPv4 only, so a hostname or an IPv6 "
            "address cannot be used here."
        ) from None


class _RelayCore(_PendingClients):
    """RFC 1542 / RFC 2131 4.1 / RFC 3046 DHCP relay agent, without its I/O.

    Forwards client broadcasts (received on port 67, same as a server) to one or
    more configured upstream DHCP servers, stamping `giaddr` and incrementing
    `hops`. Forwards server replies (unicast back to this relay) on to the
    client, applying the same destination rules a server uses on its own
    client-facing side (broadcast flag, else `yiaddr`/`ciaddr`).

    A reply leaves from the address in its `giaddr`, out of the interface that
    holds it, and is dropped when no interface does (RFC 1542 s4.1.2); nothing
    remembered per exchange chooses the interface. The `xid -> client address`
    table (`_pending_clients`) only keeps the port of a client that is not on port 68,
    bounded at `MAX_PENDING_CLIENTS` with the oldest evicted first: an evicted
    entry sends that client's reply to port 68, and no reply is lost for it.
    """

    metrics: DHCPMetrics
    _log_limit: _LogLimit
    _max_packet_size: int

    DEFAULT_PORTS: _ty.Sequence[int] = (_enum.DHCPPort.SERVER,)

    def _init_relay_state(
        self,
        server_addresses: _ty.Sequence[ServerAddressLike] = (),
        *,
        max_hops: int = DEFAULT_MAX_HOPS,
        insert_relay_agent_info: bool = False,
        circuit_id: _ty.Optional[bytes] = None,
        remote_id: _ty.Optional[bytes] = None,
        trust_client_relay_agent_info: bool = False,
    ) -> None:
        """Set up the state and validation every relay driver needs.

        Each driver's constructor takes its own listener arguments and calls
        this for the rest, so the two cannot drift apart.
        """
        if not server_addresses:
            raise ValueError("DHCPRelay requires at least one server address")
        self.server_addresses = [_normalize_server_address(a) for a in server_addresses]
        if not 0 <= max_hops <= RFC1542_MAX_HOPS:
            raise ValueError(
                f"max_hops must be between 0 and {RFC1542_MAX_HOPS} "
                f"(RFC 1542 4.1.1), got {max_hops}"
            )
        self.max_hops = max_hops
        if insert_relay_agent_info:
            if circuit_id is None and remote_id is None:
                raise ValueError(
                    "insert_relay_agent_info=True needs circuit_id or remote_id: "
                    "option 82 with no sub-option would add nothing"
                )
        elif circuit_id is not None or remote_id is not None:
            raise ValueError(
                "circuit_id and remote_id are the sub-options of the option 82 "
                "this relay inserts: pass insert_relay_agent_info=True with "
                "them, or drop them"
            )
        self.insert_relay_agent_info = insert_relay_agent_info
        self.circuit_id = circuit_id
        self.remote_id = remote_id
        self.trust_client_relay_agent_info = trust_client_relay_agent_info
        #: The option this relay adds; a reply echoing exactly its octets is the
        #: one this relay added.
        self._relay_info: _ty.Optional[_type.RelayAgentInformation] = (
            _info.relay_info(circuit_id, remote_id) if insert_relay_agent_info else None
        )
        self._server_ips = {ip for ip, _port in self.server_addresses}
        self._init_pending()

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        if msg.op == _enum.DHCPOpcode.BOOTREQUEST:
            self._forward_to_servers(msg, context)
        elif msg.op == _enum.DHCPOpcode.BOOTREPLY:
            self._forward_to_client(msg, context)
        else:
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "unknown op",
                "[XID=%08x] Received message with unknown op %s, ignoring.",
                msg.xid,
                _brief(msg.op),
                now=self._instant(context).monotonic,
            )

    @staticmethod
    def _routed_transport(transport: _DHCPTransport) -> _DHCPTransport:
        """Drop the packet-info source pin for a send to a different network.

        A relay forwards *across* interfaces, which is the one case the pin gets
        wrong. It exists so a server replies out of the interface the request
        arrived on, and the receive path sets it from the ingress packet -- so
        reusing it to reach an upstream server pins the client-facing interface
        and source address for a destination that is not on that link, and the
        datagram is dropped without an error. Measured with ISC dhclient through
        this relay: 8 requests forwarded, 0 reaching the server. Falling back to
        a plain send over the same socket lets the kernel route normally.
        """
        if isinstance(transport, _PktInfoUDPTransport):
            return _UDPTransport(transport.socket)
        return transport

    def _client_transport(
        self,
        transport: _DHCPTransport,
        interface: _ty.Optional[_netimps.Interface],
        giaddr: _ipaddress.IPv4Address,
    ) -> _DHCPTransport:
        """Send from `giaddr`, out of the interface that holds it.

        The reply arrived on the server-facing interface and has to leave on the
        client-facing one, which on a wildcard bind the kernel cannot work out:
        a broadcast would go out the default route. The relay stamped `giaddr`
        with that interface's address and the server echoed it (RFC 1542
        s4.1.2), so the reply itself names where it goes. Without an interface
        the reply goes by plain routing.
        """
        if (
            isinstance(transport, _PktInfoUDPTransport)
            and interface is not None
            and interface.index
        ):
            out = _PktInfoUDPTransport(transport.socket, transport.endpoint)
            out.ifindex = interface.index
            out.local_ip = giaddr
            out.limit = transport.limit
            out.metrics = transport.metrics
            return out
        return self._routed_transport(transport)

    def _encode_for_forward(self, msg: DHCPMessage) -> bytes:
        """Encode a server reply being forwarded to its client without shrinking it.

        `encode()` defaults to the 576-octet minimum, which is not a limit this
        relay gets to impose: a server reply legitimately exceeds it whenever the
        client advertised a larger maximum (PXE/iPXE boot options, vendor info,
        classless routes). Encoding at the default raised OverflowError and the
        receive loop logged it, so the client simply never got its reply.
        """
        advertised = msg.options.get(
            DHCPOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE, default=None, decode=_type.U16
        )
        limit = int(advertised) if advertised else self._max_packet_size
        return msg.encode(max(limit, _const.DHCP_MIN_LEGAL_PACKET_SIZE))

    def _encode_request(
        self, forwarded: DHCPMessage, add_info: bool, now: float
    ) -> bytes:
        """Encode a request for the servers, at this relay's own size limit.

        Option 57 in a request is the size the client can *receive*, so it is
        not a limit on what goes upstream: the limit is `max_packet_size`. With
        `add_info`, option 82 goes last (RFC 3046 s2.1) unless that would need
        the overload option or the `sname` and `file` fields, which the same
        sentence forbids: then the request goes without it and is counted.
        """
        limit = max(self._max_packet_size, _const.DHCP_MIN_LEGAL_PACKET_SIZE)
        if add_info and self._relay_info is not None:
            forwarded.options[DHCPOptionCode.RELAY_AGENT_INFORMATION] = self._relay_info
            try:
                data = forwarded.encode(limit)
            except OverflowError:
                data = None
            if data is not None and not _info.uses_overload(data):
                return data
            del forwarded.options[int(DHCPOptionCode.RELAY_AGENT_INFORMATION)]
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "option 82 does not fit",
                "[XID=%08x] Forwarding the request without RELAY_AGENT_INFORMATION: "
                "it does not fit the options field within max_packet_size=%d",
                forwarded.xid,
                limit,
                now=now,
            )
            self.metrics.relay_info_omitted += 1
        return forwarded.encode(limit)

    def _is_own_address(
        self, address: _ipaddress.IPv4Address, context: DHCPRequestContext
    ) -> bool:
        """Whether `address` is one this relay holds, the receiving one included."""
        return address == context.interface.ip or _netimps.is_local_address(
            address, cache=True
        )

    def _forward_to_servers(
        self, msg: DHCPMessage, context: DHCPRequestContext
    ) -> None:
        now = self._instant(context).monotonic
        if (
            msg.giaddr == _const.WILDCARD_V4
            and DHCPOptionCode.RELAY_AGENT_INFORMATION in msg.options
            and not self.trust_client_relay_agent_info
        ):
            # RFC 3046 s2.1 and s5: giaddr 0 means this came straight from a
            # client, so the option is forged -- a client claiming a circuit id
            # picks its own policy on any server that trusts option 82. Pass
            # trust_client_relay_agent_info=True only when the access layer
            # below is trusted to set it.
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "option 82 with giaddr 0",
                "[XID=%08x] Dropping request from %s: RELAY_AGENT_INFORMATION "
                "present with giaddr 0 (untrusted source)",
                msg.xid,
                context.client,
                now=now,
            )
            self.metrics.packets_dropped_untrusted += 1
            return

        if msg.giaddr != _const.WILDCARD_V4 and self._is_own_address(
            msg.giaddr, context
        ):
            # RFC 3046 s2.1.1: "SHALL discard the packet if the giaddr spoofs a
            # giaddr address implemented by the local agent itself". Forwarded,
            # the server's reply would come back addressed to this relay as the
            # relay of a client it never saw.
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "giaddr is this relay",
                "[XID=%08x] Dropping request from %s: giaddr %s is an address "
                "of this relay",
                msg.xid,
                context.client,
                msg.giaddr,
                now=now,
            )
            self.metrics.packets_dropped_relay_loop += 1
            return

        # RFC 1542 4.1.1 discards a request whose hops field *exceeds* the
        # threshold, so the test is on the value as received. Incrementing
        # first and comparing that dropped a request one hop early: with
        # max_hops=2, a request that had legitimately crossed two relays --
        # hops=2, which the third relay is entitled to forward -- was refused,
        # and the parameter behaved as "maximum minus one" while being named
        # for the maximum.
        if msg.hops > self.max_hops:
            # Debug, not warning: this is reachable by anyone who can put a
            # packet on the segment, and the counter below is the signal an
            # operator actually watches.
            LOGGER.debug(
                f"[XID={msg.xid:08x}] Dropping request from {context.client}: hop count {msg.hops} exceeds max_hops={self.max_hops}"
            )
            self.metrics.packets_dropped_hop_limit += 1
            return

        if not self._record_pending(msg, context):
            return

        forwarded = DHCPMessage(**msg.__dict__.copy())
        # A shallow __dict__ copy shares the options container, so stamping this
        # copy would edit the caller's message.
        forwarded.options = msg.options.copy()
        forwarded.hops = msg.hops + 1

        # RFC 3046 s2.1.1: only a request straight from a client (giaddr 0) is
        # given option 82; one a relay already stamped goes on as it is. A
        # client's own option 82 (the trusted case) stays.
        add_info = (
            self.insert_relay_agent_info
            and msg.giaddr == _const.WILDCARD_V4
            and DHCPOptionCode.RELAY_AGENT_INFORMATION not in msg.options
        )
        if forwarded.giaddr == _const.WILDCARD_V4:
            forwarded.giaddr = _ty.cast(_ipaddress.IPv4Address, context.interface.ip)

        data = self._encode_request(forwarded, add_info, now)
        transport = self._routed_transport(context.transport)
        for server_ip, server_port in self.server_addresses:
            forwarded.log(
                context.interface.ip,
                _net.SocketAddress(server_ip, server_port),
                _logging.INFO,
            )
            transport.send(data, server_ip, port=server_port, client_mac=msg.chaddr)
            self.metrics.packets_sent += 1

    def _added_option_82(self, reply: DHCPMessage) -> bool:
        """Whether the reply echoes the option 82 this relay adds to requests.

        A server echoes the option's octets unchanged (RFC 3046 s2.2), so the
        octets this relay would have added are what tell its option from one a
        downstream element added; nothing is remembered per exchange.
        """
        if self._relay_info is None:
            return False
        echoed = reply.options.get(
            DHCPOptionCode.RELAY_AGENT_INFORMATION, default=None, decode=False
        )
        return echoed is not None and bytes(echoed) == bytes(self._relay_info.pack())

    def _forward_to_client(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        if context.client.ip not in self._server_ips:
            # Anything that can reach this relay's port 67 could otherwise have a
            # forged ACK broadcast onto the client segment, sourced from the
            # relay's own address -- naming the attacker as router and DNS, and
            # arriving from the port DHCP-snooping switches trust. RFC 1542
            # s4.1.2 assumes replies come from the servers we forwarded to.
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "BOOTREPLY from an unconfigured source",
                "[XID=%08x] Dropping BOOTREPLY from %s: not a configured server "
                "address",
                msg.xid,
                context.client,
                now=self._instant(context).monotonic,
            )
            self.metrics.packets_dropped_untrusted += 1
            return

        # RFC 1542 s4.1.2: "If the content of the 'giaddr' field does not match
        # one of the relay agent's directly-connected logical interfaces, the
        # BOOTREPLY messsage MUST be silently discarded." The interface that
        # holds it is also where the reply leaves.
        egress = _netimps.get_interface(msg.giaddr, cache=True)
        if egress is None and not self._is_own_address(msg.giaddr, context):
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                "BOOTREPLY for a giaddr that is not ours",
                "[XID=%08x] Dropping BOOTREPLY from %s: giaddr %s is not an "
                "address of this relay",
                msg.xid,
                context.client,
                msg.giaddr,
                now=self._instant(context).monotonic,
            )
            self.metrics.packets_dropped_unknown_giaddr += 1
            return

        pending = self._lookup_pending(msg, self._instant(context).monotonic)
        client_port = (
            pending.client.port if pending is not None else int(_enum.DHCPPort.CLIENT)
        )

        dest: _ipaddress.IPv4Address
        if msg.broadcast:
            dest = _ipaddress.IPv4Address("255.255.255.255")
        elif msg.ciaddr != _const.WILDCARD_V4:
            dest = msg.ciaddr
        elif msg.yiaddr != _const.WILDCARD_V4 and _is_loopback(context):
            # Loopback has no ARP to fail, and POSIX refuses a broadcast from a
            # socket bound to 127.0.0.1 -- see _is_loopback.
            dest = msg.yiaddr
        else:
            # The client has no address yet, so it cannot answer ARP for yiaddr
            # and a unicast is dropped by the kernel with no error -- the same
            # trap DHCPServer.UNICAST_TO_UNCONFIGURED_CLIENT documents.
            dest = _ipaddress.IPv4Address("255.255.255.255")

        reply = DHCPMessage(**msg.__dict__.copy())
        reply.options = msg.options.copy()
        if self._added_option_82(reply):
            # RFC 3046 s2.1: the echoed option "MUST be removed by either the
            # relay agent or the trusted downstream network element which added
            # it". This relay removes the one it added -- circuit and remote
            # ids describe the access port and are not for the client -- and
            # leaves an element's own for that element to remove.
            del reply.options[int(DHCPOptionCode.RELAY_AGENT_INFORMATION)]

        data = self._encode_for_forward(reply)
        reply.log(
            context.interface.ip, _net.SocketAddress(dest, client_port), _logging.INFO
        )
        self._client_transport(context.transport, egress, msg.giaddr).send(
            data, dest, port=client_port, client_mac=msg.chaddr
        )
        self.metrics.packets_sent += 1
