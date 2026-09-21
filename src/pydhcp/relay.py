from __future__ import annotations

import logging as _logging
import time as _time
import typing as _ty

from .packet.message import DhcpMessage
from .listener import (
    AsyncDhcpListener as _AsyncBase,
    DhcpListener as _Base,
    ListenSpec,
    PktInfoUdpTransport as _PktInfoUdpTransport,
    RequestContext,
    Transport as _Transport,
    UdpTransport as _UdpTransport,
)
from . import network as _net, constants as _const
from .packet import enums as _enum
from .options import DhcpOptionCode
from .options import type as _type
from .log import LOGGER
from .server import _is_loopback

ServerAddress = _ty.Union[_net.IPv4, str, tuple[_ty.Union[_net.IPv4, str], int]]

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


class PendingClient(_ty.NamedTuple):
    """Where a forwarded request came from, so its reply can be sent back there.

    The reply arrives on the *server*-facing interface, but has to leave on the
    client-facing one. On a wildcard bind that is not something the kernel can
    work out: a broadcast would go out the default route and never reach the
    client's segment. The ingress interface recorded here is what pins it back.
    """

    client: _net.SocketAddress
    ifindex: _ty.Optional[int] = None
    local_ip: _ty.Optional[_net.IPv4] = None
    #: When it was recorded, so a stale entry ages out instead of being popped
    #: by whichever reply happens to arrive first.
    recorded_at: float = 0.0


def _normalize_server_address(address: ServerAddress) -> tuple[_net.IPv4, int]:
    """Coerce one upstream server entry to `(IPv4, port)`.

    The error says what is wrong and what is accepted. `IPv4()`'s own message
    is "Expected 4 octets in '::1'", which is true and tells an operator who
    passed an IPv6 address or a hostname neither which argument was at fault
    nor that only IPv4 is supported -- and it arrives *after* the "Starting
    DHCP relay" line, so it reads as a runtime failure rather than a bad
    argument.
    """
    ip, port = (
        address if isinstance(address, tuple) else (address, _enum.DhcpPort.SERVER)
    )
    try:
        return _net.IPv4(ip), int(port)
    except (ValueError, TypeError) as e:
        raise ValueError(
            f"upstream server address {ip!r} is not an IPv4 address ({e}). "
            "This relay forwards over IPv4 only, so a hostname or an IPv6 "
            "address cannot be used here."
        ) from None


class DhcpRelay(_Base):
    """RFC 1542 / RFC 2131 4.1 / RFC 3046 DHCP relay agent.

    Forwards client broadcasts (received on port 67, same as a server) to one or
    more configured upstream DHCP servers, stamping `giaddr` and incrementing
    `hops`. Forwards server replies (unicast back to this relay) on to the
    client, applying the same destination rules a server uses on its own
    client-facing side (broadcast flag, else `yiaddr`/`ciaddr`).

    The `xid -> original client address` map used to route a reply back to a
    client on a non-standard port is bounded at `MAX_PENDING_CLIENTS` entries,
    evicting the oldest first: an xid whose reply never arrives would otherwise
    stay forever and leak memory in a long-running relay. Evicting an entry is
    not a dropped reply -- a reply for a forgotten xid still goes out, to the
    well-known client port 68, which is where a real client listens.
    """

    DEFAULT_PORTS = (_enum.DhcpPort.SERVER,)

    #: Upper bound on in-flight `xid -> client address` entries.
    MAX_PENDING_CLIENTS = 1024

    #: How long a recorded client stays usable. An exchange is over in seconds,
    #: so this only has to outlive a retransmit; entries are kept rather than
    #: popped on the first reply, because several configured servers each send
    #: one and they all go to the same client.
    PENDING_TTL_SECONDS = 60.0

    def __init__(
        self,
        listen: ListenSpec = None,
        server_addresses: _ty.Sequence[ServerAddress] = (),
        max_hops: int = DEFAULT_MAX_HOPS,
        insert_relay_agent_info: bool = False,
        circuit_id: _ty.Optional[bytes] = None,
        remote_id: _ty.Optional[bytes] = None,
        trust_client_relay_agent_info: bool = False,
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
    ) -> None:
        super().__init__(
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_relay_state(
            server_addresses,
            max_hops=max_hops,
            insert_relay_agent_info=insert_relay_agent_info,
            circuit_id=circuit_id,
            remote_id=remote_id,
            trust_client_relay_agent_info=trust_client_relay_agent_info,
        )

    def _init_relay_state(
        self,
        server_addresses: _ty.Sequence[ServerAddress] = (),
        *,
        max_hops: int = DEFAULT_MAX_HOPS,
        insert_relay_agent_info: bool = False,
        circuit_id: _ty.Optional[bytes] = None,
        remote_id: _ty.Optional[bytes] = None,
        trust_client_relay_agent_info: bool = False,
    ) -> None:
        """Set up the state and validation every relay variant needs.

        `AsyncDhcpRelay` cannot call this class's `__init__` (its own base takes
        a different argument set), so without this it would have to re-implement
        the body -- which is precisely how `AsyncDhcpServer` came to be missing
        `_declined`, and how a `max_hops` range check would end up enforced on
        one relay and not the other.
        """
        if not server_addresses:
            raise ValueError("DhcpRelay requires at least one server address")
        self.server_addresses = [_normalize_server_address(a) for a in server_addresses]
        if not 0 <= max_hops <= RFC1542_MAX_HOPS:
            raise ValueError(
                f"max_hops must be between 0 and {RFC1542_MAX_HOPS} "
                f"(RFC 1542 4.1.1), got {max_hops}"
            )
        self.max_hops = max_hops
        self.insert_relay_agent_info = insert_relay_agent_info
        self.circuit_id = circuit_id
        self.remote_id = remote_id
        self.trust_client_relay_agent_info = trust_client_relay_agent_info
        self._server_ips = {ip for ip, _port in self.server_addresses}
        self._pending_clients: _ty.OrderedDict[tuple[int, bytes], PendingClient] = (
            _ty.OrderedDict()
        )

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        if msg.op == _enum.OpCode.BOOTREQUEST:
            self._forward_to_servers(msg, context)
        elif msg.op == _enum.OpCode.BOOTREPLY:
            self._forward_to_client(msg, context)
        else:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Received message with unknown op {msg.op}, ignoring."
            )

    @staticmethod
    def _routed_transport(transport: _Transport) -> _Transport:
        """Drop the IP_PKTINFO source pin for a send to a different network.

        A relay forwards *across* interfaces, which is the one case the pin gets
        wrong. It exists so a server replies out of the interface the request
        arrived on, and the receive path sets it from the ingress packet -- so
        reusing it to reach an upstream server pins the client-facing interface
        and source address for a destination that is not on that link, and the
        datagram is dropped without an error. Measured with ISC dhclient through
        this relay: 8 requests forwarded, 0 reaching the server. Falling back to
        a plain send over the same socket lets the kernel route normally.
        """
        if isinstance(transport, _PktInfoUdpTransport):
            return _UdpTransport(transport.socket)
        return transport

    def _client_transport(
        self, transport: _Transport, pending: _ty.Optional[PendingClient]
    ) -> _Transport:
        """Send out the interface the client's request arrived on."""
        if (
            isinstance(transport, _PktInfoUdpTransport)
            and pending is not None
            and pending.ifindex is not None
        ):
            out = _PktInfoUdpTransport(transport.socket)
            out.ifindex = pending.ifindex
            out.local_ip = pending.local_ip
            return out
        return self._routed_transport(transport)

    def _encode_for_forward(self, msg: DhcpMessage) -> bytearray:
        """Encode a message being forwarded without shrinking it.

        `encode()` defaults to the 576-octet minimum, which is not a limit this
        relay gets to impose: a server reply legitimately exceeds it whenever the
        client advertised a larger maximum (PXE/iPXE boot options, vendor info,
        classless routes). Encoding at the default raised OverflowError and the
        receive loop logged it, so the client simply never got its reply.
        """
        advertised = msg.options.get(
            DhcpOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE, default=None, decode=_type.U16
        )
        limit = int(advertised) if advertised else self._max_packet_size
        return msg.encode(max(limit, _const.DHCP_MIN_LEGAL_PACKET_SIZE))

    def _forward_to_servers(self, msg: DhcpMessage, context: RequestContext) -> None:
        if (
            msg.giaddr == _net.WILDCARD_IPv4
            and DhcpOptionCode.RELAY_AGENT_INFORMATION in msg.options
            and not self.trust_client_relay_agent_info
        ):
            # RFC 3046 s2.1 and s5: giaddr 0 means this came straight from a
            # client, so the option is forged -- a client claiming a circuit id
            # picks its own policy on any server that trusts option 82. Pass
            # trust_client_relay_agent_info=True only when the access layer
            # below is trusted to set it.
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Dropping request from {context.client}: "
                "RELAY_AGENT_INFORMATION present with giaddr 0 (untrusted source)"
            )
            self.metrics.packets_dropped_untrusted += 1
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

        forwarded = DhcpMessage(**msg.__dict__.copy())
        # A shallow __dict__ copy shares the options container, so stamping this
        # copy would edit the caller's message.
        forwarded.options = msg.options.copy()
        forwarded.hops = msg.hops + 1

        if forwarded.giaddr == _net.WILDCARD_IPv4:
            forwarded.giaddr = _ty.cast(_net.IPv4, context.interface.ip)

        self._record_pending(msg, context)
        self._insert_relay_agent_info(forwarded)

        data = self._encode_for_forward(forwarded)
        transport = self._routed_transport(context.transport)
        for server_ip, server_port in self.server_addresses:
            forwarded.log(
                context.interface.ip,
                _net.SocketAddress(server_ip, server_port),
                _logging.INFO,
            )
            transport.send(data, server_ip, server_port, msg.chaddr)
            self.metrics.packets_sent += 1

    def _insert_relay_agent_info(self, msg: DhcpMessage) -> None:
        if not self.insert_relay_agent_info:
            return
        if DhcpOptionCode.RELAY_AGENT_INFORMATION in msg.options:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Request already carries RELAY_AGENT_INFORMATION, passing through unmodified."
            )
            return
        suboptions: list[tuple[int, bytes]] = []
        if self.circuit_id is not None:
            suboptions.append((1, self.circuit_id))
        if self.remote_id is not None:
            suboptions.append((2, self.remote_id))
        if suboptions:
            msg.options[DhcpOptionCode.RELAY_AGENT_INFORMATION] = (
                _type.RelayAgentInformation(suboptions)
            )

    def _pending_key(self, msg: DhcpMessage) -> tuple[int, bytes]:
        """Identify an exchange by transaction *and* client.

        The xid alone is not an identity: it travels in cleartext in a broadcast
        DISCOVER, so any host on the segment can read it and send its own
        request carrying the same one. Keyed by xid alone, that overwrote the
        victim's entry and the relay then sent the victim's OFFER to the
        attacker's port -- the victim never saw it.
        """
        return msg.xid, bytes(msg.chaddr[: msg.hlen or len(msg.chaddr)])

    def _record_pending(self, msg: DhcpMessage, context: RequestContext) -> None:
        """Note where a reply for this exchange has to go.

        Recorded for every client, including one on the standard port 68. It is
        tempting to skip those, since 68 is the fallback anyway -- but the entry
        also carries the ingress interface, and that is what pins the reply back
        onto the client's segment on a wildcard bind. Skipping it would send
        every ordinary client's reply out the default route instead.

        An entry is never replaced by a request from a *different* source
        address: that takeover is what this tracking has to survive.
        """
        key = self._pending_key(msg)
        now = _time.monotonic()
        existing = self._pending_clients.get(key)
        if (
            existing is not None
            and existing.client.ip != context.client.ip
            and now - existing.recorded_at < self.PENDING_TTL_SECONDS
        ):
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Ignoring a request from {context.client} that "
                f"reuses the transaction of {existing.client}"
            )
            return
        self._pending_clients[key] = PendingClient(
            context.client, context.ifindex, context.local_ip, now
        )
        self._pending_clients.move_to_end(key)
        self._expire_pending(now)

    def _lookup_pending(self, msg: DhcpMessage) -> _ty.Optional[PendingClient]:
        """Find where this reply goes, leaving the entry for any further ones.

        Popping on the first reply meant that with more than one server
        configured, the second server's reply had lost the tracked port and fell
        back to 68 -- so which reply reached the client depended on which server
        answered first.
        """
        now = _time.monotonic()
        self._expire_pending(now)
        return self._pending_clients.get(self._pending_key(msg))

    def _expire_pending(self, now: float) -> None:
        """Drop entries past their TTL, then anything over the cap."""
        for key in list(self._pending_clients):
            if now - self._pending_clients[key].recorded_at >= self.PENDING_TTL_SECONDS:
                del self._pending_clients[key]
        while len(self._pending_clients) > self.MAX_PENDING_CLIENTS:
            self._pending_clients.popitem(last=False)

    def _forward_to_client(self, msg: DhcpMessage, context: RequestContext) -> None:
        if context.client.ip not in self._server_ips:
            # Anything that can reach this relay's port 67 could otherwise have a
            # forged ACK broadcast onto the client segment, sourced from the
            # relay's own address -- naming the attacker as router and DNS, and
            # arriving from the port DHCP-snooping switches trust. RFC 1542
            # s4.1.2 assumes replies come from the servers we forwarded to.
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Dropping BOOTREPLY from {context.client}: "
                "not a configured server address"
            )
            self.metrics.packets_dropped_untrusted += 1
            return

        pending = self._lookup_pending(msg)
        client_port = (
            pending.client.port if pending is not None else int(_enum.DhcpPort.CLIENT)
        )

        dest: _net.IPv4
        if msg.flags is _enum.Flags.BROADCAST:
            dest = _net.IPv4("255.255.255.255")
        elif msg.ciaddr != _net.WILDCARD_IPv4:
            dest = msg.ciaddr
        elif msg.yiaddr != _net.WILDCARD_IPv4 and _is_loopback(context):
            # Loopback has no ARP to fail, and POSIX refuses a broadcast from a
            # socket bound to 127.0.0.1 -- see _is_loopback.
            dest = msg.yiaddr
        else:
            # The client has no address yet, so it cannot answer ARP for yiaddr
            # and a unicast is dropped by the kernel with no error -- the same
            # trap DhcpServer.UNICAST_TO_UNCONFIGURED_CLIENT documents.
            dest = _net.IPv4("255.255.255.255")

        reply = DhcpMessage(**msg.__dict__.copy())
        reply.options = msg.options.copy()
        if DhcpOptionCode.RELAY_AGENT_INFORMATION in reply.options:
            # RFC 3046 s2.2: the relay strips the option it echoed back before
            # handing the reply to the client. It is relay-to-server bookkeeping
            # -- circuit and remote ids describe the access port -- and has no
            # meaning to, and should not be disclosed to, the client.
            del reply.options[int(DhcpOptionCode.RELAY_AGENT_INFORMATION)]

        data = self._encode_for_forward(reply)
        reply.log(
            context.interface.ip, _net.SocketAddress(dest, client_port), _logging.INFO
        )
        # The reply arrived on the server-facing interface and has to leave on the
        # client-facing one, so re-pin it to the interface the request came in on
        # rather than reusing this packet's pin or letting the default route
        # swallow the broadcast.
        self._client_transport(context.transport, pending).send(
            data, dest, client_port, msg.chaddr
        )
        self.metrics.packets_sent += 1


class AsyncDhcpRelay(_AsyncBase, DhcpRelay):  # type: ignore[misc]
    """`DhcpRelay`'s forwarding policy on the asyncio listener.

    Mixed the way `AsyncDhcpServer` is, and for the same reason: every line of
    the receive path -- `_pktinfo_supported`, `_recv_with_pktinfo`,
    `_context_for`, `_bind_sockets` -- stays in `listener.py` where both
    listeners reach it. The async half of this project has been written as a
    *copy* once already, and a hardcoded `_pktinfo = False` then left it
    receiving nothing at all on Linux while passing every unit test.

    `_pending_clients` is unguarded, exactly as on `DhcpRelay`. What keeps it
    safe here is that `AsyncDhcpListener` runs handlers on a single worker
    thread, so `handle()` is still serialised and in arrival order.
    """

    #: Read off the sync class rather than repeated: `AsyncDhcpListener`'s
    #: all-ports default comes first in the MRO and would otherwise win, so a
    #: relay would also bind the client port 68.
    DEFAULT_PORTS = DhcpRelay.DEFAULT_PORTS

    def __init__(
        self,
        listen: ListenSpec = None,
        server_addresses: _ty.Sequence[ServerAddress] = (),
        max_hops: int = DEFAULT_MAX_HOPS,
        insert_relay_agent_info: bool = False,
        circuit_id: _ty.Optional[bytes] = None,
        remote_id: _ty.Optional[bytes] = None,
        trust_client_relay_agent_info: bool = False,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
    ) -> None:
        _AsyncBase.__init__(
            self,
            listen=listen,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_relay_state(
            server_addresses,
            max_hops=max_hops,
            insert_relay_agent_info=insert_relay_agent_info,
            circuit_id=circuit_id,
            remote_id=remote_id,
            trust_client_relay_agent_info=trust_client_relay_agent_info,
        )

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        # Both bases define handle() and AsyncDhcpListener's no-op comes first
        # in the MRO; without this the relay would receive and forward nothing.
        DhcpRelay.handle(self, msg, context)
