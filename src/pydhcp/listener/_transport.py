"""How a reply leaves: the plain UDP transport and the one that pins its source."""

from __future__ import annotations

import logging as _logging
import ipaddress as _ipaddress
import select as _select
import socket as _socket
import time as _time
import typing as _ty

import netimps as _netimps

from .. import _constants as _const
from .._metrics import DHCPMetrics
from ._limit import _brief, _LogLimit

LOGGER = _logging.getLogger(__name__)

#: Where a transport built without a listener writes its limited lines.
_FALLBACK_LIMIT = _LogLimit()

#: The all-ones address every DHCP client can be reached at before it has one of
#: its own (RFC 2131 s4.1).
BROADCAST_ADDRESS = "255.255.255.255"


class DHCPTransport(_ty.Protocol):
    """How a reply leaves: anything with a `send` of this shape.

    `UDPTransport` is the one that sends on a socket. A role calls `send` from
    inside a `handle_*` hook, on the handler thread; it returns the octets sent
    and raises `OSError` for a send that failed. `client_mac` is the client's
    hardware address, for a transport that addresses by it.
    """

    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dst: _ipaddress.IPv4Address,
        *,
        port: int,
        client_mac: bytes,
    ) -> int: ...


def _dest_string(dst: _ipaddress.IPv4Address) -> str:
    """The address to actually send a reply to.

    0.0.0.0 in a DHCP header means "this client has no address yet", which on
    the wire is the limited broadcast (RFC 2131 s4.1) -- not a host called
    0.0.0.0, which is what `str()` would produce and what `sendto` would then
    reject or silently route nowhere.
    """
    return BROADCAST_ADDRESS if dst == _const.WILDCARD_V4 else str(dst)


class UDPTransport(DHCPTransport):
    #: Seconds a reply waits for a full send buffer to drain before it is given
    #: up on. The asyncio listener makes its sockets non-blocking and replies
    #: from its one worker thread, so a full buffer raises `BlockingIOError`
    #: there; the wait holds the worker for at most this long.
    SEND_WAIT_SECONDS: float = 1.0

    def __init__(self, socket: _socket.socket):
        self.socket = socket

    def _until_writable(self, send: "_ty.Callable[[], int]") -> int:
        """Run ``send``, waiting for room when the socket's send buffer is full.

        A full buffer on a non-blocking socket is not a failure of the send's
        arguments (a pin, a route): the send is repeated as it was once the
        socket is writable, for at most `SEND_WAIT_SECONDS`, and then raised as
        it is.
        """
        deadline: "_ty.Optional[float]" = None
        while True:
            try:
                return send()
            except BlockingIOError:
                now = _time.monotonic()
                if deadline is None:
                    deadline = now + self.SEND_WAIT_SECONDS
                if deadline - now <= 0:
                    raise
                _select.select([], [self.socket], [], deadline - now)

    def _send_to(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest_str: str,
        port: int,
    ) -> int:
        """One `sendto`, with no fallback of any kind."""
        return self._until_writable(lambda: self.socket.sendto(data, (dest_str, port)))

    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dst: _ipaddress.IPv4Address,
        *,
        port: int,
        client_mac: bytes,
    ) -> int:
        # No broadcast retry on failure. It was written for the case where a
        # unicast cannot reach a client that has no address yet -- "standard UDP
        # sockets can't target an L2 MAC if there is no ARP entry" -- but that
        # case does not raise: the kernel ARPs for an address nobody answers for
        # and drops the datagram silently, which is precisely how the original
        # POSIX no-reply defect went unnoticed. So the retry never fired for
        # what it was written for, and only ever fired for real socket errors --
        # EACCES, ENETUNREACH, a closed socket -- where a broadcast is both
        # useless and a disclosure: it puts a reply the caller deliberately
        # unicast onto the whole segment, carrying yiaddr, chaddr, the lease
        # options and any echoed option 82.
        #
        # Deciding *whether* a reply should be broadcast belongs to the caller
        # and is already made there: the server picks 255.255.255.255 for a
        # client with no address, `_dest_string` maps a 0.0.0.0 destination to
        # it, and a relay picks the client-facing address. The transport's job
        # is to send where it was told and report when it cannot.
        #
        # Future RawTransport can be plugged in here to craft L2 Ethernet frames
        # targeting client_mac, which is the real answer for an unconfigured
        # client on a segment where broadcast is unwanted.
        return self._send_to(data, _dest_string(dst), port)


class PktInfoUDPTransport(UDPTransport):
    """A transport that sends from the address a request arrived on.

    For a wildcard socket: the reply leaves from ``local_ip``, the address the
    request was sent to or the receiving interface's own, which the routing
    table alone would not choose on a multi-homed host. Pinning goes through
    `netimps.UDPEndpoint.send(src=...)`, which builds the per-platform control
    message -- Linux, macOS and Windows lay it out three different ways.

    What is pinned depends on where the reply goes:

    - **A broadcast** (the limited broadcast, which is also where a
      destination of 0.0.0.0 goes) is pinned to the address *and* the arrival
      interface's index, where the platform takes both, because a broadcast is
      put on the wire of the interface it is sent from. If that pin fails, it
      is tried once more with the address alone, which the kernel still keeps
      on the interface that owns the address. If that fails too the reply is
      dropped and counted: sent unpinned it would leave by whichever interface
      the routing table picks and reach a segment the client is not on.
    - **A unicast** is pinned to the address alone. An index would force it out
      of the arrival interface even when its route is through another one, and
      the kernel then waits for an ARP answer that never comes and loses the
      reply without an error. A failed pin is retried unpinned: the routing
      table delivers a unicast to where it belongs.

    A full send buffer is neither: see `UDPTransport.SEND_WAIT_SECONDS`.
    """

    def __init__(
        self,
        socket: _socket.socket,
        endpoint: "_ty.Optional[_netimps.UDPEndpoint]" = None,
    ):
        super().__init__(socket)
        self.ifindex: int | None = None
        self.local_ip: _ipaddress.IPv4Address | None = None
        #: The listener's log limit; a transport made by hand uses a shared one.
        self.limit: _ty.Optional[_LogLimit] = None
        #: The listener's counters, for a reply that is dropped.
        self.metrics: _ty.Optional[DHCPMetrics] = None
        self.endpoint = endpoint or _netimps.UDPEndpoint(socket, pktinfo=False)

    def _source(self) -> _netimps.Interface:
        """The pin by address and index, as a netimps `Interface`.

        Holds exactly ``local_ip``: not the bare address, which netimps resolves
        to its interface by enumerating every adapter on each send, and not the
        receiving adapter's own `Interface`, which may hold several IPv4
        addresses, of which the reply must come from the one the client addressed.
        """
        assert self.local_ip is not None
        return _netimps.Interface(
            name=f"ifindex {self.ifindex or 0}",
            index=self.ifindex or 0,
            ips=[_ipaddress.IPv4Interface(self.local_ip)],
        )

    def _limited(self, level: int, reason: str, message: str, *args: object) -> None:
        (self.limit or _FALLBACK_LIMIT).log(
            LOGGER, level, reason, message, *args, now=_time.monotonic()
        )

    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dst: _ipaddress.IPv4Address,
        *,
        port: int,
        client_mac: bytes,
    ) -> int:
        # `_dest_string`, not `str(dest)`: a yiaddr of 0.0.0.0 -- the normal
        # case for a client that has no address yet -- must go to the limited
        # broadcast and never to host 0.0.0.0.
        dest_str = _dest_string(dst)
        if self.local_ip is None or not self.endpoint.has_src_pinning:
            return super().send(data, dst, port=port, client_mac=client_mac)
        if dest_str == BROADCAST_ADDRESS:
            return self._send_broadcast(data, dest_str, port)
        return self._send_unicast(data, dest_str, port)

    def _pinned(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest_str: str,
        port: int,
        source: "_ty.Union[_netimps.Interface, _ipaddress.IPv4Address]",
    ) -> int:
        return self._until_writable(
            lambda: int(self.endpoint.send(bytes(data), dest_str, port, src=source))
        )

    def _send_broadcast(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest_str: str,
        port: int,
    ) -> int:
        assert self.local_ip is not None
        by_index = self.ifindex is not None and self.ifindex > 0
        try:
            return self._pinned(
                data, dest_str, port, self._source() if by_index else self.local_ip
            )
        except BlockingIOError:
            raise
        except (OSError, ValueError) as first:
            self._limited(
                _logging.WARNING,
                "pinned send failed",
                "Pinned send from %s (ifindex %s) failed (%s | %s)%s.",
                self.local_ip,
                self.ifindex,
                first.__class__.__name__,
                _brief(first),
                "; retrying with the address alone" if by_index else "",
            )
            failure: Exception = first
            if by_index:
                try:
                    return self._pinned(data, dest_str, port, self.local_ip)
                except BlockingIOError:
                    raise
                except (OSError, ValueError) as second:
                    failure = second
            # Never unpinned: a broadcast with no pin leaves by whichever
            # interface the routing table picks, which may be another segment.
            if self.metrics is not None:
                self.metrics.replies_dropped_pin += 1
            self._limited(
                _logging.WARNING,
                "broadcast reply dropped",
                "Dropping a broadcast reply to port %s: it cannot be pinned to %s "
                "(%s | %s), and unpinned it could leave by another interface.",
                port,
                self.local_ip,
                failure.__class__.__name__,
                _brief(failure),
            )
            raise failure

    def _send_unicast(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest_str: str,
        port: int,
    ) -> int:
        assert self.local_ip is not None
        try:
            return self._pinned(data, dest_str, port, self.local_ip)
        except BlockingIOError:
            raise
        except (OSError, ValueError) as e:
            # Deliberately `_send_to` and not `super().send()`: the base send
            # does not escalate a failed unicast to a broadcast either, and this
            # must not become a way to. A broadcast would put a reply the caller
            # deliberately unicast (a RENEWING client at its own ciaddr, a relay
            # at giaddr) with its yiaddr, chaddr, lease options and echoed
            # option 82 in front of every host on the segment.
            self._limited(
                _logging.WARNING,
                "pinned send failed",
                "Pinned send from %s (ifindex %s) failed (%s | %s); retrying "
                "unpinned to %s.",
                self.local_ip,
                self.ifindex,
                e.__class__.__name__,
                _brief(e),
                dest_str,
            )
            return self._send_to(data, dest_str, port)


class _Datagram(_ty.NamedTuple):
    """One datagram a protocol core wants sent, and to whom."""

    data: _ty.Union[bytes, bytearray]
    dst: _ipaddress.IPv4Address
    port: int
    client_mac: bytes
