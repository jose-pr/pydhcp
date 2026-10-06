"""One received datagram: packet-info support, the netimps conversion, and its context."""

from __future__ import annotations

import datetime as _dt
import logging as _logging
import ipaddress as _ipaddress
import socket as _socket
import typing as _ty

import netimps as _netimps

from .. import _network as _net
from .._clock import _Instant
from ._interfaces import _resolve_interface
from ._spec import ListenSpec, _listen_uses_wildcard
from ._transport import PktInfoUDPTransport, DHCPTransport, UDPTransport

LOGGER = _logging.getLogger(__name__)


class _TruncatedDatagram(Exception):
    """A datagram longer than `max_packet_size` arrived and was cut short.

    Not an error the peer can be blamed for and not one a retry fixes: the
    remedy is a larger `max_packet_size`. Raised so the receive loop can say
    that, instead of handing a half-message to the decoder.
    """


class DHCPRequestContext(_ty.NamedTuple):
    transport: DHCPTransport
    interface: _net.NetworkInterface
    client: _net.SocketAddress
    client_mac: bytes
    ifindex: _ty.Optional[int] = None
    local_ip: _ty.Optional[_ipaddress.IPv4Address] = None
    #: When the datagram arrived: timezone-aware UTC wall-clock time, and
    #: `time.monotonic()` seconds. Stamped by the listener that received it;
    #: `None` on a context built by hand.
    received_at: _ty.Optional[_dt.datetime] = None
    received_monotonic: _ty.Optional[float] = None


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


def _pktinfo_supported(listen: ListenSpec, per_interface: "_ty.Optional[bool]") -> bool:
    """Whether this listener receives through the packet-info path.

    Only a wildcard bind needs it. Without it a wildcard has to be expanded into
    one socket per address -- which on Linux then receives no broadcasts at all,
    so a client's DISCOVER never arrives.

    `netimps.has_pktinfo` decides by asking a socket, never by testing a
    constant's name: `getattr(socket, "IP_PKTINFO", None)` is None on CPython
    3.9-3.11 on every platform while the kernel supports it throughout, which
    is how this path used to be silently off across half the supported range.
    """
    return (
        per_interface is not True
        and _listen_uses_wildcard(listen)
        and _netimps.has_pktinfo(_socket.AF_INET)
    )


Arrival = _ty.Tuple[
    bytes, _net.SocketAddress, _ty.Optional[int], _ty.Optional[_ipaddress.IPv4Address]
]


def _arrival(datagram: _netimps.Datagram, max_packet_size: int) -> Arrival:
    """Turn one netimps `Datagram` into ``(data, client, ifindex, local_ip)``.

    The one conversion both listeners use, for every receive path.

    ``local_ip`` is **this host's address on the receiving interface** -- what
    the reply's SERVER_IDENTIFIER and source are derived from -- which is not
    always what netimps reports. `Datagram.destination` is the address the datagram
    was sent *to*: for a broadcast DISCOVER that is 255.255.255.255 (or a subnet
    broadcast), which names no interface. The old Linux-only receive path read
    `ipi_spec_dst` instead, the kernel's choice of local address, which macOS
    zero-fills and Windows does not report at all -- so it only ever worked on
    Linux. When the destination is not one of the interface's own addresses,
    the interface's `primary_ip()` stands in for it: a routable address, else a
    loopback one, else a link-local one.
    """
    data = datagram.data
    sender = datagram.sender
    # Every listener socket is AF_INET, so the sender is IPv4; `unmap` only
    # normalises the type (and would undo a v4-mapped form if that changed).
    client = _net.SocketAddress(
        _ty.cast(_ipaddress.IPv4Address, _netimps.unmap(sender[0])), int(sender[1])
    )
    # Either signal means the payload was cut: `truncated` is MSG_TRUNC, and a
    # datagram that fills the one-octet-larger buffer was longer than the limit
    # on a path that does not report the flag. Measured on Linux with
    # max_packet_size=576: a 1102-octet datagram arrived cut to 576, and the
    # decoder was then handed a message whose option stream stops mid-option.
    if datagram.truncated or len(data) > max_packet_size:
        raise _TruncatedDatagram(
            f"datagram from {client} exceeded max_packet_size="
            f"{max_packet_size}; {min(len(data), max_packet_size)} octets kept"
        )
    if datagram.control_truncated:
        # The payload is intact but the control message was cut, so the
        # interface below may be missing or partial. Worth saying: the reply's
        # SERVER_IDENTIFIER and egress interface are derived from it.
        LOGGER.warning(
            f"Packet-info control data truncated for a datagram from "
            f"{client}; the receiving interface may be resolved wrongly."
        )
    ifindex = datagram.interface_index or None
    local: "_ipaddress.IPv4Address | None" = None
    destination = datagram.destination
    if destination is not None:
        unmapped = _netimps.unmap(destination)
        if isinstance(unmapped, _ipaddress.IPv4Address) and not unmapped.is_unspecified:
            local = unmapped
    interface = datagram.interface
    if interface is not None:
        own = [
            address.ip
            for address in interface.ips
            if isinstance(address, _ipaddress.IPv4Interface)
        ]
        if local not in own:
            primary = interface.primary_ip()
            # primary_ip() is typed for both families and answers from the IPv4
            # entries unless asked for IPv6.
            local = (
                _ty.cast(_ipaddress.IPv4Address, primary.ip)
                if primary is not None
                else None
            )
    elif local is not None and datagram.is_unicast is False:
        local = None
    return data, client, ifindex, local


def _context_for(
    sock: _socket.socket,
    client: _net.SocketAddress,
    client_mac: bytes,
    ifindex: "_ty.Optional[int]" = None,
    local_ip: "_ty.Optional[_ipaddress.IPv4Address]" = None,
    endpoint: "_ty.Optional[_netimps.UDPEndpoint]" = None,
    received: "_ty.Optional[_Instant]" = None,
) -> DHCPRequestContext:
    """Build the context for one received datagram.

    Shared by both listeners: duplicating it is what let the async half miss
    every fix the sync half gained. ``endpoint`` is the one the datagram was
    received through, reused for the pinned reply. ``received`` is the time the
    driver read when the datagram arrived.
    """
    transport: DHCPTransport
    if ifindex is not None or local_ip is not None:
        pkt_transport = PktInfoUDPTransport(sock, endpoint)
        pkt_transport.ifindex = ifindex
        pkt_transport.local_ip = local_ip
        transport = pkt_transport
    else:
        transport = UDPTransport(sock)
    return DHCPRequestContext(
        transport=transport,
        interface=_resolve_interface(sock, local_ip, ifindex),
        client=client,
        client_mac=client_mac,
        ifindex=ifindex,
        local_ip=local_ip,
        received_at=received.utc if received is not None else None,
        received_monotonic=received.monotonic if received is not None else None,
    )
