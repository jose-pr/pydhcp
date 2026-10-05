"""One received datagram: packet-info support, the netimps conversion, and its context."""

from __future__ import annotations

import ipaddress as _ipaddress
import socket as _socket
import typing as _ty

import netimps as _netimps

from .. import network as _net
from ..log import LOGGER
from .interfaces import _resolve_interface
from .spec import ListenSpec, _listen_uses_wildcard
from .transport import BROADCAST_ADDRESS, PktInfoUdpTransport, Transport, UdpTransport


class _TruncatedDatagram(Exception):
    """A datagram longer than `max_packet_size` arrived and was cut short.

    Not an error the peer can be blamed for and not one a retry fixes: the
    remedy is a larger `max_packet_size`. Raised so the receive loop can say
    that, instead of handing a half-message to the decoder.
    """


class RequestContext(_ty.NamedTuple):
    transport: Transport
    interface: _net.NetworkInterface
    client: _net.SocketAddress
    client_mac: bytes
    ifindex: int | None = None
    local_ip: _net.IPv4 | None = None


def _pktinfo_supported(listen: ListenSpec, per_interface: "bool | None") -> bool:
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


Arrival = _ty.Tuple[bytes, _net.SocketAddress, "int | None", "_net.IPv4 | None"]


def _arrival(datagram: _netimps.Datagram, max_packet_size: int) -> Arrival:
    """Turn one netimps `Datagram` into ``(data, client, ifindex, local_ip)``.

    The one conversion both listeners use, for every receive path.

    ``local_ip`` is **this host's address on the receiving interface** -- what
    the reply's SERVER_IDENTIFIER and source are derived from -- which is not
    always what netimps reports. `Datagram.local_address` is the datagram's
    *destination*: for a broadcast DISCOVER that is 255.255.255.255 (or a subnet
    broadcast), which names no interface. The old Linux-only receive path read
    `ipi_spec_dst` instead, the kernel's choice of local address, which macOS
    zero-fills and Windows does not report at all -- so it only ever worked on
    Linux. When the destination is not one of the interface's own addresses,
    the interface's IPv4 address stands in for it, a non-APIPA one first.
    """
    data = datagram.data
    sender = datagram.sender
    # Every listener socket is AF_INET, so the sender is IPv4; `unmap` only
    # normalises the type (and would undo a v4-mapped form if that changed).
    client = _net.SocketAddress(
        _ty.cast(_net.IPv4, _netimps.unmap(sender[0])), int(sender[1])
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
    local: "_net.IPv4 | None" = None
    destination = datagram.destination
    if destination is not None:
        unmapped = _netimps.unmap(destination)
        if isinstance(unmapped, _net.IPv4) and not unmapped.is_unspecified:
            local = unmapped
    interface = datagram.interface
    if interface is not None:
        own = [
            address.ip
            for address in interface.ips
            if isinstance(address, _ipaddress.IPv4Interface)
        ]
        if local not in own:
            preferred = [ip for ip in own if ip not in _net.LINK_LOCAL_V4] or own
            local = preferred[0] if preferred else None
    elif local is not None and (local.is_multicast or str(local) == BROADCAST_ADDRESS):
        local = None
    return data, client, ifindex, local


def _context_for(
    sock: _socket.socket,
    client: _net.SocketAddress,
    client_mac: bytes,
    ifindex: "int | None" = None,
    local_ip: "_net.IPv4 | None" = None,
    endpoint: "_netimps.UDPEndpoint | None" = None,
) -> RequestContext:
    """Build the context for one received datagram.

    Shared by both listeners: duplicating it is what let the async half miss
    every fix the sync half gained. ``endpoint`` is the one the datagram was
    received through, reused for the pinned reply.
    """
    transport: Transport
    if ifindex is not None or local_ip is not None:
        pkt_transport = PktInfoUdpTransport(sock, endpoint)
        pkt_transport.ifindex = ifindex
        pkt_transport.local_ip = local_ip
        transport = pkt_transport
    else:
        transport = UdpTransport(sock)
    return RequestContext(
        transport=transport,
        interface=_resolve_interface(sock, local_ip, ifindex),
        client=client,
        client_mac=client_mac,
        ifindex=ifindex,
        local_ip=local_ip,
    )
