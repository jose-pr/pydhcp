from __future__ import annotations

import socket as _socket

import netimps as _netimps
import functools as _functools
import ipaddress as _ipaddress
import select as _select
import threading as _thread
import concurrent.futures as _futures
import typing as _ty
import weakref as _weakref

from . import network as _net, constants as _const
from .packet import enums as _enum
from .packet.message import DhcpMessage
from .log import LOGGER
from .metrics import DhcpMetrics
import logging as _logging

#: The all-ones address every DHCP client can be reached at before it has one of
#: its own (RFC 2131 s4.1).
BROADCAST_ADDRESS = "255.255.255.255"

#: WSAEMSGSIZE. Where Linux truncates an oversized datagram and reports it in
#: the recv flags, Windows fails the call outright with this. Same event, two
#: shapes; both become `_TruncatedDatagram` so the log and the counter do not
#: depend on the platform.
_WSAEMSGSIZE = 10040


class _TruncatedDatagram(Exception):
    """A datagram longer than `max_packet_size` arrived and was cut short.

    Not an error the peer can be blamed for and not one a retry fixes: the
    remedy is a larger `max_packet_size`. Raised so the receive loop can say
    that, instead of handing a half-message to the decoder.
    """


ListenAddress = _ty.Union[_net.IPv4, str]
ListenPort = _ty.Union[int, _ty.Sequence[int]]
ListenBinding = _ty.Union[ListenAddress, tuple[ListenAddress, ListenPort]]
ListenSpec = _ty.Optional[_ty.Union[ListenBinding, _ty.Sequence[ListenBinding]]]


class Transport:
    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest: _net.IPv4,
        port: int,
        client_mac: bytes,
    ) -> int:
        raise NotImplementedError()


def _dest_string(dest: _net.IPv4) -> str:
    """The address to actually send a reply to.

    0.0.0.0 in a DHCP header means "this client has no address yet", which on
    the wire is the limited broadcast (RFC 2131 s4.1) -- not a host called
    0.0.0.0, which is what `str()` would produce and what `sendto` would then
    reject or silently route nowhere.
    """
    return BROADCAST_ADDRESS if dest == _net.WILDCARD_IPv4 else str(dest)


class UdpTransport(Transport):
    def __init__(self, socket: _socket.socket):
        self.socket = socket

    def _send_to(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest_str: str,
        port: int,
    ) -> int:
        """One `sendto`, with no fallback of any kind."""
        return self.socket.sendto(data, (dest_str, port))

    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest: _net.IPv4,
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
        # options and any echoed option 82 (`gap1-posix-pktinfo-4`).
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
        return self._send_to(data, _dest_string(dest), port)


class PktInfoUdpTransport(UdpTransport):
    """A transport that sends from a pinned interface and source address.

    For a wildcard socket: the reply leaves from the address and interface the
    request arrived on (``local_ip``, ``ifindex``), which the routing table
    alone would not choose on a multi-homed host. Pinning goes through
    `netimps.UdpEndpoint.send(src=...)`, which builds the per-platform control
    message -- Linux, macOS and Windows lay it out three different ways.
    """

    def __init__(
        self,
        socket: _socket.socket,
        endpoint: "_netimps.UdpEndpoint | None" = None,
    ):
        super().__init__(socket)
        self.ifindex: int | None = None
        self.local_ip: _net.IPv4 | None = None
        self.endpoint = endpoint or _netimps.UdpEndpoint(socket, pktinfo=False)

    def _source(self) -> _netimps.Interface:
        """The pin, as a netimps `Interface` holding exactly ``local_ip``.

        Not the bare address: netimps resolves an address to its interface by
        enumerating every adapter, measured at 1.29 ms per send against 0.04 ms
        for an `Interface` -- per reply, which is the per-packet enumeration
        cost this module has already removed once from the receive side. And not
        the receiving adapter's own `Interface`, which may hold several IPv4
        addresses: netimps would pick one, and the reply must come from the one
        the client addressed. An index of 0 means "unknown" and pins the address
        alone.
        """
        assert self.local_ip is not None
        return _netimps.Interface(
            name=f"ifindex {self.ifindex or 0}",
            index=self.ifindex or 0,
            ips=[_ipaddress.IPv4Interface(self.local_ip)],
        )

    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest: _net.IPv4,
        port: int,
        client_mac: bytes,
    ) -> int:
        dest_str = _dest_string(dest)
        if self.local_ip is not None and self.endpoint.supports_src_pinning:
            try:
                # `_dest_string`, not `str(dest)`: this path took a yiaddr of
                # 0.0.0.0 -- the normal case for a client that has no address
                # yet -- and asked the kernel to send to host 0.0.0.0, which is
                # the one destination a reply to an unconfigured client must
                # never be.
                return int(
                    self.endpoint.send(bytes(data), dest_str, port, src=self._source())
                )
            except Exception as e:
                # This path's own failure modes -- a stale ifindex, a local_ip
                # no longer on that adapter -- used to propagate and lose the
                # reply outright. Retry without the pin, which is the thing that
                # went stale.
                #
                # Deliberately `_send_to` and not `super().send()`: the base
                # send answers a failed *unicast* with a broadcast to the whole
                # segment. That is right for a client with no address yet, and
                # wrong for one the server deliberately unicast to -- a
                # RENEWING client at its own ciaddr, or a relay at giaddr. Going
                # through it here would put yiaddr, chaddr, the lease options
                # and the echoed RELAY_AGENT_INFORMATION (RFC 3046 s2.2, whose
                # circuit-id identifies the subscriber's physical port) in front
                # of every host on the segment. Measured on the version this
                # replaces: sendmsg -> 192.0.2.50, sendto -> 192.0.2.50, sendto
                # -> 255.255.255.255. Same destination, one attempt, and the
                # error propagates if it fails.
                LOGGER.warning(
                    f"Pinned send from {self.local_ip} (ifindex {self.ifindex}) "
                    f"failed ({e.__class__.__name__} | {e}); retrying unpinned to "
                    f"{dest_str}."
                )
                return self._send_to(data, dest_str, port)
        return super().send(data, dest, port, client_mac)


class RequestContext(_ty.NamedTuple):
    transport: Transport
    interface: _net.NetworkInterface
    client: _net.SocketAddress
    client_mac: bytes
    ifindex: int | None = None
    local_ip: _net.IPv4 | None = None


def _split_listen_string(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _split_host_port(value: str) -> tuple[str, int | None]:
    """Split ``host:port``, defaulting an empty host to the IPv4 wildcard.

    Delegates to :func:`netimps.normalize_host`, which handles the IPv6 forms
    the previous implementation could not: ``[::1]:67`` now yields
    ``("::1", 67)`` rather than silently dropping the port, and a bare ``::1``
    stays an address instead of being read as host ``::`` port ``1``.
    """
    # ":67" means "wildcard, port 67" here, but is an empty host to a strict
    # parser -- normalize it before delegating rather than losing the form.
    if value.startswith(":") and not value.startswith("::"):
        value = "0.0.0.0" + value

    host, port = _netimps.normalize_host(value)
    return host or "0.0.0.0", port


def _iter_listen_bindings(listen: ListenSpec) -> _ty.Iterator[ListenBinding]:
    if listen is None:
        return
    if isinstance(listen, str):
        for part in _split_listen_string(listen):
            yield part
        return
    if isinstance(listen, tuple):
        yield listen
        return
    if isinstance(listen, _net.IPv4):
        yield listen
        return
    for binding in listen:
        if isinstance(binding, str) and "," in binding:
            for part in _split_listen_string(binding):
                yield part
        else:
            yield binding


def _binding_host(binding: ListenBinding) -> ListenAddress:
    """The host part of one listen binding, with any ``:port`` removed.

    Comparing the raw binding is what made ``"0.0.0.0:67"`` and ``"*:67"`` fail
    to count as wildcards: they skipped the packet-info path and expanded into
    one socket per address, and on Linux an address-bound socket receives no
    limited broadcasts -- measured, 0 of 3 broadcast DISCOVERs seen, against 3 of
    3 for ``("0.0.0.0", 67)``.
    """
    ip = binding[0] if isinstance(binding, tuple) else binding
    if not isinstance(ip, str):
        return ip
    ip = ip.strip()
    if ip == "*" or ip.startswith("*:"):
        return "0.0.0.0"
    try:
        return _split_host_port(ip)[0]
    except ValueError:
        return ip


def _listen_uses_wildcard(listen: ListenSpec) -> bool:
    return any(
        _netimps.is_wildcard(_binding_host(binding))
        for binding in _iter_listen_bindings(listen)
    )


def _parselisteners(
    listen: ListenSpec = None,
    default_ports: _ty.Sequence[int] = (),
    expand_wildcard: bool = True,
) -> list[_net.SocketAddress]:
    _listen: list[_net.SocketAddress] = []
    for bind in _iter_listen_bindings(listen):
        port: _ty.Optional[_ty.Union[int, _ty.Sequence[int]]]
        if not isinstance(bind, tuple):
            ip, port = _split_host_port(bind) if isinstance(bind, str) else (bind, None)
        else:
            ip, port = bind
            if isinstance(ip, str):
                ip, parsed_port = _split_host_port(ip)
                if port is None:
                    port = parsed_port

        if not ip:
            ip = "127.0.0.1"
        elif ip == "*":
            ip = _net.WILDCARD_IPv4
        if not isinstance(ip, _net.IPv4):
            ip = _net.IPv4(ip)

        if ip == _net.WILDCARD_IPv4 and expand_wildcard:
            ips = [
                i.ip for i in _net.host_ip_interfaces() if isinstance(i.ip, _net.IPv4)
            ]
        else:
            ips = [ip]
        for ip in ips:
            ports: _ty.Sequence[int]
            if port is None:
                ports = default_ports
            elif isinstance(port, int):
                ports = [port]
            else:
                ports = port
            for p in ports:
                p = int(p)
                bind_addr = _net.SocketAddress(ip, p)
                if bind_addr not in _listen:
                    _listen.append(bind_addr)
    return _listen


#: Resolved interfaces, keyed by (ifindex, local address). Enumerating every host
#: adapter costs tens of milliseconds on Windows, and it was paid per datagram --
#: enough that a modest flood denied service on its own. Cleared by `bind()`, which
#: is the point at which the set of addresses this listener serves can change.
_INTERFACE_CACHE: dict[tuple[int, str], _net.NetworkInterface] = {}


#: Every cache keyed by "what addresses does this host have", dropped together
#: whenever a listener binds. Binding is the one moment both listeners pass
#: through, and the moment that answer can change.
_ADDRESS_CACHES: "list[_ty.MutableMapping[_ty.Any, _ty.Any]]" = [_INTERFACE_CACHE]


def _register_address_cache(cache: "_ty.MutableMapping[_ty.Any, _ty.Any]") -> None:
    """Have `cache` dropped on every bind, alongside `_INTERFACE_CACHE`.

    So that a second module caching the same kind of answer -- `server.py`
    memoising which servable interface holds an address -- cannot end up with a
    different invalidation point from this one.
    """
    _ADDRESS_CACHES.append(cache)


def _clear_interface_cache() -> None:
    for cache in _ADDRESS_CACHES:
        cache.clear()


#: The address each socket was *asked* to bind, which is not what it ended up
#: bound to whenever that request named port 0. `_bind_sockets` matches already
#: open sockets against the requested list, and keying them by `getsockname()`
#: meant a port-0 request never matched the socket it had produced: measured, a
#: second `bind()` closed the socket on port 52908 and opened a new one on
#: 52909, so every caller holding the first port was talking to a closed socket.
#: Weak keys, so an entry disappears with the socket it describes rather than
#: pinning a closed one alive for the process's lifetime.
_REQUESTED_ADDRESS: "_ty.MutableMapping[_socket.socket, _net.SocketAddress]" = (
    _weakref.WeakKeyDictionary()
)


@_functools.lru_cache(maxsize=None)
def _platform_reports_pktinfo() -> bool:
    """Whether an IPv4 UDP socket here can report the interface a datagram
    arrived on, decided by asking one rather than by feature-testing names.

    The feature test is what was wrong: `getattr(socket, "IP_PKTINFO", None)`
    is None on CPython 3.9-3.11 on every platform (the constant arrived in
    3.12) and on Windows before that, while the kernel supports it throughout.
    netimps' `UdpEndpoint` uses the documented per-platform values and decides
    from the socket's own family, so a throwaway endpoint gives the real answer.
    """
    probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        return bool(_netimps.UdpEndpoint(probe).supports_pktinfo)
    finally:
        probe.close()


def _pktinfo_supported(listen: ListenSpec, per_interface: "bool | None") -> bool:
    """Whether this listener receives through the packet-info path.

    Only a wildcard bind needs it. Without it a wildcard has to be expanded into
    one socket per address -- which on Linux then receives no broadcasts at all,
    so a client's DISCOVER never arrives.
    """
    return (
        per_interface is not True
        and _listen_uses_wildcard(listen)
        and _platform_reports_pktinfo()
    )


def _raise_bind_error(error: OSError, address: _net.SocketAddress) -> "_ty.NoReturn":
    """Re-raise a failed bind with the DHCP-specific next step appended.

    "The port is taken" is decided by netimps, which raises
    `AddressInUseError` for every shape of it: WSAEADDRINUSE, POSIX
    EADDRINUSE, and Windows' WSAEACCES against an exclusive holder -- which
    Python maps onto errno 13 and so used to arrive as a `PermissionError`,
    for a port that is merely in use (Windows has no privileged ports). That
    type is kept, so `except PermissionError` never catches an in-use port.
    """
    if isinstance(error, _netimps.AddressInUseError):
        raise _netimps.AddressInUseError(
            error.errno, f"{error.strerror or error}; try port {address.port + 1000}."
        ) from error
    hint = _netimps.bind_error_hint(error, address.port)
    if hint is None:
        raise error
    if isinstance(error, PermissionError) or "permission" in hint.lower():
        raise PermissionError(f"{hint}. Try 6767 for testing.") from error
    raise OSError(error.errno, hint) from error


def _bind_sockets(
    listen: "_ty.Sequence[_net.SocketAddress]",
    sockets: "list[_socket.socket]",
    endpoints: "dict[_socket.socket, _netimps.UdpEndpoint]",
    pktinfo: bool,
    label: str = "",
    reuse_address: bool = False,
) -> None:
    """Bind one socket per listen address, reusing any already bound.

    Shared by both listeners. Held apart, the async copy silently lacked the
    packet-info option and the bind-error hints, so the same mistake produced a
    helpful message from one listener and a bare errno from the other.

    Every socket gets a `netimps.UdpEndpoint` in `endpoints`, which is what both
    listeners receive through; a wildcard one asks it for packet info, which it
    enables itself with the right per-platform option.

    Idempotent, including for port 0: an already open socket is matched against
    the address it was *asked* for, not the one it was given, so re-binding a
    port-0 listener keeps the ephemeral port it already has. See
    `_REQUESTED_ADDRESS`.
    """
    _clear_interface_cache()
    active: "dict[_net.SocketAddress, _socket.socket]" = {}
    for sock in sockets:
        requested = _REQUESTED_ADDRESS.get(sock)
        if requested is None:  # pragma: no cover - not bound through here
            try:
                requested = _net.SocketAddress(sock)
            except OSError:
                continue
        active[requested] = sock
    wanted = []
    for address in listen:
        wanted.append(address)
        if address in active:
            continue
        LOGGER.info(f"Listening on{' (' + label + ')' if label else ''}: {address}")
        try:
            # Exclusive unless REUSE_ADDRESS: a second listener binding a port
            # the first held used to *succeed silently* and receive nothing --
            # a misconfiguration, or another process quietly taking over a DHCP
            # port, that looked exactly like a working start-up. netimps makes
            # the exclusive bind the default on both platforms.
            #
            # connreset=False: on Windows an ICMP port-unreachable provoked by
            # an earlier reply otherwise surfaces as ConnectionResetError on a
            # *later, unrelated* receive -- measured, one client that had gone
            # away logged a full ERROR traceback on the server.
            sock = address.listen(
                _socket.AF_INET,
                _socket.SOCK_DGRAM,
                _socket.IPPROTO_UDP,
                broadcast=True,
                allow_address_takeover=reuse_address,
                connreset=False,
            )
        except OSError as e:
            _raise_bind_error(e, address)
        endpoints[sock] = _netimps.UdpEndpoint(
            sock, pktinfo=pktinfo and address.ip == _net.WILDCARD_IPv4
        )
        _REQUESTED_ADDRESS[sock] = address
        sockets.append(sock)
    for address, sock in active.items():
        if address not in wanted:
            sockets.remove(sock)
            _close_socket(sock, endpoints)


def _close_socket(
    sock: _socket.socket, endpoints: "dict[_socket.socket, _netimps.UdpEndpoint]"
) -> None:
    """Close `sock` through its endpoint where it has one.

    `UdpEndpoint.close()` also retires the thread netimps uses to wait on a
    Windows proactor loop, which a bare `socket.close()` would strand.
    """
    endpoint = endpoints.pop(sock, None)
    try:
        if endpoint is not None:
            endpoint.close()
        else:
            sock.close()
    except Exception:
        pass


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
    destination = datagram.local_address
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
            preferred = [ip for ip in own if ip not in _net.APIPA] or own
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
    endpoint: "_netimps.UdpEndpoint | None" = None,
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


def _resolve_interface(
    sock: _socket.socket,
    pkt_local_ip: _ty.Optional[_net.IPv4] = None,
    pkt_ifindex: _ty.Optional[int] = None,
) -> _net.NetworkInterface:
    """Find the NetworkInterface a datagram actually arrived on.

    ``pkt_local_ip``/``pkt_ifindex`` come from the ``IP_PKTINFO`` control message
    and are authoritative when present: the pktinfo path only runs on a wildcard
    bind, where ``getsockname()`` reports 0.0.0.0 -- precisely the information
    pktinfo exists to supply. The address picks the adapter and which of its
    addresses (a NIC may hold several, and the reply's SERVER_IDENTIFIER must be
    the right one); the index is the fallback when the address names none.

    Falls back to a synthetic host-route entry when nothing matches, which keeps
    callers from having to special-case it. Results are cached per
    (ifindex, address) and `bind()` clears the cache: the lookup is
    `netimps.interface_for`, which enumerates every adapter on each call --
    tens of milliseconds on Windows, paid per datagram before this cache.

    A local address of 0.0.0.0 is no address at all and is treated as absent.
    It is what a zero-filled `ipi_spec_dst` decodes to, and taking it literally
    skipped the index lookup (which applies only when the address is None), so
    the datagram resolved to a synthetic `unknown[0.0.0.0]/32` -- a network with
    nothing in it to lease. Measured: the server received the DISCOVER and
    allocated and sent nothing.
    """
    if pkt_local_ip is not None and pkt_local_ip.is_unspecified:
        pkt_local_ip = None
    if pkt_local_ip is None and pkt_ifindex is None:
        try:
            sock_ip, _port = sock.getsockname()
        except Exception:
            sock_ip = "127.0.0.1"
        cache_key = (0, sock_ip)
    else:
        cache_key = (pkt_ifindex or 0, str(pkt_local_ip) if pkt_local_ip else "")
    cached = _INTERFACE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    resolved = _resolve_interface_uncached(sock, pkt_local_ip, pkt_ifindex)
    _INTERFACE_CACHE[cache_key] = resolved
    return resolved


def _network_interface(
    interface: _netimps.Interface, address: "_net.IPv4 | None" = None
) -> "_net.NetworkInterface | None":
    """pydhcp's per-address view of one netimps adapter.

    ``address`` picks which of its addresses -- a NIC may hold several, and the
    reply's SERVER_IDENTIFIER must be the right one. Without one, the adapter's
    first IPv4 address stands in, a non-APIPA one first. None if the adapter
    holds no such address.
    """
    candidates = [
        entry
        for entry in interface.ips
        if isinstance(entry, _ipaddress.IPv4Interface)
        and (address is None or entry.ip == address)
    ]
    if address is None:
        candidates = [e for e in candidates if e.ip not in _net.APIPA] or candidates
    if not candidates:
        return None
    return _net.NetworkInterface(
        name=interface.name,
        ip_interface=candidates[0],
        mac=_net.MACAddress(interface.mac) if interface.mac else None,
    )


def _resolve_interface_uncached(
    sock: _socket.socket,
    pkt_local_ip: _ty.Optional[_net.IPv4] = None,
    pkt_ifindex: _ty.Optional[int] = None,
) -> _net.NetworkInterface:
    if pkt_local_ip is not None:
        local_ip = str(pkt_local_ip)
    else:
        try:
            local_ip, _ = sock.getsockname()
        except Exception:
            local_ip = "127.0.0.1"

    # The adapter holding exactly this address, from netimps -- link-local
    # included. That matters: "which interface did this arrive on" is not "which
    # addresses are worth serving from", and an APIPA-only NIC (the normal state
    # of an isolated DHCP-only segment) used to be filtered out of the list
    # searched here, degrading to the synthetic `unknown[...]` below with a /32
    # and no MAC -- losing the prefix the server derives its pool from.
    address = _ipaddress.ip_address(local_ip)
    if isinstance(address, _net.IPv4) and not address.is_unspecified:
        held = _netimps.interface_for(address)
        if held is not None:
            found = _network_interface(held, address)
            if found is not None:
                return found

    # Only the index is known (or the address is no adapter's): the adapter by
    # index, answering from its own address.
    if pkt_ifindex:
        for interface in _netimps.get_interfaces():
            if interface.index == pkt_ifindex:
                found = _network_interface(interface)
                if found is not None:
                    return found
                break

    try:
        ip_addr = _net.IPv4(local_ip)
    except Exception:
        ip_addr = _net.IPv4("127.0.0.1")
    LOGGER.warning(
        f"Could not resolve interface for IP {local_ip}; using synthetic interface"
    )
    return _net.NetworkInterface(
        name=f"unknown[{local_ip}]",
        ip_interface=_ipaddress.IPv4Interface((str(ip_addr), 32)),
        mac=None,
    )


class DhcpListener:
    DEFAULT_PORTS: _ty.Sequence[int] = tuple(p.value for p in _enum.DhcpPort)

    #: Whether to set ``SO_REUSEADDR`` on every listening socket. Off: see
    #: `_bind_sockets` for what sharing a DHCP port actually looks like when it
    #: goes wrong. A class attribute rather than a constructor argument so every
    #: subclass (server, client, relay, capture) inherits it without each
    #: constructor having to forward it.
    REUSE_ADDRESS: bool = False

    def __init__(
        self,
        listen: ListenSpec = None,
        select_timeout: float | None = None,
        max_packet_size: int | None = _const.UDP_MAX_PACKET_SIZE,
        per_interface: bool | None = None,
    ) -> None:
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._pktinfo = _pktinfo_supported(listen, per_interface)
        self._listen = _parselisteners(
            listen, self.DEFAULT_PORTS, expand_wildcard=not self._pktinfo
        )
        self._per_interface = per_interface
        self._sockets: list[_socket.socket] = []
        #: The netimps endpoint each socket is received through.
        self._endpoints: dict[_socket.socket, _netimps.UdpEndpoint] = {}
        self._sigint_handler: _ty.Optional[_ty.Any] = None
        self._previous_sigint: _ty.Optional[_ty.Any] = None
        self._select_timeout = select_timeout or 1
        self._cancellation_token: _thread.Event | None = None
        self.metrics = DhcpMetrics()

    @property
    def bound_addresses(self) -> "tuple[_net.SocketAddress, ...]":
        """The addresses this listener is currently bound to.

        Empty before `bind()` and after `close()`. **Not** emptied by `stop()`
        returning: `stop()` only asks the receive loop to exit, and the sockets
        are closed by `listen()` on its way out -- up to `select_timeout` later,
        on the receive thread. Join the thread `start()` handed back before
        reading this if the distinction matters. (It previously stayed populated
        indefinitely, because nothing closed the sockets at all.)

        Asking the socket rather than repeating `self._listen` is the point:
        binding port 0 gives an ephemeral port that only the socket knows, which
        is how a test or a tool discovers where to send. Without this the only
        way to find out was to reach into the private socket list, which the
        tests did in twenty-one places.
        """
        addresses = []
        for sock in self._sockets:
            try:
                addresses.append(_net.SocketAddress(sock))
            except OSError:  # pragma: no cover - socket closed underneath us
                continue
        return tuple(addresses)

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        pass

    def bind(self) -> None:
        _bind_sockets(
            self._listen,
            self._sockets,
            self._endpoints,
            self._pktinfo,
            reuse_address=self.REUSE_ADDRESS,
        )

    def stop(self) -> None:
        if self._cancellation_token is not None:
            self._cancellation_token.set()

    def close(self) -> None:
        """Close every bound socket and release the SIGINT handler.

        `stop()` only ends the receive loop; without this the sockets stayed
        open, so a process that creates a listener per operation leaked a bound
        UDP socket and its port each time, and the next bind to the same port
        failed or silently shared it.
        """
        for socket in self._sockets:
            _close_socket(socket, self._endpoints)
        self._sockets.clear()
        self._restore_sigint_handler()

    def __enter__(self) -> "DhcpListener":
        self.bind()
        return self

    def __exit__(self, *_exc: _ty.Any) -> None:
        self.stop()
        self.close()

    def wait(self) -> None:
        # Read once per turn, not twice. `listen()` sets `_cancellation_token`
        # to None from the receive thread as it exits, so a token that was not
        # None at the `is not None` test could be None at the `.wait()` --
        # `AttributeError: 'NoneType' object has no attribute 'wait'` out of a
        # call whose whole job is to block until shutdown.
        while True:
            token = self._cancellation_token
            if token is None:
                return
            token.wait(self._select_timeout)

    def _install_sigint_handler(self) -> None:
        """Install a Ctrl-C handler, if this thread is allowed to.

        `signal.signal` raises off the main thread, which used to propagate out
        of `start()` *after* the cancellation token was set -- leaving the
        listener permanently 'started' and impossible to start again. Library
        code should not claim a process-wide handler as a side effect of
        starting, so failure here is not an error.
        """
        import signal

        if _thread.current_thread() is not _thread.main_thread():
            return

        def stop(*args: _ty.Any) -> None:
            self.stop()
            LOGGER.info("Stopped listening due to Ctrl-C")

        try:
            self._sigint_handler = stop
            self._previous_sigint = signal.signal(signal.SIGINT, stop)
        except (ValueError, OSError):  # pragma: no cover - platform dependent
            self._sigint_handler = None
            self._previous_sigint = None

    def _restore_sigint_handler(self) -> None:
        import signal

        if self._sigint_handler is None:
            return
        if _thread.current_thread() is not _thread.main_thread():
            # `signal.signal` raises off the main thread, so the handler cannot
            # be given back from here -- and `close()` now runs on the receive
            # thread too (from `listen()`'s teardown). Leave both the handler
            # and the bookkeeping in place so a later `close()` on the owning
            # thread can still restore it; clearing them here would make that
            # restore a silent no-op and strand the process-wide handler.
            return
        try:
            # Only give it back if nobody else has claimed it since.
            if signal.getsignal(signal.SIGINT) is self._sigint_handler:
                signal.signal(signal.SIGINT, self._previous_sigint)
        except (ValueError, OSError, TypeError):  # pragma: no cover
            pass
        self._sigint_handler = None
        self._previous_sigint = None

    def start(
        self, cancellation_token: _thread.Event | None = None
    ) -> _thread.Thread | None:
        if not self._cancellation_token:
            # Daemon: a non-daemon receive thread keeps the interpreter alive
            # after `main` returns, and nothing in the loop ends on its own.
            # Measured: a process that started a listener and fell off the end
            # of `main` without `stop()` was still running after 8 s and had to
            # be killed. Shutdown is `stop()` plus `join()`, which every
            # supported entry point does; a caller that forgets now exits
            # instead of hanging.
            thread = _thread.Thread(
                target=self.listen, args=(), name="pydhcp-listener", daemon=True
            )
            self._cancellation_token = cancellation_token or _thread.Event()
            self._install_sigint_handler()
            thread.start()
            return thread
        return None

    def _receive_one(self, sock: _socket.socket) -> None:
        """Receive, decode and dispatch exactly one datagram.

        Split into three steps because they fail for three unrelated reasons and
        need three different reports. One `except Exception` used to cover all of
        them and log `Encounter error handling request: <class> | <str>` with no
        traceback -- so a malformed packet from the segment (routine, the peer's
        doing), a socket error (ours), and a bug inside a `handle()` override
        were indistinguishable, and the only one whose traceback matters was the
        one that lost it.
        """
        try:
            # One octet over the limit, so a datagram that does not fit can be
            # told apart from one that exactly fills it. Linux truncates
            # silently and reports MSG_TRUNC; Windows fails the call with
            # WSAEMSGSIZE, which lands in the OSError branch below.
            endpoint = self._endpoints.get(sock)
            if endpoint is None:  # pragma: no cover - not bound through bind()
                endpoint = self._endpoints[sock] = _netimps.UdpEndpoint(
                    sock, pktinfo=False
                )
            data, client, ifindex, local_ip = _arrival(
                endpoint.recv(self._max_packet_size + 1), self._max_packet_size
            )
            raw: memoryview = memoryview(data)
        except _TruncatedDatagram as e:
            self.metrics.packets_dropped_truncated += 1
            LOGGER.warning(f"Dropping a truncated datagram: {e}")
            return
        except OSError as e:
            if getattr(e, "winerror", None) == _WSAEMSGSIZE:
                self.metrics.packets_dropped_truncated += 1
                LOGGER.warning(
                    f"Dropping a truncated datagram on {self._describe(sock)}: "
                    f"it exceeded max_packet_size={self._max_packet_size} "
                    f"(WSAEMSGSIZE)"
                )
                return
            self.metrics.packets_dropped_error += 1
            LOGGER.error(
                f"Receive failed on {self._describe(sock)}: "
                f"{e.__class__.__name__} | {e}",
                exc_info=True,
            )
            return

        try:
            msg = DhcpMessage.decode(raw)
        except Exception as e:
            # The sender's fault, and routine on a shared segment: a warning
            # with the facts, not an error with a traceback of our own decoder.
            self.metrics.packets_dropped_error += 1
            LOGGER.warning(
                f"Discarding an undecodable {len(raw)}-octet datagram from "
                f"{client}: {e.__class__.__name__} | {e}"
            )
            return

        try:
            self.metrics.packets_received += 1
            context = _context_for(
                sock, client, msg.chaddr, ifindex, local_ip, self._endpoints.get(sock)
            )
            msg.log(client, _net.SocketAddress(sock), _logging.DEBUG)
            self.handle(msg, context)
        except Exception as e:
            # Ours, almost always: `handle()` is the documented override point.
            # exc_info is the whole value here -- the class name and str of, say,
            # a KeyError deep in a lease backend say nothing about where it came
            # from. `DhcpCapture.hook_fail_fast` relies on this staying a catch
            # rather than a propagate.
            self.metrics.packets_dropped_error += 1
            LOGGER.error(
                f"Encounter error handling request from {client}: "
                f"{e.__class__.__name__} | {e}",
                exc_info=True,
            )

    @staticmethod
    def _describe(sock: _socket.socket) -> str:
        try:
            return str(_net.SocketAddress(sock))
        except OSError:  # pragma: no cover - closed underneath us
            return "a closed socket"

    def listen(self) -> None:
        self.bind()
        rlist: list[_socket.socket]
        if self._cancellation_token is None:
            self._cancellation_token = _thread.Event()
        token = self._cancellation_token
        try:
            while not token.is_set():
                rlist, _, _ = _select.select(
                    list(self._sockets), [], [], self._select_timeout
                )
                if token.is_set():
                    break
                for sock in rlist:
                    if token.is_set():
                        # A handler can stop the listener -- `DhcpCapture`'s
                        # `--count` sink and `hook_fail_fast` both do -- and
                        # this loop then kept draining the rest of the ready
                        # set. Measured: `capture --count 1` wrote 3 records in
                        # 3 of 3 trials on a wildcard bind with three sockets
                        # ready in the same `select()`.
                        break
                    self._receive_one(sock)
        except KeyboardInterrupt:
            LOGGER.info("Stopped listening due to Ctrl-C")
            token.set()
        finally:
            self._cancellation_token = None
            # Release the sockets. `stop()` only ends the loop, and nothing else
            # closed them on this path: measured across three test modules, 7
            # sockets were still open at the end of the session. `close()` also
            # gives back the SIGINT handler, but only when it can -- see
            # `_restore_sigint_handler` for why that part waits for the main
            # thread.
            self.close()


import asyncio as _asyncio


class AsyncDhcpListener:
    DEFAULT_PORTS: _ty.Sequence[int] = tuple(p.value for p in _enum.DhcpPort)

    #: As on `DhcpListener`; see `_bind_sockets`.
    REUSE_ADDRESS: bool = False

    def __init__(
        self,
        listen: ListenSpec = None,
        max_packet_size: int | None = None,
        per_interface: bool | None = None,
    ) -> None:
        self._max_packet_size = max_packet_size or _const.UDP_MAX_PACKET_SIZE
        if listen is None:
            listen = "*"
        self._pktinfo = _pktinfo_supported(listen, per_interface)
        self._listen = _parselisteners(
            listen, self.DEFAULT_PORTS, expand_wildcard=not self._pktinfo
        )
        self._per_interface = per_interface
        self._sockets: list[_socket.socket] = []
        #: As on `DhcpListener`.
        self._endpoints: dict[_socket.socket, _netimps.UdpEndpoint] = {}
        #: One receive task per socket; see `_receive`.
        self._tasks: "list[_asyncio.Task[None]]" = []
        self._loop: _ty.Optional[_asyncio.AbstractEventLoop] = None
        self._stopped: _ty.Optional[_asyncio.Event] = None
        self._worker: _ty.Optional[_futures.ThreadPoolExecutor] = None
        self.metrics = DhcpMetrics()
        #: As on `DhcpListener`.
        self.packets_dropped_truncated = 0
        self.packets_dropped_error = 0

    async def _receive(
        self, sock: _socket.socket, endpoint: _netimps.UdpEndpoint
    ) -> None:
        """Receive from one socket until cancelled, on the event loop.

        Only the read happens here; the handler runs on the worker. netimps'
        `arecv` keeps packet info on every loop type, Windows' default proactor
        included -- which `add_reader` (absent there) and a `DatagramTransport`
        (no slot for control messages) could not, so that loop used to run
        without knowing which interface a broadcast arrived on.

        An `arecv` loop rather than `datagrams()`: an async iterator ends at its
        first exception, and a server has to survive a datagram it cannot read.
        """
        while True:
            try:
                arrival = _arrival(
                    await endpoint.arecv(self._max_packet_size + 1),
                    self._max_packet_size,
                )
            except (BlockingIOError, InterruptedError):  # spurious readability
                continue
            except _TruncatedDatagram as e:
                self.metrics.packets_dropped_truncated += 1
                LOGGER.warning(f"Dropping a truncated datagram: {e}")
                continue
            except OSError as e:
                if sock.fileno() == -1:
                    return  # closed underneath us; nothing more will arrive
                if getattr(e, "winerror", None) == _WSAEMSGSIZE:
                    # As in `DhcpListener._receive_one`: Windows reports an
                    # oversized datagram as a failed call, not a short read.
                    self.metrics.packets_dropped_truncated += 1
                    LOGGER.warning(
                        f"Dropping a truncated datagram: it exceeded "
                        f"max_packet_size={self._max_packet_size} (WSAEMSGSIZE)"
                    )
                    continue
                self.metrics.packets_dropped_error += 1
                LOGGER.error(
                    f"Encounter error reading async datagram: "
                    f"{e.__class__.__name__} | {e}",
                    exc_info=True,
                )
                continue
            data, client, ifindex, local_ip = arrival
            self._dispatch_received(data, client, sock, ifindex, local_ip)

    def _dispatch_received(
        self,
        data: bytes,
        client: _net.SocketAddress,
        sock: _socket.socket,
        ifindex: "int | None" = None,
        local_ip: "_net.IPv4 | None" = None,
    ) -> None:
        """Run one datagram's handling off the event loop.

        Exactly one worker thread, so handlers still run one at a time and in
        arrival order. That matters: the lease backends are not thread-safe, so a
        pool here would trade a blocked event loop for a data race.
        """
        worker = self._worker
        if worker is None:  # not started through start(); keep working anyway
            self._handle_datagram(data, client, sock, ifindex, local_ip)
            return
        future = worker.submit(
            self._handle_datagram, data, client, sock, ifindex, local_ip
        )
        future.add_done_callback(self._report_worker_result)

    @staticmethod
    def _report_worker_result(future: "_futures.Future[None]") -> None:
        error = future.exception()
        if error is not None:  # pragma: no cover - _handle_datagram catches
            LOGGER.error(
                f"Unhandled error in async handler: "
                f"{error.__class__.__name__} | {error}"
            )

    def _handle_datagram(
        self,
        data: bytes,
        client: _net.SocketAddress,
        sock: _socket.socket,
        ifindex: "int | None" = None,
        local_ip: "_net.IPv4 | None" = None,
    ) -> None:
        # Split for the same reason as `DhcpListener._receive_one`: a packet the
        # peer malformed and a bug in a `handle()` override are different
        # events, and only the second one's traceback is worth keeping.
        try:
            msg = DhcpMessage.decode(memoryview(data))
        except Exception as e:
            self.metrics.packets_dropped_error += 1
            LOGGER.warning(
                f"Discarding an undecodable {len(data)}-octet datagram from "
                f"{client}: {e.__class__.__name__} | {e}"
            )
            return
        try:
            self.metrics.packets_received += 1
            msg.log(client, _net.SocketAddress(sock), _logging.DEBUG)
            context = _context_for(
                sock, client, msg.chaddr, ifindex, local_ip, self._endpoints.get(sock)
            )
            self.handle(msg, context)
        except Exception as e:
            self.metrics.packets_dropped_error += 1
            LOGGER.error(
                f"Encounter error handling async request from {client} : "
                f"{e.__class__.__name__} | {e}",
                exc_info=True,
            )

    @property
    def bound_addresses(self) -> "tuple[_net.SocketAddress, ...]":
        """The addresses this listener is currently bound to.

        Empty before `bind()` and after `stop()` has actually run -- which is
        not necessarily when `stop()` returns; see the note on `stop()` about
        being called from the handler worker. Asking the socket rather than
        repeating `self._listen` is the point: binding port 0 gives an ephemeral
        port that only the socket knows, which is how a test or a tool discovers
        where to send. Without this the only way to find out was to reach into
        the private socket list, which the tests did in twenty-one places.
        """
        addresses = []
        for sock in self._sockets:
            try:
                addresses.append(_net.SocketAddress(sock))
            except OSError:  # pragma: no cover - socket closed underneath us
                continue
        return tuple(addresses)

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        pass

    def bind(self) -> None:
        _bind_sockets(
            self._listen,
            self._sockets,
            self._endpoints,
            self._pktinfo,
            label="async",
            reuse_address=self.REUSE_ADDRESS,
        )

    async def wait(self) -> None:
        """Block until `stop()` is called.

        The sync counterpart is `DhcpListener.wait()`, and reaching *that* one
        through the inherited contract raised `AttributeError: _cancellation_token`
        -- the async constructor never sets one. A coroutine is the honest shape
        here: waiting synchronously inside the loop that has to run the handlers
        would deadlock.
        """
        stopped = self._stopped
        if stopped is None:  # never started, or already stopped
            return
        await stopped.wait()

    def listen(self) -> None:
        """Not available: the async listener is driven by its event loop.

        Inherited from `DhcpListener` through `AsyncDhcpServer`'s MRO, where it
        used to fail with `AttributeError: _cancellation_token` several frames
        deep instead of saying what to call.
        """
        raise NotImplementedError(
            "AsyncDhcpListener has no blocking listen(); "
            "use `await start()` and then `await wait()`."
        )

    async def start(self) -> None:
        self.bind()
        if self._worker is None:
            self._worker = _futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="pydhcp-async-handler"
            )
        loop = _asyncio.get_running_loop()
        self._loop = loop
        self._stopped = _asyncio.Event()
        for sock in self._sockets:
            sock.setblocking(False)
            self._tasks.append(
                loop.create_task(self._receive(sock, self._endpoints[sock]))
            )

    def stop(self) -> _ty.Any:
        """Close every transport and socket.

        Deliberately not a coroutine, even though `await listener.stop()` is the
        documented form and still works. The work here is entirely synchronous,
        and as `async def` this silently did nothing whenever it was reached
        through the inherited `DhcpListener` contract: `server.stop()` returned a
        coroutine nobody awaited, so the server kept running with its ports
        bound, and mypy accepted it. Returning an already-finished future keeps
        the `await` form working from inside a running loop.

        Called from the handler worker thread -- which is exactly what
        `DhcpCapture.hook_fail_fast` and the capture CLI's `--count` sink do --
        the close is handed back to the event loop instead of being run inline.
        Nothing it touches is thread-safe: `Task.cancel()` and
        `asyncio.Event.set()` both finish through `loop.call_soon`, which
        queues a callback *without* waking the loop.
        Measured with a handler calling `stop()` on its worker: the selector
        loop (Linux) never woke and `await wait()` blocked forever, while
        Windows' proactor loop returned in 7 ms -- the same
        green-on-one-platform shape as every other defect in this file.
        """
        loop = self._loop
        if loop is not None and not loop.is_closed():
            try:
                running: "_asyncio.AbstractEventLoop | None" = (
                    _asyncio.get_running_loop()
                )
            except RuntimeError:
                running = None
            if running is not loop:
                try:
                    loop.call_soon_threadsafe(self._close_endpoints)
                except RuntimeError:  # pragma: no cover - loop closed since
                    return self._close_endpoints()
                return None
        return self._close_endpoints()

    def _close_endpoints(self) -> _ty.Any:
        """The body of `stop()`, always on the event loop's own thread.

        Cancel the receive tasks, *then* close the endpoints -- the order netimps
        documents as a clean shutdown: a cancelled `arecv` unregisters its
        reader, so the loop is not left polling a socket about to close. The
        close therefore runs once the tasks have finished, and the returned
        awaitable completes then, so `await stop()` still means "closed". So
        does `await wait()`: the stop event is set only after the close, since
        `hook_fail_fast` callers check `bound_addresses` the moment it returns.
        """
        stopped, self._stopped = self._stopped, None
        self._loop = None
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            task.cancel()
        worker, self._worker = self._worker, None
        if worker is not None:
            # Don't wait: stop() is called from the event loop, and a handler in
            # flight may be doing exactly the blocking work this worker exists to
            # keep off it.
            worker.shutdown(wait=False)

        try:
            running = _asyncio.get_running_loop()
        except RuntimeError:
            # No running loop, so the tasks cannot be waited for and nobody can
            # be awaiting this anyway.
            self._close_sockets(stopped)
            return None
        if not tasks:
            self._close_sockets(stopped)
            future = running.create_future()
            future.set_result(None)
            return future

        async def finish() -> None:
            await _asyncio.gather(*tasks, return_exceptions=True)
            self._close_sockets(stopped)

        return running.create_task(finish())

    def _close_sockets(self, stopped: "_asyncio.Event | None" = None) -> None:
        for sock in self._sockets:
            _close_socket(sock, self._endpoints)
        self._sockets.clear()
        if stopped is not None:
            stopped.set()
