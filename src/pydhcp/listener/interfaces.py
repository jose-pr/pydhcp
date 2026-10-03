"""Which host interface a datagram arrived on, and the caches that keep that cheap."""

from __future__ import annotations

import ipaddress as _ipaddress
import socket as _socket
import typing as _ty

import netimps as _netimps

from .. import network as _net
from ..log import LOGGER

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


def _resolve_interface(
    sock: _socket.socket,
    pkt_local_ip: _ty.Optional[_net.IPv4] = None,
    pkt_ifindex: _ty.Optional[int] = None,
) -> _net.NetworkInterface:
    """Find the NetworkInterface a datagram actually arrived on.

    ``pkt_local_ip``/``pkt_ifindex`` come from the datagram's packet info
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
