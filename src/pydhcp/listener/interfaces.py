"""Which host interface a datagram arrived on."""

from __future__ import annotations

import logging as _logging
import functools as _functools
import ipaddress as _ipaddress
import socket as _socket
import typing as _ty

import netimps as _netimps

from .. import network as _net

LOGGER = _logging.getLogger(__name__)


def _network_interface(
    interface: _netimps.Interface,
    address: "_ty.Optional[_ipaddress.IPv4Address]" = None,
) -> "_ty.Optional[_net.NetworkInterface]":
    """pydhcp's per-address view of one netimps adapter.

    ``address`` picks which of its addresses -- a NIC may hold several, and the
    reply's SERVER_IDENTIFIER must be the right one. Without one,
    `Interface.primary_ip()` stands in: a routable address, else a loopback one,
    else a link-local one. None if the adapter holds no such address.
    """
    if address is None:
        chosen = interface.primary_ip()
    else:
        chosen = next(
            (
                entry
                for entry in interface.ips
                if isinstance(entry, _ipaddress.IPv4Interface) and entry.ip == address
            ),
            None,
        )
    if chosen is None:
        return None
    return _net.NetworkInterface(
        name=interface.name,
        ip_interface=chosen,
        mac=interface.mac,
    )


@_functools.lru_cache(maxsize=256)
def _warn_synthetic(local_ip: str) -> None:
    """Log the synthetic-interface fallback once per address.

    The lookup used to be cached per bind, which incidentally also made this
    warning fire once. Without that cache it would fire for every datagram from
    an unresolvable address, and a warning on a path any sender can drive needs
    a bound or the log becomes the second target. Bounded, so a flood of
    distinct addresses cannot grow it.
    """
    LOGGER.warning(
        f"Could not resolve interface for IP {local_ip}; using synthetic interface"
    )


def _resolve_interface(
    sock: _socket.socket,
    pkt_local_ip: _ty.Optional[_ipaddress.IPv4Address] = None,
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
    callers from having to special-case it.

    The lookups use netimps' enumeration cache (`cache=True`, a one-second
    TTL), which `bind()` also clears. An uncached enumeration costs about a
    millisecond with a handful of adapters and 35-42 ms with many; paid per
    datagram, a flood alone denied service. The TTL bounds it at one
    enumeration per second whatever the arrival rate, and -- unlike the
    per-bind cache this replaced -- notices an address the host gains or loses
    within a second, without a re-bind.

    A local address of 0.0.0.0 is no address at all and is treated as absent.
    It is what a zero-filled `ipi_spec_dst` decodes to, and taking it literally
    skipped the index lookup, so the datagram resolved to a synthetic
    `unknown[0.0.0.0]/32` -- a network with nothing in it to lease. Measured:
    the server received the DISCOVER and allocated and sent nothing.
    """
    if pkt_local_ip is not None and pkt_local_ip.is_unspecified:
        pkt_local_ip = None
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
    if isinstance(address, _ipaddress.IPv4Address) and not address.is_unspecified:
        held = _netimps.get_interface(address, cache=True)
        if held is not None:
            found = _network_interface(held, address)
            if found is not None:
                return found

    # Only the index is known (or the address is no adapter's): the adapter by
    # index, answering from its own address.
    if pkt_ifindex:
        by_index = _netimps.get_interface(index=pkt_ifindex, cache=True)
        if by_index is not None:
            found = _network_interface(by_index)
            if found is not None:
                return found

    try:
        ip_addr = _ipaddress.IPv4Address(local_ip)
    except Exception:
        ip_addr = _ipaddress.IPv4Address("127.0.0.1")
    _warn_synthetic(local_ip)
    return _net.NetworkInterface(
        name=f"unknown[{local_ip}]",
        ip_interface=_ipaddress.IPv4Interface((str(ip_addr), 32)),
        mac=None,
    )
