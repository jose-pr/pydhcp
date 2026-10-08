"""The wildcard of a listen specification, expanded to the host's addresses."""

from __future__ import annotations

import ipaddress as _ipaddress
import typing as _ty

from .. import _constants as _const, _network as _net


def _expand_wildcards(
    addresses: _ty.Iterable[_net.SocketAddress],
) -> list[_net.SocketAddress]:
    """Replace each wildcard address by one entry per host IPv4 address.

    Reads the host's interfaces, so it belongs where sockets are bound.
    """
    expanded: list[_net.SocketAddress] = []
    for address in addresses:
        if address.ip == _const.WILDCARD_V4:
            ips = [
                i.ip
                for i in _net.host_ip_interfaces()
                if isinstance(i.ip, _ipaddress.IPv4Address)
            ]
        else:
            ips = [address.ip]
        for ip in ips:
            entry = _net.SocketAddress(ip, address.port)
            if entry not in expanded:
                expanded.append(entry)
    return expanded
