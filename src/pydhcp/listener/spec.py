"""The `listen` argument: its accepted forms, and the addresses they expand to."""

from __future__ import annotations

import ipaddress as _ipaddress
import typing as _ty

import netimps as _netimps

from .. import _constants as _const, network as _net

ListenAddress = _ty.Union[_ipaddress.IPv4Address, str]


ListenPort = _ty.Union[int, _ty.Sequence[int]]


ListenBinding = _ty.Union[ListenAddress, tuple[ListenAddress, ListenPort]]


ListenSpec = _ty.Optional[_ty.Union[ListenBinding, _ty.Sequence[ListenBinding]]]


def _split_listen_string(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _split_host_port(value: str) -> tuple[str, _ty.Optional[int]]:
    """Split ``host:port``, defaulting an empty host to the IPv4 wildcard.

    Delegates to :func:`netimps.split_host`: ``[::1]:67`` is ``("::1", 67)``, a bare
    ``::1`` stays an address rather than host ``::`` port ``1``, a port is ASCII
    digits only, and brackets may enclose only an IPv6 literal.
    """
    # ":67" means "wildcard, port 67" here, but is an empty host to a strict
    # parser -- normalize it before delegating rather than losing the form.
    if value.startswith(":") and not value.startswith("::"):
        value = "0.0.0.0" + value

    host, port = _netimps.split_host(value)
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
    if isinstance(listen, _ipaddress.IPv4Address):
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
            ip = _const.WILDCARD_V4
        if not isinstance(ip, _ipaddress.IPv4Address):
            ip = _ipaddress.IPv4Address(ip)

        if ip == _const.WILDCARD_V4 and expand_wildcard:
            ips = [
                i.ip
                for i in _net.host_ip_interfaces()
                if isinstance(i.ip, _ipaddress.IPv4Address)
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
