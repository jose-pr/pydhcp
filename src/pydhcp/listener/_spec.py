"""The `listen` argument: its grammar, and the addresses it expands to.

One argument names where to listen. `None` is the wildcard on the default ports.
Otherwise it is a *binding* or a sequence of bindings, and a binding is:

* text, `"host"`, `"host:port"`, `"*"`, `"*:port"` or `":port"` (the wildcard),
  or several of them joined by commas;
* an `IPv4Address`, or `None` (the wildcard), on the default ports;
* a pair of host and ports, as a tuple or a list (a configuration file only has
  lists): the host is `None`, blank text, `"*"`, text or an `IPv4Address`; the
  ports are an `int`, digit text, `None` (the default ports) or a sequence of
  those. A pair is told from two bindings by its second item being port-like.

A `bool`, a bare number and any other type are refused; so is a port outside
0-65535, a port written twice that disagrees (`("*:67", 68)`), a host that is not
an IPv4 address, and anything that names no address at all (`""`, `[]`, `" , "`).
Text and pairs are read by `netimps.split_host`.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import typing as _ty

import netimps as _netimps

from .. import _constants as _const, _network as _net

#: The host of a binding: `None` and blank text mean every address.
ListenAddress = _ty.Optional[_ty.Union[str, _ipaddress.IPv4Address]]

#: One port, as an `int` or as digit text.
ListenPort = _ty.Union[int, str]

#: What follows a host in a pair: a port, several, or `None` for the defaults.
ListenPorts = _ty.Optional[_ty.Union[ListenPort, _ty.Sequence[ListenPort]]]

#: One binding: text, an address, `None`, or a `(host, ports)` pair (a list in a
#: configuration file).
ListenBinding = _ty.Union[
    ListenAddress, _ty.Tuple[ListenAddress, ListenPorts], _ty.List[_ty.Any]
]

#: What `listen` accepts: nothing (every interface), one binding, or a sequence
#: of bindings.
ListenLike = _ty.Optional[_ty.Union[ListenBinding, _ty.Sequence[ListenBinding]]]

#: What a binding parses to: an address and its ports, `None` for the defaults.
_Parsed = _ty.Tuple[_ipaddress.IPv4Address, _ty.Optional[_ty.List[int]]]

_DIGITS_AND_SIGNS = frozenset("0123456789+- _")


def _split_listen_string(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _wildcard_text(text: str) -> str:
    """``*`` and an empty host are the wildcard; ``*:67`` and ``:67`` name its port."""
    if text == "*" or text.startswith("*:"):
        return "0.0.0.0" + text[1:]
    if text.startswith(":") and not text.startswith("::"):
        return "0.0.0.0" + text
    return text


def _split_host_port(value: str) -> tuple[str, _ty.Optional[int]]:
    """Split ``host:port``, defaulting an empty host to the IPv4 wildcard.

    Delegates to :func:`netimps.split_host`: ``[::1]:67`` is ``("::1", 67)``, a bare
    ``::1`` stays an address rather than host ``::`` port ``1``, a port is ASCII
    digits only, and brackets may enclose only an IPv6 literal.
    """
    host, port = _netimps.split_host(_wildcard_text(value.strip()))
    return host or "0.0.0.0", port


def _is_port_like(value: object) -> bool:
    """Whether `value` can be a pair's second item rather than a second binding."""
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, str):
        return all(c in _DIGITS_AND_SIGNS for c in value)
    if isinstance(value, (tuple, list)):
        return all(
            item is not None
            and not isinstance(item, (tuple, list))
            and _is_port_like(item)
            for item in value
        )
    return False


def _is_host_like(value: object) -> bool:
    return value is None or isinstance(value, (str, _ipaddress.IPv4Address))


def _is_pair(value: _ty.Sequence[object]) -> bool:
    return (
        len(value) == 2
        and _is_host_like(value[0])
        and not (isinstance(value[0], str) and "," in value[0])
        and _is_port_like(value[1])
    )


def _one_text(text: str) -> _Parsed:
    host, port = _split_host_port(text)
    return _ipaddress.IPv4Address(host), None if port is None else [port]


def _pair(host: ListenAddress, ports: ListenPorts) -> _Parsed:
    if host is None:
        host_text = "0.0.0.0"
    else:
        host_text = _wildcard_text(str(host).strip()) or "0.0.0.0"
    wanted: _ty.Sequence[object]
    if ports is None or isinstance(ports, (int, str)):
        wanted = [ports]
    else:
        wanted = list(ports)
        if not wanted:
            raise ValueError(f"{(host, ports)!r} names no port")
    resolved: _ty.Optional[_ty.List[int]] = None
    address: _ty.Optional[_ipaddress.IPv4Address] = None
    for one in wanted:
        # `split_host` checks the type and range of the port and that it agrees
        # with one written in the host.
        text, port = _netimps.split_host((host_text, _ty.cast("_ty.Any", one)))
        address = _ipaddress.IPv4Address(text)
        if port is not None:
            resolved = (resolved or []) + [port]
    assert address is not None
    return address, resolved


def _bindings_of(item: object) -> _ty.Iterator[_Parsed]:
    if item is None:
        yield _pair(None, None)
    elif isinstance(item, str):
        parts = _split_listen_string(item)
        if not parts:
            raise ValueError(f"listen names no address: {item!r}")
        for part in parts:
            yield _one_text(part)
    elif isinstance(item, _ipaddress.IPv4Address):
        yield _pair(item, None)
    elif isinstance(item, (tuple, list)) and _is_pair(item):
        yield _pair(item[0], item[1])
    else:
        raise TypeError(
            "a listen binding is text, an IPv4 address, None or a (host, ports) "
            f"pair, not {type(item).__name__} {item!r}"
        )


def _iter_listen_bindings(listen: object) -> _ty.Iterator[_Parsed]:
    if isinstance(listen, (tuple, list)) and not _is_pair(listen):
        if not listen:
            raise ValueError("listen names no address: it is empty")
        for item in listen:
            yield from _bindings_of(item)
    else:
        yield from _bindings_of(listen)


def _listen_uses_wildcard(listen: ListenLike) -> bool:
    return any(
        address == _const.WILDCARD_V4
        for address, _ports in _iter_listen_bindings(listen)
    )


def _parselisteners(
    listen: ListenLike = None,
    default_ports: _ty.Sequence[int] = (),
    expand_wildcard: bool = True,
) -> list[_net.SocketAddress]:
    """The addresses `listen` names, each once and in order; refuses a spec naming none."""
    _listen: list[_net.SocketAddress] = []
    for address, ports in _iter_listen_bindings(listen):
        for p in default_ports if ports is None else ports:
            bind_addr = _net.SocketAddress(address, int(p))
            if bind_addr not in _listen:
                _listen.append(bind_addr)
    if not _listen:
        raise ValueError(f"listen names no address: {listen!r}")
    return _expand_wildcards(_listen) if expand_wildcard else _listen


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
