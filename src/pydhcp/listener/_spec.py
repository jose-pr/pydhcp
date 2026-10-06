"""The `listen` argument: its grammar, and the addresses it expands to.

One argument names where to listen. `None` is the wildcard on the default ports.
Otherwise it is a *binding* or a sequence of bindings, and a binding is:

* text, `"host"`, `"host:port"`, `"*"`, `"*:port"` or `":port"` (the wildcard),
  or several of them joined by commas;
* an `IPv4Address`, or `None` (the wildcard), on the default ports;
* a `netimps.Interface` or `netimps.MACAddress`, on the default ports;
* a pair of host and ports, as a tuple or a list (a configuration file only has
  lists): the host is `None`, blank text, `"*"`, text, an `IPv4Address`, an
  `Interface` or a `MACAddress`; the ports are an `int`, digit text, `None` (the
  default ports) or a sequence of those. A pair is told from two bindings by its
  second item being port-like.

**An interface.** Text that is not an IPv4 address names an interface, and the
reading is in this order, so no name is looked up as a host name (a host name is
never resolved): the wildcard forms; an IPv4 address; a MAC in any spelling
(`aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`, `aa.bb.cc.dd.ee.ff`,
`aabbccddeeff`); otherwise an adapter name (`eth1`, `Wi-Fi 2`, `eth0.100`). So
`"eth1"` and `"localhost"` are adapters, and an adapter whose name is also an
address or a MAC is given as a `netimps.Interface`. A port follows the last colon
(`"eth1:67"`, `"aa-bb-cc-dd-ee-ff:67"`); the colon spelling of a MAC takes its port
in a pair (`("aa:bb:cc:dd:ee:ff", 67)`), and an adapter name holding a colon is
given as an `Interface`. Whether an interface exists is checked when the sockets
are bound, not when the argument is read. An interface binding is one wildcard
socket that drops what arrives on any other interface (a MAC names every adapter
carrying it); `"*"` on the same port, or an address, takes precedence.

A `bool`, a bare number and any other type are refused; so is a port outside
0-65535, a port written twice that disagrees (`("*:67", 68)`), an IPv6 address,
and anything that names no address at all (`""`, `[]`, `" , "`). Text and pairs
are read by `netimps.split_host`.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import typing as _ty

import netimps as _netimps

from .. import _constants as _const, _network as _net

#: The host of a binding: `None` and blank text mean every address; an
#: `Interface` or a `MACAddress` names an interface.
ListenAddress = _ty.Optional[
    _ty.Union[str, _ipaddress.IPv4Address, _netimps.Interface, _netimps.MACAddress]
]

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

#: What names an interface: a `MACAddress`, an adapter name, an `Interface`.
Selector = _ty.Union[_netimps.MACAddress, str, _netimps.Interface]

#: What a binding parses to: an address and its ports (`None` for the defaults),
#: and the interface it is limited to (`None` for an address). An interface
#: binding's address is the wildcard.
_Parsed = _ty.Tuple[
    _ipaddress.IPv4Address, _ty.Optional[_ty.List[int]], _ty.Optional[Selector]
]

_DIGITS_AND_SIGNS = frozenset("0123456789+- _")

_WILDCARD = _ipaddress.IPv4Address("0.0.0.0")


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


def _host(
    text: str,
) -> "_ty.Tuple[_ipaddress.IPv4Address, _ty.Optional[Selector]]":
    """What the host text of a binding names: an address, or an interface.

    An IPv4 address first, then a MAC, then an adapter name. IPv6 is refused.
    """
    try:
        return _ipaddress.IPv4Address(text), None
    except _ipaddress.AddressValueError as refused:
        try:
            _ipaddress.IPv6Address(text.split("%")[0])
        except ValueError:
            pass
        else:
            raise refused
    return _WILDCARD, _selector(text)


def _selector(text: str) -> Selector:
    mac = _netimps.MACAddress.try_parse(text)
    if mac is not None:
        return mac
    if not text.strip() or "/" in text:
        raise ValueError(f"{text!r} is not an interface name")
    return text


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
    return value is None or isinstance(
        value,
        (str, _ipaddress.IPv4Address, _netimps.Interface, _netimps.MACAddress),
    )


def _is_pair(value: _ty.Sequence[object]) -> bool:
    return (
        len(value) == 2
        and _is_host_like(value[0])
        and not (isinstance(value[0], str) and "," in value[0])
        and _is_port_like(value[1])
    )


def _one_text(text: str) -> _Parsed:
    stripped = text.strip()
    mac = _netimps.MACAddress.try_parse(stripped)
    if mac is not None:
        return _WILDCARD, None, mac
    host, port = _split_host_port(text)
    address, selector = _host(host)
    return address, None if port is None else [port], selector


def _ports_of(
    host_text: str, ports: ListenPorts, label: object
) -> _ty.Tuple[str, _ty.Optional[_ty.List[int]]]:
    """The host and the ports of a pair, checked by `netimps.split_host`."""
    wanted: _ty.Sequence[object]
    if ports is None or isinstance(ports, (int, str)):
        wanted = [ports]
    else:
        wanted = list(ports)
        if not wanted:
            raise ValueError(f"{label!r} names no port")
    resolved: _ty.Optional[_ty.List[int]] = None
    host = host_text
    for one in wanted:
        # `split_host` checks the type and range of the port and that it agrees
        # with one written in the host.
        host, port = _netimps.split_host((host_text, _ty.cast("_ty.Any", one)))
        if port is not None:
            resolved = (resolved or []) + [port]
    return host, resolved


def _pair(host: ListenAddress, ports: ListenPorts) -> _Parsed:
    if isinstance(host, (_netimps.Interface, _netimps.MACAddress)):
        _host_text, resolved = _ports_of("0.0.0.0", ports, (host, ports))
        return _WILDCARD, resolved, host
    if host is None:
        host_text = "0.0.0.0"
    else:
        host_text = _wildcard_text(str(host).strip()) or "0.0.0.0"
    mac = _netimps.MACAddress.try_parse(host_text)
    if mac is not None:
        # The colon spelling cannot carry a port in the text: it comes second.
        _host_text, resolved = _ports_of("0.0.0.0", ports, (host, ports))
        return _WILDCARD, resolved, mac
    text, resolved = _ports_of(host_text, ports, (host, ports))
    address, selector = _host(text)
    return address, resolved, selector


def _bindings_of(item: object) -> _ty.Iterator[_Parsed]:
    if item is None:
        yield _pair(None, None)
    elif isinstance(item, str):
        parts = _split_listen_string(item)
        if not parts:
            raise ValueError(f"listen names no address: {item!r}")
        for part in parts:
            yield _one_text(part)
    elif isinstance(item, (_ipaddress.IPv4Address, _netimps.Interface)):
        yield _pair(item, None)
    elif isinstance(item, _netimps.MACAddress):
        yield _pair(item, None)
    elif isinstance(item, (tuple, list)) and _is_pair(item):
        yield _pair(item[0], item[1])
    else:
        raise TypeError(
            "a listen binding is text, an IPv4 address, an interface, None or a "
            f"(host, ports) pair, not {type(item).__name__} {item!r}"
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
        for address, _ports, _selector in _iter_listen_bindings(listen)
    )


def _parselisteners(
    listen: ListenLike = None,
    default_ports: _ty.Sequence[int] = (),
    expand_wildcard: bool = True,
) -> list[_net.SocketAddress]:
    """The addresses `listen` names, each once and in order; refuses a spec naming none."""
    _listen: list[_net.SocketAddress] = []
    for address, ports, _selector in _iter_listen_bindings(listen):
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


def _interface_limits(
    listen: ListenLike, default_ports: _ty.Sequence[int] = ()
) -> "dict[_net.SocketAddress, tuple[Selector, ...]]":
    """The interfaces each wildcard socket is limited to, by the socket's address.

    A socket named by an interface binding only. A port the wildcard is also
    named for plainly (`"*:67"`, `"0.0.0.0"`) has no limit and is absent.
    """
    limits: "dict[_net.SocketAddress, tuple[Selector, ...]]" = {}
    open_sockets: "set[_net.SocketAddress]" = set()
    for address, ports, selector in _iter_listen_bindings(listen):
        for p in default_ports if ports is None else ports:
            socket_address = _net.SocketAddress(address, int(p))
            if selector is None:
                open_sockets.add(socket_address)
            elif selector not in limits.get(socket_address, ()):
                limits[socket_address] = limits.get(socket_address, ()) + (selector,)
    return {a: found for a, found in limits.items() if a not in open_sockets}
