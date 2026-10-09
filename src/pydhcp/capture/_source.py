"""DHCP messages arriving at sockets, as pktcap frames: `sniff_dhcp` and `asniff_dhcp`.

Both are netimps' `bind_listen` with DHCP's defaults (ports 67 and 68, IPv4, broadcast
allowed) handed to pktcap's socket source, which reads, dissects and closes.
"""

from __future__ import annotations

import socket as _socket
import typing as _ty

import netimps as _netimps

from .. import _extras
from ._dissector import DHCP_PORTS, capture_dissector

if _ty.TYPE_CHECKING:
    import pktcap as _pktcap
else:
    _pktcap = _extras.lazy_pktcap


#: Octets of receive buffer asked for each socket: a segment powering up sends its
#: DISCOVERs together, and a default buffer (64 KiB on Windows) holds about 220 of them.
RECEIVE_BUFFER_SIZE: _ty.Final = 1 << 20


def bound_endpoints(
    listen: "_netimps.ListenLike", per_interface: _ty.Optional[bool]
) -> "_ty.Tuple[_netimps.UDPEndpoint, ...]":
    """The sockets `listen` names, bound; nothing is opened when any part is refused.

    DHCP's defaults for `netimps.bind_listen`: ports 67 and 68, IPv4, broadcast
    allowed. Each socket's receive buffer is grown to `RECEIVE_BUFFER_SIZE`; a socket
    that refuses keeps the system's.
    """
    endpoints = _netimps.bind_listen(
        listen,
        DHCP_PORTS,
        family=_socket.AF_INET,
        per_address=True if per_interface else None,
        broadcast=True,
    )
    for endpoint in endpoints:
        try:
            _netimps.set_buffer_size(endpoint.socket, receive=RECEIVE_BUFFER_SIZE)
        except OSError:
            pass
    return endpoints


def _reader(
    endpoints: "_ty.Iterable[_netimps.UDPEndpoint]",
) -> "_pktcap.FrameDissector":
    """`capture_dissector()` reading DHCP on 67, 68 and every port the sockets are bound to."""
    bound = {int(endpoint.socket.getsockname()[1]) for endpoint in endpoints}
    return capture_dissector((*DHCP_PORTS, *sorted(bound.difference(DHCP_PORTS))))


def _close(endpoints: "_ty.Iterable[_netimps.UDPEndpoint]") -> None:
    for endpoint in endpoints:
        endpoint.close()


def sniff_dhcp(
    listen: "_netimps.ListenLike" = None,
    *,
    per_interface: _ty.Optional[bool] = None,
    stop: _ty.Optional[_ty.Callable[[], bool]] = None,
    dissector: "_ty.Optional[_pktcap.FrameDissector]" = None,
) -> "_ty.Iterator[_pktcap.DissectedFrame]":
    """The DHCP messages that reach `listen`, as pktcap's dissected frames, as they arrive.

    `listen` is netimps' listen specification (`netimps.parse_listen`) read with the
    default ports 67 and 68 and IPv4: `None` is every address, `"127.0.0.1:6767"` one
    socket, an adapter name or a MAC the sockets of that adapter. The sockets are bound
    when this is called, and a part of the specification that cannot be bound is an
    error before any is opened (`ValueError` for an adapter that matches nothing,
    `OSError` for a port taken). `per_interface=True` binds one socket for each
    address of the host instead of a wildcard; on Linux such sockets hear no broadcast.

    The iterator closes every socket when it ends, fails, is closed or is dropped.
    `stop()` is called between datagrams, and at least once a second on a quiet socket;
    true ends the iteration. `dissector` is a `pktcap.FrameDissector`: omitted, it is
    `capture_dissector()` reading DHCP on 67, 68 and the ports the sockets are bound to,
    so the last layer of a frame that holds a message is a `DHCPLayer`. The IP header
    of a frame is made up and no other host's traffic is seen: see pktcap's `sniff_udp`.
    `ImportError` naming the `pktcap` extra when it is not installed.
    """
    _extras.pktcap_module()
    endpoints = bound_endpoints(listen, per_interface)
    try:
        reader = dissector if dissector is not None else _reader(endpoints)
        return _pktcap.sniff_udp(endpoints, stop=stop, dissector=reader)
    except BaseException:
        _close(endpoints)  # the source turned them away: they are still ours
        raise


def asniff_dhcp(
    listen: "_netimps.ListenLike" = None,
    *,
    per_interface: _ty.Optional[bool] = None,
    dissector: "_ty.Optional[_pktcap.FrameDissector]" = None,
) -> "_ty.AsyncIterator[_pktcap.DissectedFrame]":
    """`sniff_dhcp` for an event loop: an asynchronous iterator of dissected frames.

    The sockets are bound when this is called. When the iterator ends, fails or is
    cancelled, every reader task is cancelled and every socket closed; a loop that
    stops early awaits the iterator's `aclose()`. It has no `stop`: break and
    `aclose()`, or cancel.
    """
    _extras.pktcap_module()
    endpoints = bound_endpoints(listen, per_interface)
    try:
        reader = dissector if dissector is not None else _reader(endpoints)
        return _pktcap.asniff_udp(endpoints, dissector=reader)
    except BaseException:
        _close(endpoints)
        raise
