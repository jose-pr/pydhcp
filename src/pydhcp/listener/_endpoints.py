"""What the listener does to the endpoints netimps opened: the receive buffer, the
Bound record, the broadcast warning and closing."""

from __future__ import annotations

import logging as _logging
import socket as _socket
import sys as _sys
import typing as _ty

import netimps as _netimps

from .. import _constants as _const, _network as _net

LOGGER = _logging.getLogger(__name__)

_ADDRESS_BOUND_WARNED = False


def _address_bound_hears_no_broadcast() -> bool:
    """Whether a socket bound to one address receives no broadcast here.

    Measured on Linux: a socket bound to a host address received none of three
    limited and none of three subnet broadcasts, where the wildcard received
    all of them. The BSDs and macOS deliver a broadcast only to a socket bound
    to the wildcard in the same way (unmeasured here). Windows delivers a
    broadcast to an address-bound socket, so it is the one platform without the
    behaviour, which is why this is a test of `sys.platform` and not a probe.
    """
    return _sys.platform != "win32"


def _warn_if_address_bound_hears_no_broadcast(address: _net.SocketAddress) -> None:
    """Warn, once per process, that `address` will not hear a broadcast.

    A client that has no address yet reaches a server only by broadcast, so a
    listener bound to one address serves nobody that is still unconfigured.
    The wildcard and loopback addresses are not what this is about: the first
    hears everything, and the second hears no segment at all. Once per process
    and not per socket, because the listener binds one socket per address.
    """
    global _ADDRESS_BOUND_WARNED
    if _ADDRESS_BOUND_WARNED or not _address_bound_hears_no_broadcast():
        return
    if address.ip == _const.UNSPECIFIED_ADDRESS or address.ip.is_loopback:
        return
    _ADDRESS_BOUND_WARNED = True
    LOGGER.warning(
        f"Listening on the address {address}: on this platform a socket bound to "
        "an address receives no broadcast, so a client without an address yet "
        'will not reach it. Listen on the wildcard (listen="*") to serve '
        "unconfigured clients."
    )


def _grow_receive_buffer(
    sock: _socket.socket, address: _net.SocketAddress, wanted: int
) -> None:
    """Grow `sock`'s receive buffer to `wanted` octets, and say if it was refused.

    A DHCP server is a burst receiver: a segment powering up sends its DISCOVERs
    together. The default buffer is small -- 64 KiB on Windows, which holds about
    220 of a typical 300-octet DHCP datagram -- and measured, a 1000-datagram
    burst at a wildcard server delivered exactly 220; the kernel dropped the
    rest before the server could read them, and the clients waited out their
    retransmission timers.

    The kernel may grant less than asked and does not say so (`setsockopt`
    succeeds; Linux caps at `net.core.rmem_max` and also doubles what it
    reports), so the grant is read back through `netimps.set_buffer_size` and a
    shortfall is logged (INFO, naming the address) rather than assumed away;
    netimps also warns, once per process for each distinct request and grant.
    Failure to grow is not fatal: the socket works at its default size.
    """
    try:
        granted, _send = _netimps.set_buffer_size(sock, receive=wanted)
    except OSError as error:
        LOGGER.warning(
            f"Could not grow the receive buffer on {address} to {wanted} octets: "
            f"{error}; keeping the OS default."
        )
        return
    if granted < wanted:
        LOGGER.info(
            f"Receive buffer on {address}: asked for {wanted} octets, the OS "
            f"granted {granted} (on Linux, raise net.core.rmem_max to allow more)."
        )


def _prepare_endpoints(
    endpoints: "_ty.Iterable[_netimps.UDPEndpoint]", label: str, receive_buffer: int
) -> None:
    """Grow each endpoint's receive buffer and say where it is bound.

    ``receive_buffer`` is in octets, 0 leaving the OS default; see
    `_grow_receive_buffer`. "Bound" is the line a supervisor or a test waits
    for: it carries the port the kernel gave.
    """
    for endpoint in endpoints:
        sock = endpoint.socket
        address = _net.SocketAddress.from_socket(sock)
        if receive_buffer:
            _grow_receive_buffer(sock, address, receive_buffer)
        LOGGER.info(f"Bound{' (' + label + ')' if label else ''}: {address}")
        _warn_if_address_bound_hears_no_broadcast(address)


def _close_socket(
    sock: _socket.socket, endpoints: "dict[_socket.socket, _netimps.UDPEndpoint]"
) -> None:
    """Close `sock` through its endpoint where it has one.

    `UDPEndpoint.close()` also retires the thread netimps uses to wait on a
    Windows proactor loop, which a bare `socket.close()` would strand.
    """
    endpoint = endpoints.pop(sock, None)
    try:
        if endpoint is not None:
            endpoint.close()
        else:
            sock.close()
    except Exception:
        # Closing is cleanup and must not mask the error that led to it.
        LOGGER.debug("Closing a listening socket failed", exc_info=True)
