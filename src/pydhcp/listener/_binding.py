"""Claiming the listen ports, and what to say when one cannot be claimed."""

from __future__ import annotations

import logging as _logging
import socket as _socket
import sys as _sys
import typing as _ty
import weakref as _weakref

import netimps as _netimps

from .. import _constants as _const, _network as _net

LOGGER = _logging.getLogger(__name__)

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


def _requested(sock: _socket.socket) -> "_ty.Optional[_net.SocketAddress]":
    """The address `sock` was asked to bind, or `None` for one not bound here."""
    return _REQUESTED_ADDRESS.get(sock)


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
    if address.ip == _const.WILDCARD_V4 or address.ip.is_loopback:
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


def _bind_sockets(
    listen: "_ty.Sequence[_net.SocketAddress]",
    sockets: "list[_socket.socket]",
    endpoints: "dict[_socket.socket, _netimps.UDPEndpoint]",
    pktinfo: bool,
    label: str = "",
    reuse_address: bool = False,
    receive_buffer: int = 0,
    devices: "_ty.Optional[_ty.Mapping[_net.SocketAddress, _netimps.Interface]]" = None,
    on_device_refused: "_ty.Optional[_ty.Callable[[_net.SocketAddress, _netimps.Interface, OSError], None]]" = None,
) -> None:
    """Bind one socket per listen address, reusing any already bound.

    Shared by both listeners. Held apart, the async copy silently lacked the
    packet-info option and the bind-error hints, so the same mistake produced a
    helpful message from one listener and a bare errno from the other.

    Every socket gets a `netimps.UDPEndpoint` in `endpoints`, which is what both
    listeners receive through; a wildcard one asks it for packet info, which it
    enables itself with the right per-platform option.

    Idempotent, including for port 0: an already open socket is matched against
    the address it was *asked* for, not the one it was given, so re-binding a
    port-0 listener keeps the ephemeral port it already has. See
    `_REQUESTED_ADDRESS`.

    ``receive_buffer`` grows each new socket's receive buffer to that many
    octets (0 leaves the OS default); see `_grow_receive_buffer`.

    ``devices`` maps a wildcard address to the one adapter its socket is bound
    to, so the kernel delivers only that interface's datagrams. A bind the
    kernel refuses for the device (`DeviceBindingUnsupportedError`, or
    `PermissionError` where the option needs a capability) is repeated without
    it and reported to ``on_device_refused``: the socket then hears every
    interface and the caller's allow-list drops the rest, which is what the
    caller asked to hear. An error the repeat raises too (a port in use, or
    one that needs privilege) is the real one and propagates.

    Binding is the moment the set of addresses served can change, so it drops
    netimps' interface-enumeration cache rather than leaving the next lookup
    to wait out the TTL.

    A failure leaves the listener as it found it: the sockets this call opened
    are closed before the error is raised, and the ones already bound stay.
    """
    _netimps.clear_interface_cache()
    active: "dict[_net.SocketAddress, _socket.socket]" = {}
    for sock in sockets:
        requested = _REQUESTED_ADDRESS.get(sock)
        if requested is None:  # pragma: no cover - not bound through here
            try:
                requested = _net.SocketAddress.from_socket(sock)
            except OSError:
                continue
        active[requested] = sock
    wanted = []
    opened: "list[_socket.socket]" = []
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
            device = devices.get(address) if devices else None
            options: "dict[str, _ty.Any]" = dict(
                family=_socket.AF_INET,
                kind=_socket.SOCK_DGRAM,
                reuse_address=False,
                allow_address_takeover=reuse_address,
                broadcast=True,
                connreset=False,
            )
            if device is not None:
                options["device"] = device
            try:
                sock = _netimps.bind(str(address.ip), address.port, **options)
            except (_netimps.DeviceBindingUnsupportedError, PermissionError) as refused:
                if device is None:
                    raise
                if on_device_refused is not None:
                    on_device_refused(address, device, refused)
                del options["device"]
                sock = _netimps.bind(str(address.ip), address.port, **options)
        except OSError:
            _release(opened, sockets, endpoints)
            raise
        opened.append(sock)
        sockets.append(sock)
        try:
            if receive_buffer:
                _grow_receive_buffer(sock, address, receive_buffer)
            endpoints[sock] = _netimps.UDPEndpoint(
                sock, pktinfo=pktinfo and address.ip == _const.WILDCARD_V4
            )
        except BaseException:
            _release(opened, sockets, endpoints)
            raise
        _REQUESTED_ADDRESS[sock] = address
        # After the bind, with the port the kernel gave: the line a supervisor or a
        # test waits for, since "Listening on" is logged before it.
        LOGGER.info(
            f"Bound{' (' + label + ')' if label else ''}: {_bound_address(sock, address)}"
        )
        _warn_if_address_bound_hears_no_broadcast(address)
    for address, sock in active.items():
        if address not in wanted:
            sockets.remove(sock)
            _close_socket(sock, endpoints)


def _bound_address(
    sock: _socket.socket, asked: "_net.SocketAddress"
) -> "_net.SocketAddress":
    """The address `sock` is bound to, or the one asked for when it cannot say."""
    try:
        return _net.SocketAddress.from_socket(sock)
    except OSError:  # pragma: no cover - a socket that closed under us
        return asked


def _release(
    opened: "list[_socket.socket]",
    sockets: "list[_socket.socket]",
    endpoints: "dict[_socket.socket, _netimps.UDPEndpoint]",
) -> None:
    """Close the sockets one failed `_bind_sockets` call opened, and unlist them."""
    for sock in opened:
        if sock in sockets:
            sockets.remove(sock)
        _close_socket(sock, endpoints)
    opened.clear()


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
