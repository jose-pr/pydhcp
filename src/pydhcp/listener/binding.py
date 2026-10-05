"""Claiming the listen ports, and what to say when one cannot be claimed."""

from __future__ import annotations

import socket as _socket
import typing as _ty
import weakref as _weakref

import netimps as _netimps

from .. import network as _net
from ..log import LOGGER

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

    Binding is the moment the set of addresses served can change, so it drops
    netimps' interface-enumeration cache rather than leaving the next lookup
    to wait out the TTL.
    """
    _netimps.clear_interface_cache()
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
        if receive_buffer:
            _grow_receive_buffer(sock, address, receive_buffer)
        endpoints[sock] = _netimps.UDPEndpoint(
            sock, pktinfo=pktinfo and address.ip == _net.WILDCARD_IPv4
        )
        _REQUESTED_ADDRESS[sock] = address
        sockets.append(sock)
    for address, sock in active.items():
        if address not in wanted:
            sockets.remove(sock)
            _close_socket(sock, endpoints)


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
        pass
