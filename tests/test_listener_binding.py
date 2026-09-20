"""How a listener claims its ports, and what it says when it cannot.

`transport-12` (a port-0 listener silently moved port across a re-bind) and
`transport-11` (`SO_REUSEADDR` was unconditional, so a second listener took a
bound port in silence and then received nothing).
"""

from __future__ import annotations

import socket

import pytest

from pydhcp.listener import DhcpListener

#: Read from `socket`, not from `pydhcp.listener`: the skips below are about
#: what this platform has, not about what the module chose to re-export.
SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)


class ReusingListener(DhcpListener):
    """A listener that opts back into the old blanket `SO_REUSEADDR`."""

    REUSE_ADDRESS = True


# --- transport-12: bind() is idempotent, port 0 included ---


def test_rebinding_keeps_the_ephemeral_port_and_the_socket() -> None:
    """`bind()` matched open sockets by `getsockname()`.

    A port-0 request never equals the port it produced, so the second `bind()`
    saw its own socket as unwanted: measured before the fix, the first socket
    was closed and the listener moved from port 52908 to 52909, while every
    caller that had read `bound_addresses` was still aiming at 52908.
    """
    listener = DhcpListener(listen=("127.0.0.1", 0))
    listener.bind()
    try:
        first_socket = listener._sockets[0]
        first_address = listener.bound_addresses[0]

        listener.bind()

        assert listener.bound_addresses == (first_address,)
        assert listener._sockets == [first_socket], "the socket was replaced"
        assert first_socket.fileno() != -1, "the original socket was closed"
    finally:
        listener.close()


def test_rebinding_still_drops_an_address_no_longer_asked_for() -> None:
    """The matching change must not defeat the point of matching."""
    # Two *distinct* requests: `_parselisteners` deduplicates, so the same
    # ("127.0.0.1", 0) twice is one address, not two.
    listener = DhcpListener(listen=[("127.0.0.1", 0), ("127.0.0.2", 0)])
    listener.bind()
    try:
        assert len(listener._sockets) == 2
        dropped = listener._sockets[1]
        listener._listen = listener._listen[:1]

        listener.bind()

        assert len(listener._sockets) == 1
        assert dropped.fileno() == -1, "the unwanted socket was left open"
    finally:
        listener.close()


def test_a_closed_listener_gets_a_fresh_ephemeral_port() -> None:
    """Idempotence is per bind cycle: port 0 still means "any" after close()."""
    listener = DhcpListener(listen=("127.0.0.1", 0))
    listener.bind()
    first = listener.bound_addresses[0].port
    listener.close()
    assert listener.bound_addresses == ()

    listener.bind()
    try:
        assert listener.bound_addresses[0].port != 0
    finally:
        listener.close()


# --- transport-11: the port is claimed exclusively by default ---


def test_a_second_listener_cannot_silently_take_a_bound_port() -> None:
    """Measured before the fix: the second bind *succeeded*, and then received
    nothing at all while the first listener got every datagram -- so another
    process quietly taking over a DHCP port looked like a clean start-up."""
    first = DhcpListener(listen=("127.0.0.1", 0))
    first.bind()
    try:
        port = first.bound_addresses[0].port
        second = DhcpListener(listen=("127.0.0.1", port))
        with pytest.raises(OSError) as exc_info:
            second.bind()
        second.close()

        message = str(exc_info.value)
        assert "in use" in message.lower(), message
        assert str(port) in message
    finally:
        first.close()


def test_the_duplicate_bind_really_would_have_stolen_the_datagrams() -> None:
    """The half of `transport-11` that makes the silence expensive.

    With `SO_REUSEADDR` both sockets bind and exactly one of them -- not the
    one the operator thinks -- is fed. Pinned through the opt-in class so the
    behaviour stays visible now that it is no longer the default.
    """
    first = ReusingListener(listen=("127.0.0.1", 0))
    first.bind()
    second = ReusingListener(listen=("127.0.0.1", 0))
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        port = first.bound_addresses[0].port
        second._listen = [type(second._listen[0])("127.0.0.1", port)]
        second.bind()  # no error: this is the behaviour being pinned
        assert second.bound_addresses[0].port == port

        sender.sendto(b"x" * 20, ("127.0.0.1", port))
        import select

        readable, _, _ = select.select(first._sockets + second._sockets, [], [], 1.0)
        assert len(readable) == 1, "both sockets were fed, which is not the point"
    finally:
        sender.close()
        first.close()
        second.close()


def test_reuse_address_is_opt_in_and_reaches_the_socket() -> None:
    listener = DhcpListener(listen=("127.0.0.1", 0))
    listener.bind()
    try:
        sock = listener._sockets[0]
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
    finally:
        listener.close()

    reusing = ReusingListener(listen=("127.0.0.1", 0))
    reusing.bind()
    try:
        sock = reusing._sockets[0]
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0
    finally:
        reusing.close()


@pytest.mark.skipif(
    SO_EXCLUSIVEADDRUSE is None, reason="SO_EXCLUSIVEADDRUSE is Windows-only"
)
def test_the_default_bind_asks_windows_for_exclusive_use() -> None:
    """Without this a *later* SO_REUSEADDR socket can still steal the port."""
    listener = DhcpListener(listen=("127.0.0.1", 0))
    listener.bind()
    try:
        sock = listener._sockets[0]
        assert sock.getsockopt(socket.SOL_SOCKET, SO_EXCLUSIVEADDRUSE) != 0
    finally:
        listener.close()


@pytest.mark.skipif(
    SO_EXCLUSIVEADDRUSE is None, reason="WSAEACCES is a Windows bind failure"
)
def test_binding_over_an_exclusive_holder_is_reported_as_in_use() -> None:
    """Measured before the fix:

        PermissionError: permission denied binding port 64514. Try 6767 for testing.

    64514 is not a privileged port and Windows has no privileged ports at all
    (measured: binding UDP/67 as an ordinary user succeeds). The address was
    simply taken. Reachable only with `REUSE_ADDRESS` on, since a plain bind
    now reports the same situation as WSAEADDRINUSE by itself.
    """
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.setsockopt(socket.SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    try:
        listener = ReusingListener(listen=("127.0.0.1", port))
        with pytest.raises(OSError) as exc_info:
            listener.bind()
        listener.close()

        assert not isinstance(
            exc_info.value, PermissionError
        ), "still reported as a privilege problem"
        message = str(exc_info.value)
        assert "in use" in message.lower(), message
        assert "not privileged" in message, message
    finally:
        holder.close()
