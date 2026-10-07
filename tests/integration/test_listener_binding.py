"""How a listener claims its ports, and what it says when it cannot.

`transport-12` (a port-0 listener silently moved port across a re-bind) and
`transport-11` (`SO_REUSEADDR` was unconditional, so a second listener took a
bound port in silence and then received nothing).
"""

from __future__ import annotations

import ipaddress
import logging
import socket

import pytest

from helpers import DUPLICATE_UDP_BIND_ALLOWED, LOOPBACK_ALIAS_BINDABLE

from pydhcp.listener import DHCPListener

#: Read from `socket`, not from `pydhcp.listener`: the skips below are about
#: what this platform has, not about what the module chose to re-export.
SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)


class ReusingListener(DHCPListener):
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
    listener = DHCPListener(listen=("127.0.0.1", 0))
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


@pytest.mark.skipif(
    not LOOPBACK_ALIAS_BINDABLE,
    reason="needs a second loopback address; macOS aliases only 127.0.0.1",
)
def test_rebinding_still_drops_an_address_no_longer_asked_for() -> None:
    """The matching change must not defeat the point of matching."""
    # Two *distinct* requests: `_parselisteners` deduplicates, so the same
    # ("127.0.0.1", 0) twice is one address, not two.
    listener = DHCPListener(listen=[("127.0.0.1", 0), ("127.0.0.2", 0)])
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


def test_a_closed_listener_cannot_bind_again() -> None:
    """Closed is final: the sockets `close()` released are not reopened."""
    listener = DHCPListener(listen=("127.0.0.1", 0))
    listener.bind()
    listener.close()
    assert listener.bound_addresses == ()

    with pytest.raises(RuntimeError, match="closed"):
        listener.bind()
    assert listener.bound_addresses == ()


# --- transport-11: the port is claimed exclusively by default ---


def test_a_second_listener_cannot_silently_take_a_bound_port() -> None:
    """Measured before the fix: the second bind *succeeded*, and then received
    nothing at all while the first listener got every datagram -- so another
    process quietly taking over a DHCP port looked like a clean start-up."""
    first = DHCPListener(listen=("127.0.0.1", 0))
    first.bind()
    try:
        port = first.bound_addresses[0].port
        second = DHCPListener(listen=("127.0.0.1", port))
        with pytest.raises(OSError) as exc_info:
            second.bind()
        second.close()

        message = str(exc_info.value)
        assert "in use" in message.lower(), message
        assert str(port) in message
    finally:
        first.close()


@pytest.mark.skipif(
    not DUPLICATE_UDP_BIND_ALLOWED,
    reason="BSD/macOS need SO_REUSEPORT to share a UDP port, so there is no "
    "silent takeover to demonstrate",
)
def test_the_duplicate_bind_really_would_have_stolen_the_datagrams() -> None:
    """The half of `transport-11` that makes the silence expensive.

    With `SO_REUSEADDR` both sockets bind and exactly one of them -- not the
    one the operator thinks -- is fed. Pinned through the opt-in class so the
    behaviour stays visible now that it is no longer the default.

    Skipped where `SO_REUSEADDR` alone does not permit the duplicate bind: on
    the BSDs the kernel refuses it outright, which is the safe behaviour this
    test exists to show the absence of elsewhere.
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
    listener = DHCPListener(listen=("127.0.0.1", 0))
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


def _rcvbuf(sock: socket.socket) -> int:
    return sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)


def test_the_receive_buffer_is_grown_or_the_shortfall_is_reported(caplog) -> None:
    """A segment powering up sends its DISCOVERs together. Measured on Windows,
    whose default buffer is 64 KiB: a 1000-datagram burst at a wildcard server
    delivered exactly 220 -- about what 64 KiB holds at 300 octets each -- and
    all 1000 with a 1 MiB buffer. The kernel may grant less than asked (Linux
    caps at rmem_max and doubles the read-back), so either the grant took or
    the listener said it did not."""
    import logging

    class Grown(DHCPListener):
        RECEIVE_BUFFER_SIZE = 256 * 1024

    listener = Grown(listen=("127.0.0.1", 0))
    with caplog.at_level(logging.INFO, logger="pydhcp"):
        listener.bind()
    try:
        granted = _rcvbuf(listener._sockets[0])
    finally:
        listener.close()

    reported = [r for r in caplog.records if "Receive buffer" in r.getMessage()]
    assert (
        granted >= Grown.RECEIVE_BUFFER_SIZE or reported
    ), f"granted {granted} of {Grown.RECEIVE_BUFFER_SIZE} and said nothing"


def test_a_zero_receive_buffer_keeps_the_os_default() -> None:
    class Default(DHCPListener):
        RECEIVE_BUFFER_SIZE = 0

    plain = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener = Default(listen=("127.0.0.1", 0))
    listener.bind()
    try:
        assert _rcvbuf(listener._sockets[0]) == _rcvbuf(plain)
    finally:
        listener.close()
        plain.close()


@pytest.mark.skipif(
    SO_EXCLUSIVEADDRUSE is None, reason="SO_EXCLUSIVEADDRUSE is Windows-only"
)
def test_the_default_bind_asks_windows_for_exclusive_use() -> None:
    """Without this a *later* SO_REUSEADDR socket can still steal the port."""
    listener = DHCPListener(listen=("127.0.0.1", 0))
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


# --- a bind that fails partway leaves the listener as it found it ---


def _held_port() -> "tuple[socket.socket, int]":
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", 0))
    return holder, holder.getsockname()[1]


def test_a_bind_that_fails_partway_closes_what_it_opened() -> None:
    """The first address binds and the second is held: nothing stays bound."""
    holder, port = _held_port()
    listener = DHCPListener(listen=[("127.0.0.1", 0), ("127.0.0.1", port)])
    try:
        with pytest.raises(OSError):
            listener.bind()
        assert listener.bound_addresses == ()
        assert listener._sockets == []
        assert listener._endpoints == {}
    finally:
        holder.close()
        listener.close()


def test_a_failed_bind_keeps_the_sockets_an_earlier_bind_opened() -> None:
    """Only what the failing call opened is closed; the listener is as it was."""
    holder, port = _held_port()
    listener = DHCPListener(listen=("127.0.0.1", 0))
    listener.bind()
    try:
        before = listener.bound_addresses
        socket_before = listener._sockets[0]
        listener._listen = list(listener._listen) + [
            type(listener._listen[0])("127.0.0.1", port)
        ]
        with pytest.raises(OSError):
            listener.bind()
        assert listener.bound_addresses == before
        assert socket_before.fileno() != -1
    finally:
        holder.close()
        listener.close()


def test_with_a_listener_that_cannot_bind_holds_no_port() -> None:
    holder, port = _held_port()
    listener = DHCPListener(listen=[("127.0.0.1", 0), ("127.0.0.1", port)])
    try:
        with pytest.raises(OSError):
            with listener:
                pass  # pragma: no cover - __enter__ raises
        assert listener.bound_addresses == ()
    finally:
        holder.close()


# --- an address-bound socket hears no broadcast where the platform says so ---


@pytest.fixture
def fresh_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """The warning is once per process: let each test see it again."""
    # the bind step is not public
    import pydhcp.listener._binding as binding

    monkeypatch.setattr(binding, "_ADDRESS_BOUND_WARNED", False)


def _platform(monkeypatch: pytest.MonkeyPatch, hears_no_broadcast: bool) -> None:
    """Say what the platform does, without changing `sys.platform` under netimps."""
    # the bind step is not public
    import pydhcp.listener._binding as binding

    monkeypatch.setattr(
        binding, "_address_bound_hears_no_broadcast", lambda: hears_no_broadcast
    )


def _warnings(caplog: pytest.LogCaptureFixture) -> "list[str]":
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and "broadcast" in record.getMessage()
    ]


def _a_routable_host_address() -> str:
    import netimps

    from netimps import LINK_LOCAL_V4

    for adapter in netimps.get_interfaces():
        if adapter.is_loopback:
            continue
        for entry in adapter.ips:
            if isinstance(entry, ipaddress.IPv4Interface) and (
                entry.ip not in LINK_LOCAL_V4
            ):
                return str(entry.ip)
    pytest.skip("no non-loopback adapter with a routable IPv4 address")


def test_two_address_bound_sockets_are_warned_about_once(
    fresh_warning: None,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _platform(monkeypatch, True)
    address = _a_routable_host_address()
    listeners = [DHCPListener(listen=(address, 0)), DHCPListener(listen=(address, 0))]
    try:
        with caplog.at_level(logging.WARNING, logger="pydhcp"):
            for listener in listeners:
                listener.bind()
    finally:
        for listener in listeners:
            listener.close()
    reports = _warnings(caplog)
    assert len(reports) == 1, reports
    assert address in reports[0] and "wildcard" in reports[0]


def test_windows_hears_broadcast_on_an_address_so_it_is_not_warned_about(
    fresh_warning: None,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _platform(monkeypatch, False)
    address = _a_routable_host_address()
    listener = DHCPListener(listen=(address, 0))
    try:
        with caplog.at_level(logging.WARNING, logger="pydhcp"):
            listener.bind()
    finally:
        listener.close()
    assert _warnings(caplog) == []


def test_the_wildcard_and_loopback_are_not_warned_about(
    fresh_warning: None,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _platform(monkeypatch, True)
    listeners = [
        DHCPListener(listen=("127.0.0.1", 0)),
        DHCPListener(listen=("0.0.0.0", 0)),
    ]
    try:
        with caplog.at_level(logging.WARNING, logger="pydhcp"):
            for listener in listeners:
                listener.bind()
    finally:
        for listener in listeners:
            listener.close()
    assert _warnings(caplog) == []


def test_a_held_port_is_reported_in_netimps_words() -> None:
    """The error is netimps' own: no port suggestion and no testing hint are
    added to a message that names the port."""
    from netimps import AddressInUseError

    holder, port = _held_port()
    listener = DHCPListener(listen=("127.0.0.1", port))
    try:
        with pytest.raises(AddressInUseError) as exc_info:
            listener.bind()
    finally:
        holder.close()
        listener.close()

    message = str(exc_info.value)
    assert str(port) in message
    assert "try port" not in message.lower()
    assert "6767" not in message


def test_a_socket_that_fails_to_close_is_logged_not_swallowed(caplog) -> None:
    from pydhcp.listener._binding import _close_socket

    class Stubborn:
        def close(self) -> None:
            raise OSError("already gone")

    endpoints = {}
    with caplog.at_level(logging.DEBUG, logger="pydhcp.listener._binding"):
        _close_socket(Stubborn(), endpoints)  # type: ignore[arg-type]
    assert any(
        "Closing a listening socket failed" in r.getMessage() for r in caplog.records
    )
