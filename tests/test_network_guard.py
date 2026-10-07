"""The suite's network guard refuses anything that would leave this host.

Each refusal below is provoked on purpose with an address from TEST-NET-1
(RFC 5737), which nothing answers: the guard acts before the call reaches the
network, so nothing is sent, and a failure of the guard would show as a
datagram into a documentation range rather than as a hang.
"""

from __future__ import annotations

import socket

import netimps
import pytest

OFF_HOST = "192.0.2.53"


def _udp() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def _refused(network_escapes: "list[str]", call: "object") -> "list[str]":
    """Run `call`, expect the guard's refusal, and take the record so teardown passes."""
    with pytest.raises(AssertionError, match="tests must never leave the host"):
        call()  # type: ignore[operator]
    seen = list(network_escapes)
    network_escapes.clear()
    return seen


def test_a_datagram_to_another_host_is_refused(network_escapes) -> None:
    with _udp() as sock:
        seen = _refused(network_escapes, lambda: sock.sendto(b"x", (OFF_HOST, 67)))

    assert seen and "socket.sendto" in seen[0] and OFF_HOST in seen[0]


def test_the_limited_broadcast_is_refused(network_escapes) -> None:
    """A broadcast leaves by the default interface, so it is not on this host."""
    with _udp() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        seen = _refused(
            network_escapes, lambda: sock.sendto(b"x", ("255.255.255.255", 67))
        )

    assert seen and "255.255.255.255" in seen[0]


def test_a_connect_to_another_host_is_refused(network_escapes) -> None:
    with _udp() as sock:
        seen = _refused(network_escapes, lambda: sock.connect((OFF_HOST, 67)))

    assert seen and "socket.connect" in seen[0]


def test_the_endpoint_send_of_netimps_is_refused_too(network_escapes) -> None:
    """netimps sends through its own endpoint, which does not go by `sendto` on Windows."""
    with _udp() as sock:
        endpoint = netimps.UDPEndpoint(sock)
        seen = _refused(network_escapes, lambda: endpoint.send(b"x", OFF_HOST, 67))

    assert seen and "UDPEndpoint.send" in seen[0]


def test_the_async_endpoint_send_is_refused_at_the_call(network_escapes) -> None:
    with _udp() as sock:
        endpoint = netimps.UDPEndpoint(sock)
        seen = _refused(network_escapes, lambda: endpoint.asend(b"x", OFF_HOST, 67))

    assert seen and "UDPEndpoint.asend" in seen[0]


def test_a_name_that_needs_a_name_server_is_refused(network_escapes) -> None:
    seen = _refused(
        network_escapes, lambda: socket.getaddrinfo("dhcp.example.invalid", 67)
    )

    assert seen and "getaddrinfo" in seen[0]


def test_an_address_literal_is_not_a_lookup() -> None:
    """Parsing four numbers asks nobody, so the guard lets it through."""
    assert socket.getaddrinfo(OFF_HOST, 67, type=socket.SOCK_DGRAM)


def test_loopback_is_delivered() -> None:
    with _udp() as receiver, _udp() as sender:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(5.0)
        sender.sendto(b"x", receiver.getsockname())

        assert receiver.recv(16) == b"x"


def test_a_test_that_asks_may_address_another_host(
    allow_off_host_destination: bool,
) -> None:
    """Connecting a UDP socket sends nothing; it only fixes the peer."""
    with _udp() as sock:
        sock.connect((OFF_HOST, 67))

        assert sock.getpeername() == (OFF_HOST, 67)
