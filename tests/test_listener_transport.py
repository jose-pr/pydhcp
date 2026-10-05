"""Sending and receiving one datagram, at the edges.

`transport-29` (an oversized datagram was decoded from its truncated half),
`transport-25` (three unrelated failures shared one log line and no traceback)
and `transport-16` (the broadcast fallback retried a broadcast, and the
`IP_PKTINFO` send path had neither the fallback nor the 0.0.0.0 mapping).
"""

from __future__ import annotations

import logging
import socket
import threading
import time

import pytest

from conftest import LOOPBACK_ALIAS_BINDABLE, build_request
from pydhcp import listener as listener_module
import ipaddress
import types

import netimps

from pydhcp.listener import (
    DhcpListener,
    PktInfoUdpTransport,
    UdpTransport,
    _arrival,
)
from pydhcp.network import IPv4


class RecordingListener(DhcpListener):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.handled: list = []

    def handle(self, msg, context) -> None:
        self.handled.append(msg)


def _drain(listener: DhcpListener, turns: int = 1) -> None:
    """Run the receive loop just long enough to take what is already queued."""
    listener._select_timeout = 0.05
    thread = threading.Thread(target=listener.listen, daemon=True)
    thread.start()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        # getattr: the counters are part of the fix, and this helper has to
        # keep working against a listener without them so that the assertions
        # below -- not an AttributeError in here -- are what fails on the old
        # behaviour.
        if (
            getattr(listener, "handled", None)
            or listener.metrics.packets_dropped_truncated
            or listener.metrics.packets_dropped_error
        ):
            break
        time.sleep(0.02)
    listener.stop()
    thread.join(5)
    assert not thread.is_alive()


# --- transport-29: a datagram that does not fit is dropped, not decoded ---


def test_an_oversized_datagram_is_dropped_rather_than_half_decoded() -> None:
    """`recvfrom_into` was given a buffer exactly `max_packet_size` long and its
    result was decoded unconditionally. Measured on Linux with
    `max_packet_size=576`: a 1102-octet datagram was silently delivered as 576
    octets and handed to the decoder, whose option stream then stops
    mid-option. Windows reports the same cut as `truncated`; both land in the
    same counter."""
    listener = RecordingListener(listen=("127.0.0.1", 0), max_packet_size=576)
    listener.bind()
    address = listener.bound_addresses[0]

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # A real BOOTREQUEST, padded past the limit with option 0 (PAD), so the
    # truncated half would have decoded cleanly and looked like a valid packet.
    payload = build_request().encode() + b"\x00" * 1102
    sender.sendto(payload, (str(address.ip), address.port))
    sender.close()

    _drain(listener)

    assert listener.handled == [], "a truncated datagram reached handle()"
    assert listener.metrics.packets_dropped_truncated == 1
    assert listener.metrics.packets_received == 0


def test_a_datagram_that_exactly_fills_the_buffer_is_still_accepted() -> None:
    """The counterpart: the extra octet must not turn a legal packet away."""
    message = build_request()
    encoded = message.encode()
    listener = RecordingListener(listen=("127.0.0.1", 0), max_packet_size=len(encoded))
    listener.bind()
    address = listener.bound_addresses[0]

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(encoded, (str(address.ip), address.port))
    sender.close()

    _drain(listener)

    assert listener.metrics.packets_dropped_truncated == 0
    assert len(listener.handled) == 1


def _datagram(**fields) -> "netimps.Datagram":
    fields.setdefault("data", b"z" * 40)
    fields.setdefault("sender", ("192.0.2.5", 68))
    return netimps.Datagram(**fields)


def _interface(*addresses: str):
    """Just the part of a netimps `Interface` that `_arrival` reads."""
    return types.SimpleNamespace(ips=[ipaddress.ip_interface(a) for a in addresses])


def test_arrival_reports_the_msg_trunc_flag() -> None:
    """The flags `recvmsg` returns were discarded outright, so a datagram cut
    to the buffer was decoded from its leading half."""
    with pytest.raises(listener_module._TruncatedDatagram) as exc_info:
        _arrival(_datagram(data=b"z" * 576, truncated=True), 576)

    assert "576" in str(exc_info.value)
    assert "192.0.2.5" in str(exc_info.value)


def test_arrival_treats_a_full_extra_octet_as_truncated() -> None:
    """The path with no MSG_TRUNC to report: a datagram that fills the
    one-octet-larger buffer was longer than the limit."""
    with pytest.raises(listener_module._TruncatedDatagram):
        _arrival(_datagram(data=b"z" * 577), 576)


def test_arrival_warns_when_the_control_data_was_cut(caplog) -> None:
    """MSG_CTRUNC leaves the payload intact but the interface unresolved, and
    the interface is what the reply's SERVER_IDENTIFIER comes from."""
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        data, client, ifindex, local_ip = _arrival(
            _datagram(control_truncated=True), 576
        )

    assert len(data) == 40
    assert ifindex is None and local_ip is None
    assert any("control data truncated" in r.getMessage() for r in caplog.records)


def test_arrival_answers_a_broadcast_from_the_interface_address() -> None:
    """`Datagram.local_address` is the *destination*. For a broadcast DISCOVER
    that is 255.255.255.255, which names no interface and must never become
    the server identifier; the receiving interface's own address does."""
    *_, ifindex, local_ip = _arrival(
        _datagram(
            destination=IPv4("255.255.255.255"),
            interface_index=4,
            interface=_interface("fe80::1/64", "169.254.7.7/16", "192.0.2.1/24"),
        ),
        576,
    )

    assert ifindex == 4
    assert local_ip == IPv4("192.0.2.1"), "APIPA or the broadcast was chosen"


def test_arrival_keeps_a_unicast_destination_the_interface_holds() -> None:
    """A NIC with several addresses: the one the client addressed is the one
    to answer from."""
    *_, local_ip = _arrival(
        _datagram(
            destination=IPv4("192.0.2.2"),
            interface_index=4,
            interface=_interface("192.0.2.1/24", "192.0.2.2/24"),
        ),
        576,
    )

    assert local_ip == IPv4("192.0.2.2")


def test_arrival_resolves_an_apipa_only_interface() -> None:
    """An APIPA-only NIC is the normal state of an isolated DHCP-only segment;
    resolution must still find it, only selection prefers otherwise."""
    *_, local_ip = _arrival(
        _datagram(
            destination=IPv4("255.255.255.255"),
            interface_index=9,
            interface=_interface("169.254.7.7/16"),
        ),
        576,
    )

    assert local_ip == IPv4("169.254.7.7")


def test_arrival_without_an_interface_drops_a_broadcast_destination() -> None:
    *_, ifindex, local_ip = _arrival(
        _datagram(destination=IPv4("255.255.255.255"), interface_index=3), 576
    )

    assert ifindex == 3
    assert local_ip is None


def test_arrival_treats_a_zero_local_address_as_absent() -> None:
    """A zero-filled `ipi_spec_dst` decodes to 0.0.0.0; taken literally it
    resolved a synthetic 0.0.0.0/32 interface and the server served nothing."""
    *_, local_ip = _arrival(
        _datagram(destination=IPv4("0.0.0.0"), interface_index=3), 576
    )

    assert local_ip is None


def test_a_reply_to_a_vanished_client_does_not_cost_the_next_datagram(caplog) -> None:
    """On Windows an ICMP port-unreachable provoked by an earlier send surfaces
    as ConnectionResetError on a *later, unrelated* receive. Measured before
    `bind(connreset=False)`: one client that had gone away logged a full ERROR
    traceback on the server and counted the next datagram as dropped. POSIX
    reports such errors only on connected sockets, so there it always passed."""
    gone = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gone.bind(("127.0.0.1", 0))
    closed_port = gone.getsockname()[1]
    gone.close()

    listener = RecordingListener(listen=("127.0.0.1", 0), select_timeout=0.05)
    listener.bind()
    address = listener.bound_addresses[0]
    # The reply to the vanished client, from the listening socket itself.
    listener._sockets[0].sendto(b"x" * 20, ("127.0.0.1", closed_port))
    time.sleep(0.1)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(build_request().encode(), (str(address.ip), address.port))
    sender.close()

    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        _drain(listener)

    assert len(listener.handled) == 1
    assert listener.metrics.packets_dropped_error == 0
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


# --- transport-25: three failures, three reports ---


class ExplodingListener(DhcpListener):
    def handle(self, msg, context) -> None:
        raise RuntimeError("deliberate handler failure")


def test_an_undecodable_datagram_is_a_warning_with_its_size(caplog) -> None:
    listener = RecordingListener(listen=("127.0.0.1", 0), select_timeout=0.05)
    listener.bind()
    address = listener.bound_addresses[0]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(b"not a dhcp packet", (str(address.ip), address.port))
    sender.close()

    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        _drain(listener)

    assert listener.metrics.packets_dropped_error == 1
    records = [r for r in caplog.records if "undecodable" in r.getMessage()]
    assert records, [r.getMessage() for r in caplog.records]
    assert records[0].levelno == logging.WARNING
    # The peer's fault, not ours: no traceback of our own decoder.
    assert records[0].exc_info is None
    assert "17-octet" in records[0].getMessage()


def test_a_failing_handler_is_an_error_with_a_traceback(caplog) -> None:
    """The one failure whose class name and `str()` say nothing about where it
    came from was the one logging them without `exc_info`."""
    listener = ExplodingListener(listen=("127.0.0.1", 0), select_timeout=0.05)
    listener.handled = []  # type: ignore[attr-defined]
    listener.bind()
    address = listener.bound_addresses[0]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(build_request().encode(), (str(address.ip), address.port))
    sender.close()

    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        _drain(listener)

    assert listener.metrics.packets_dropped_error == 1
    records = [r for r in caplog.records if "error handling request" in r.getMessage()]
    assert records, [r.getMessage() for r in caplog.records]
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None, "no traceback attached"
    assert records[0].exc_info[0] is RuntimeError


# --- transport-16: the broadcast fallback, and the pktinfo send path ---


class FailingSocket:
    """A socket whose sends fail, recording every attempt."""

    def __init__(self, sendto_error=None, sendmsg_error=None) -> None:
        self.sendto_calls: list = []
        self.sendmsg_calls: list = []
        self.sendto_error = sendto_error
        self.sendmsg_error = sendmsg_error

    def sendto(self, data, address):
        self.sendto_calls.append(address)
        if self.sendto_error is not None:
            raise self.sendto_error
        return len(data)

    def sendmsg(self, buffers, ancdata, flags, address):
        self.sendmsg_calls.append(address)
        if self.sendmsg_error is not None:
            raise self.sendmsg_error
        return sum(len(b) for b in buffers)


def test_a_failed_broadcast_is_not_retried_as_the_same_broadcast() -> None:
    """The "fallback" was the identical syscall with identical arguments, so it
    could only fail identically -- while the warning claimed a retry had been
    made and the *second* exception, not the first, reached the caller."""
    sock = FailingSocket(sendto_error=OSError("no broadcast permission"))
    transport = UdpTransport(sock)  # type: ignore[arg-type]

    with pytest.raises(OSError):
        transport.send(b"x" * 20, IPv4("255.255.255.255"), 68, b"\x00" * 6)

    assert sock.sendto_calls == [("255.255.255.255", 68)], sock.sendto_calls


def test_a_wildcard_destination_is_also_only_tried_once() -> None:
    """0.0.0.0 is mapped to the broadcast before the send, so it is the same
    address the fallback would have used."""
    sock = FailingSocket(sendto_error=OSError("no broadcast permission"))
    transport = UdpTransport(sock)  # type: ignore[arg-type]

    with pytest.raises(OSError):
        transport.send(b"x" * 20, IPv4("0.0.0.0"), 68, b"\x00" * 6)

    assert sock.sendto_calls == [("255.255.255.255", 68)]


def test_a_failed_unicast_is_not_escalated_to_a_broadcast() -> None:
    """`gap1-posix-pktinfo-4`. This test used to assert the opposite.

    Its stated rationale was "no ARP entry for an address the client has not
    configured yet is exactly why the fallback exists" -- and this project has
    already disproved that premise by measurement. `DhcpServer` documents it:
    an L2 send to an address the client cannot answer ARP for is dropped by the
    kernel "with no error at all", which is how the original POSIX no-reply
    defect stayed hidden. So the retry never fired for the case it was written
    for.

    What it did fire for is real socket errors, where broadcasting is both
    useless and a disclosure -- a reply the caller deliberately unicast goes to
    the whole segment carrying yiaddr, chaddr, the lease options and any echoed
    option 82. Whether to broadcast is the caller's decision and is already made
    there.
    """
    calls: list = []

    class OnlyUnicastFails(FailingSocket):
        def sendto(self, data, address):
            calls.append(address)
            if address[0] != "255.255.255.255":
                raise OSError("no route to host")
            return len(data)

    sock = OnlyUnicastFails()
    transport = UdpTransport(sock)  # type: ignore[arg-type]

    with pytest.raises(OSError):
        transport.send(b"x" * 20, IPv4("192.0.2.9"), 68, b"\x00" * 6)

    assert calls == [("192.0.2.9", 68)], "the reply was escalated to a broadcast"


def test_a_wildcard_destination_is_still_broadcast() -> None:
    """The half that must NOT change: 0.0.0.0 means "this client has no address
    yet", and the limited broadcast is the correct delivery for it -- measured
    against ISC dhclient, which saw none of the unicast OFFERs."""
    sock = FailingSocket()
    transport = UdpTransport(sock)  # type: ignore[arg-type]

    transport.send(b"x" * 20, IPv4("0.0.0.0"), 68, b"\x00" * 6)

    assert sock.sendto_calls == [("255.255.255.255", 68)]


class RecordingEndpoint:
    """The part of a netimps `UdpEndpoint` the pinned transport uses.

    The pinned send now goes through netimps, which builds the per-platform
    control message itself, so what matters here is what the transport *asks*
    for: the destination, and the source it pins.
    """

    has_src_pinning = True

    def __init__(self, error=None) -> None:
        self.sends: list = []
        self.error = error

    def send(self, data, address, port, src=None):
        self.sends.append(((address, port), src))
        if self.error is not None:
            raise self.error
        return len(data)


def _pinned(sock, endpoint, ifindex=3, local_ip="192.0.2.1"):
    transport = PktInfoUdpTransport(sock, endpoint)  # type: ignore[arg-type]
    transport.ifindex = ifindex
    transport.local_ip = IPv4(local_ip)
    return transport


def test_the_pktinfo_send_maps_a_wildcard_destination_to_broadcast() -> None:
    """`sendmsg` was handed `str(dest)`, so a yiaddr of 0.0.0.0 -- the normal
    case for a client that has no address yet -- addressed the reply to host
    0.0.0.0, the one destination it must never go to."""
    sock, endpoint = FailingSocket(), RecordingEndpoint()

    assert (
        _pinned(sock, endpoint).send(b"x" * 20, IPv4("0.0.0.0"), 68, b"\x00" * 6) == 20
    )

    assert [dest for dest, _src in endpoint.sends] == [("255.255.255.255", 68)]
    assert sock.sendto_calls == []


def test_the_pktinfo_send_falls_back_to_plain_udp() -> None:
    """A stale ifindex or a local_ip no longer on that adapter used to lose the
    reply outright: this path had no fallback of any kind."""
    sock = FailingSocket()
    endpoint = RecordingEndpoint(error=OSError("invalid argument"))

    assert (
        _pinned(sock, endpoint, ifindex=99999).send(
            b"x" * 20, IPv4("192.0.2.9"), 68, b"\x00" * 6
        )
        == 20
    )

    assert [dest for dest, _src in endpoint.sends] == [("192.0.2.9", 68)]
    assert sock.sendto_calls == [("192.0.2.9", 68)]


def test_the_pktinfo_fallback_never_escalates_a_unicast_to_a_broadcast() -> None:
    """The fallback must not become a way to leak a reply to the segment.

    The base `send` answers a failed unicast with a broadcast, which is right
    for a client that has no address yet and wrong for one the server
    deliberately unicast to -- a RENEWING client at its own ciaddr, or a relay
    at giaddr. Measured on the first version of the fallback, which routed
    through it: `sendmsg -> 192.0.2.50`, `sendto -> 192.0.2.50`, `sendto ->
    255.255.255.255`, putting yiaddr, chaddr, the lease options and the echoed
    RELAY_AGENT_INFORMATION (RFC 3046 s2.2) in front of every host on the
    segment. The reply is lost instead, which is what it was before the
    fallback existed.
    """

    class Dead(FailingSocket):
        def sendto(self, data, address):
            self.sendto_calls.append(address)
            if address[0] == "255.255.255.255":
                return len(data)
            raise OSError("network is unreachable")

    sock = Dead()
    endpoint = RecordingEndpoint(error=OSError("invalid argument (stale ifindex)"))

    with pytest.raises(OSError):
        _pinned(sock, endpoint, ifindex=99999).send(
            b"x" * 20, IPv4("192.0.2.50"), 68, b"\x00" * 6
        )

    assert sock.sendto_calls == [("192.0.2.50", 68)], sock.sendto_calls
    assert ("255.255.255.255", 68) not in sock.sendto_calls


def test_the_pktinfo_fallback_still_broadcasts_for_an_unconfigured_client() -> None:
    """The counterpart: broadcast *is* the right delivery when the reply was
    already addressed to the limited broadcast, so the guard must not turn that
    into a lost reply."""
    sock = FailingSocket()
    endpoint = RecordingEndpoint(error=OSError("invalid argument"))

    assert (
        _pinned(sock, endpoint, ifindex=99999).send(
            b"x" * 20, IPv4("0.0.0.0"), 68, b"\x00" * 6
        )
        == 20
    )

    assert [dest for dest, _src in endpoint.sends] == [("255.255.255.255", 68)]
    assert sock.sendto_calls == [("255.255.255.255", 68)]


def test_the_pin_names_exactly_the_receiving_address_and_interface() -> None:
    """The pin is a netimps `Interface` holding just ``local_ip``: an adapter
    with several IPv4 addresses must answer from the one the client used, and
    a bare address would make netimps enumerate every adapter per reply."""
    endpoint = RecordingEndpoint()
    _pinned(FailingSocket(), endpoint).send(b"x" * 20, IPv4("192.0.2.9"), 68, b"\0" * 6)

    ((_dest, src),) = endpoint.sends
    assert isinstance(src, netimps.Interface)
    assert src.index == 3
    assert [str(ip) for ip in src.ips] == ["192.0.2.1/32"]


def test_no_local_address_means_no_pin() -> None:
    """With nothing to pin, the plain transport's rules apply unchanged."""
    sock, endpoint = FailingSocket(), RecordingEndpoint()
    transport = PktInfoUdpTransport(sock, endpoint)  # type: ignore[arg-type]
    transport.ifindex = 3

    transport.send(b"x" * 20, IPv4("192.0.2.9"), 68, b"\x00" * 6)

    assert endpoint.sends == []
    assert sock.sendto_calls == [("192.0.2.9", 68)]


@pytest.mark.skipif(
    not LOOPBACK_ALIAS_BINDABLE, reason="127.0.0.2 is not usable on this host"
)
def test_a_pinned_reply_leaves_from_the_pinned_address(caplog) -> None:
    """On real sockets: the receiver sees the pinned source, not the one the
    routing table would pick. 127.0.0.2 is used because the default source for
    a loopback send is 127.0.0.1, so only a working pin can produce it.

    Windows Server (the GitHub runner) refuses that pin with WSAEADDRNOTAVAIL:
    127.0.0.2 binds there but is not an *assigned* address, while Windows 11
    accepts it. Production never meets this -- the pin is always the address
    the request arrived at -- so only that one refusal skips."""
    loopback = netimps.get_interface("127.0.0.1")
    assert loopback is not None and loopback.index

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(2.0)
    sender = netimps.bind("0.0.0.0", 0)
    try:
        transport = PktInfoUdpTransport(sender)
        if not transport.endpoint.has_src_pinning:
            pytest.skip("no source pinning on this platform")
        transport.ifindex = loopback.index
        transport.local_ip = IPv4("127.0.0.2")
        with caplog.at_level(logging.WARNING, logger="pydhcp"):
            transport.send(b"x" * 20, IPv4("127.0.0.1"), receiver.getsockname()[1], b"")
        _data, (source, _port) = receiver.recvfrom(64)
    finally:
        sender.close()
        receiver.close()

    if any("WinError 10049" in r.getMessage() for r in caplog.records):
        pytest.skip("this Windows build refuses a pin to an unassigned 127.0.0.2")
    assert source == "127.0.0.2"
