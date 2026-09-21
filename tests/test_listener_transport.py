"""Sending and receiving one datagram, at the edges.

`transport-29` (an oversized datagram was decoded from its truncated half),
`transport-25` (three unrelated failures shared one log line and no traceback)
and `transport-16` (the broadcast fallback retried a broadcast, and the
`IP_PKTINFO` send path had neither the fallback nor the 0.0.0.0 mapping).
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time

import pytest

from conftest import build_request
from pydhcp import listener as listener_module
from pydhcp.listener import (
    DhcpListener,
    PktInfoUdpTransport,
    UdpTransport,
    _recv_with_pktinfo,
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
    mid-option. Windows fails the same call with WSAEMSGSIZE; both land in the
    same counter now."""
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


def test_recv_with_pktinfo_reports_the_msg_trunc_flag(monkeypatch) -> None:
    """The flags `recvmsg` returns were discarded outright.

    Driven through a stub rather than a real POSIX socket so it runs on every
    platform: `recvmsg` does not exist on Windows, which is precisely how a
    POSIX-only truncation went unnoticed.
    """
    monkeypatch.setattr(listener_module, "CMSG_SPACE", lambda n: n + 16)
    monkeypatch.setattr(listener_module, "IP_PKTINFO", 8)
    monkeypatch.setattr(listener_module, "MSG_TRUNC", 0x20)

    def fake_recvmsg(sock, bufsize, ancbufsize):
        return (b"z" * bufsize, [], 0x20, ("192.0.2.5", 68))

    monkeypatch.setattr(listener_module, "_RECVMSG", fake_recvmsg)

    with pytest.raises(listener_module._TruncatedDatagram) as exc_info:
        _recv_with_pktinfo(object(), 576)  # type: ignore[arg-type]

    assert "576" in str(exc_info.value)
    assert "192.0.2.5" in str(exc_info.value)


def test_recv_with_pktinfo_warns_when_the_control_data_was_cut(
    monkeypatch, caplog
) -> None:
    """MSG_CTRUNC leaves the payload intact but the interface unresolved, and
    the interface is what the reply's SERVER_IDENTIFIER comes from."""
    monkeypatch.setattr(listener_module, "CMSG_SPACE", lambda n: n + 16)
    monkeypatch.setattr(listener_module, "IP_PKTINFO", 8)
    monkeypatch.setattr(listener_module, "MSG_CTRUNC", 0x08)

    def fake_recvmsg(sock, bufsize, ancbufsize):
        return (b"z" * 40, [], 0x08, ("192.0.2.5", 68))

    monkeypatch.setattr(listener_module, "_RECVMSG", fake_recvmsg)

    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        data, client, ifindex, local_ip = _recv_with_pktinfo(object(), 576)  # type: ignore[arg-type]

    assert len(data) == 40
    assert ifindex is None and local_ip is None
    assert any("control data truncated" in r.getMessage() for r in caplog.records)


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


def test_the_pktinfo_send_maps_a_wildcard_destination_to_broadcast(
    monkeypatch,
) -> None:
    """`sendmsg` was handed `str(dest)`, so a yiaddr of 0.0.0.0 -- the normal
    case for a client that has no address yet -- addressed the reply to host
    0.0.0.0, the one destination it must never go to."""
    monkeypatch.setattr(listener_module, "IP_PKTINFO", 8)
    sock = FailingSocket()
    transport = PktInfoUdpTransport(sock)  # type: ignore[arg-type]
    transport.ifindex = 3
    transport.local_ip = IPv4("192.0.2.1")

    assert transport.send(b"x" * 20, IPv4("0.0.0.0"), 68, b"\x00" * 6) == 20

    assert sock.sendmsg_calls == [("255.255.255.255", 68)]
    assert sock.sendto_calls == []


def test_the_pktinfo_send_falls_back_to_plain_udp(monkeypatch) -> None:
    """A stale ifindex or a local_ip no longer on that adapter used to lose the
    reply outright: this path had no fallback of any kind."""
    monkeypatch.setattr(listener_module, "IP_PKTINFO", 8)
    sock = FailingSocket(sendmsg_error=OSError("invalid argument"))
    transport = PktInfoUdpTransport(sock)  # type: ignore[arg-type]
    transport.ifindex = 99999
    transport.local_ip = IPv4("192.0.2.1")

    assert transport.send(b"x" * 20, IPv4("192.0.2.9"), 68, b"\x00" * 6) == 20

    assert sock.sendmsg_calls == [("192.0.2.9", 68)]
    assert sock.sendto_calls == [("192.0.2.9", 68)]


def test_the_pktinfo_fallback_never_escalates_a_unicast_to_a_broadcast(
    monkeypatch,
) -> None:
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
    monkeypatch.setattr(listener_module, "IP_PKTINFO", 8)

    class Dead(FailingSocket):
        def sendmsg(self, buffers, ancdata, flags, address):
            self.sendmsg_calls.append(address)
            raise OSError("invalid argument (stale ifindex)")

        def sendto(self, data, address):
            self.sendto_calls.append(address)
            if address[0] == "255.255.255.255":
                return len(data)
            raise OSError("network is unreachable")

    sock = Dead()
    transport = PktInfoUdpTransport(sock)  # type: ignore[arg-type]
    transport.ifindex = 99999
    transport.local_ip = IPv4("192.0.2.1")

    with pytest.raises(OSError):
        transport.send(b"x" * 20, IPv4("192.0.2.50"), 68, b"\x00" * 6)

    assert sock.sendto_calls == [("192.0.2.50", 68)], sock.sendto_calls
    assert ("255.255.255.255", 68) not in sock.sendto_calls


def test_the_pktinfo_fallback_still_broadcasts_for_an_unconfigured_client(
    monkeypatch,
) -> None:
    """The counterpart: broadcast *is* the right delivery when the reply was
    already addressed to the limited broadcast, so the guard must not turn that
    into a lost reply."""
    monkeypatch.setattr(listener_module, "IP_PKTINFO", 8)
    sock = FailingSocket(sendmsg_error=OSError("invalid argument"))
    transport = PktInfoUdpTransport(sock)  # type: ignore[arg-type]
    transport.ifindex = 99999
    transport.local_ip = IPv4("192.0.2.1")

    assert transport.send(b"x" * 20, IPv4("0.0.0.0"), 68, b"\x00" * 6) == 20

    assert sock.sendmsg_calls == [("255.255.255.255", 68)]
    assert sock.sendto_calls == [("255.255.255.255", 68)]


def test_the_pktinfo_control_message_is_still_what_it_was(monkeypatch) -> None:
    """Guard: the mapping and the fallback must not disturb the ancillary data
    that is the whole reason this transport exists."""
    monkeypatch.setattr(listener_module, "IP_PKTINFO", 8)
    seen: list = []

    class Recording(FailingSocket):
        def sendmsg(self, buffers, ancdata, flags, address):
            seen.append(ancdata)
            return sum(len(b) for b in buffers)

    transport = PktInfoUdpTransport(Recording())  # type: ignore[arg-type]
    transport.ifindex = 3
    transport.local_ip = IPv4("192.0.2.1")
    transport.send(b"x" * 20, IPv4("192.0.2.9"), 68, b"\x00" * 6)

    ((level, ctype, data),) = seen[0]
    assert level == socket.IPPROTO_IP
    assert ctype == 8
    ifindex, local, _ = struct.unpack("=I4s4s", data)
    assert ifindex == 3
    assert socket.inet_ntoa(local) == "192.0.2.1"
