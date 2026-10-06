"""A line written for something a sender did is rate-limited, and every one is counted.

Each site gets the smallest input that proves the bound: five datagrams inside
one interval write one line, and one more after the interval writes a second
line that carries the running count (6). Time is passed in through the
listener's stamp (`received_monotonic`) or its clock, never slept.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import socket
import typing as ty
from unittest.mock import Mock

import pytest

from pydhcp import (
    AsyncDHCPListener,
    DHCPCapture,
    DHCPClient,
    DHCPListener,
    DHCPMessage,
    DHCPOptions,
    DHCPRelay,
    DHCPRequestContext,
    DHCPServer,
    NetworkInterface,
    SocketAddress,
)
from pydhcp import _clock, _leniency
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.listener._limit import BRIEF_OCTETS, _brief, _LogLimit
from pydhcp.listener._receive import _arrival
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType, DHCPOpcode
from conftest import build_request

import netimps

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
INSIDE = 5
AFTER = 61.0
UTC0 = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


class Clock:
    """The one clock a test moves: the listener's reading, in seconds."""

    def __init__(self) -> None:
        self.t = 1000.0

    def instant(self) -> _clock._Instant:
        return _clock._Instant(UTC0 + dt.timedelta(seconds=self.t), self.t)


@pytest.fixture
def clock() -> Clock:
    return Clock()


def _context(clock: Clock, client: str = "10.0.0.50", port: int = 68):
    return DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress(client, port),
        client_mac=CHADDR,
        received_at=clock.instant().utc,
        received_monotonic=clock.t,
    )


def _written(
    caplog: pytest.LogCaptureFixture, logger: str
) -> "list[logging.LogRecord]":
    return [
        r for r in caplog.records if r.name == logger and r.levelno >= logging.WARNING
    ]


def _assert_bounded(
    caplog: pytest.LogCaptureFixture,
    clock: Clock,
    logger: str,
    send: "ty.Callable[[], None]",
) -> None:
    """Five occurrences inside the interval write one line; the sixth, after it, a second."""
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        for _ in range(INSIDE):
            send()
            clock.t += 1.0
        assert len(_written(caplog, logger)) == 1, [
            r.getMessage() for r in _written(caplog, logger)
        ]
        assert "occurrences so far" not in _written(caplog, logger)[0].getMessage()
        clock.t += AFTER
        send()
    lines = _written(caplog, logger)
    assert len(lines) == 2, [r.getMessage() for r in lines]
    assert f"[{INSIDE + 1} occurrences so far" in lines[1].getMessage()


# -- the limiter ------------------------------------------------------------


def test_the_first_occurrence_is_written_and_the_next_one_waits_an_interval(
    caplog: pytest.LogCaptureFixture,
) -> None:
    limit = _LogLimit(interval=10.0)
    log = logging.getLogger("pydhcp.test.limit")
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        written = [
            limit.log(log, logging.WARNING, "r", "line", now=t) for t in (0, 1, 9)
        ]
        assert written == [True, False, False]
        assert limit.log(log, logging.WARNING, "r", "line", now=10.0) is True
    assert [r.getMessage() for r in caplog.records] == [
        "line",
        "line [4 occurrences so far; at most one line per 10 s]",
    ]
    assert limit.count(log, "r") == 4


def test_reasons_are_limited_apart_and_per_logger(
    caplog: pytest.LogCaptureFixture,
) -> None:
    limit = _LogLimit(interval=10.0)
    one, two = logging.getLogger("pydhcp.a"), logging.getLogger("pydhcp.b")
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        assert limit.log(one, logging.WARNING, "x", "a", now=0.0)
        assert limit.log(one, logging.WARNING, "y", "b", now=0.0)
        assert limit.log(two, logging.WARNING, "x", "c", now=0.0)
        assert not limit.log(one, logging.WARNING, "x", "a", now=1.0)


def test_the_table_is_capped_and_the_counts_stay_exact(
    caplog: pytest.LogCaptureFixture,
) -> None:
    limit = _LogLimit(interval=10.0, max_reasons=4)
    log = logging.getLogger("pydhcp.test.cap")
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        for index in range(40):
            limit.log(log, logging.WARNING, f"reason {index}", "line", now=0.0)
    assert limit.tracked() == 5  # the four, and the one entry the rest share
    assert [limit.count(log, f"reason {i}") for i in range(4)] == [1, 1, 1, 1]
    assert limit.count(log, "reason 39") == 36
    assert len(caplog.records) == 5


def test_a_traceback_goes_with_the_first_occurrence_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    limit = _LogLimit(interval=1.0)
    log = logging.getLogger("pydhcp.test.trace")
    with caplog.at_level(logging.ERROR, logger="pydhcp"):
        for now in (0.0, 5.0):
            try:
                raise KeyError("x")
            except KeyError:
                limit.log(log, logging.ERROR, "r", "failed", now=now, exc_info=True)
    first, second = caplog.records
    assert first.exc_info is not None
    assert not second.exc_info


def test_text_a_sender_wrote_is_escaped_and_cut() -> None:
    assert _brief("a\nb\x1b[31mé") == "a\\nb\\x1b[31m\\xe9"
    long = _brief("x" * 500)
    assert len(long) < BRIEF_OCTETS + 40
    assert long.endswith("(500 characters)")


# -- what the decoders forgave ------------------------------------------------


def _octets_with_bad_names() -> bytes:
    raw = bytearray(build_request().encode())
    raw[44:48] = b"\xff\xfe\xfd\xfc"  # sname
    raw[108:112] = b"\xff\xfe\xfd\xfc"  # file
    return bytes(raw)


def _octets_with_a_cut_option() -> bytes:
    raw = build_request().encode().rstrip(b"\x00")
    return raw[:-1] + b"\x0c\x40ab"  # option 12 claims 64 octets, 2 arrive


@pytest.mark.parametrize(
    "octets",
    [_octets_with_bad_names, _octets_with_a_cut_option],
    ids=["text", "option"],
)
def test_a_decoder_writes_no_line_above_debug(
    octets: "ty.Callable[[], bytes]", caplog: pytest.LogCaptureFixture
) -> None:
    data = octets()
    with caplog.at_level(logging.DEBUG, logger="pydhcp"):
        for _ in range(INSIDE):
            DHCPMessage.decode(data)
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
    assert any(r.levelno == logging.DEBUG for r in caplog.records)


@pytest.mark.parametrize(
    "octets",
    [_octets_with_bad_names, _octets_with_a_cut_option],
    ids=["text", "option"],
)
def test_the_listener_counts_every_datagram_a_decoder_forgave(
    octets: "ty.Callable[[], bytes]",
    caplog: pytest.LogCaptureFixture,
    clock: Clock,
) -> None:
    listener = DHCPListener(listen=("127.0.0.1", 0))
    listener._read_clock = clock.instant  # type: ignore[method-assign]
    listener.bind()
    sock = listener._sockets[0]
    data = octets()
    try:
        with caplog.at_level(logging.DEBUG, logger="pydhcp"):
            for _ in range(INSIDE):
                listener._dispatch(data, SocketAddress("127.0.0.1", 68), sock)
    finally:
        listener.close()
    assert listener.metrics.packets_decoded_leniently == INSIDE
    assert listener.metrics.packets_received == INSIDE
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_a_clean_datagram_is_not_counted_as_forgiven(clock: Clock) -> None:
    listener = DHCPListener(listen=("127.0.0.1", 0))
    listener._read_clock = clock.instant  # type: ignore[method-assign]
    listener.bind()
    try:
        listener._dispatch(
            build_request().encode(),
            SocketAddress("127.0.0.1", 68),
            listener._sockets[0],
        )
    finally:
        listener.close()
    assert listener.metrics.packets_decoded_leniently == 0


def test_the_collector_counts_only_while_it_is_open() -> None:
    _leniency.note()
    with _leniency.collecting() as seen:
        _leniency.note()
        _leniency.note()
    _leniency.note()
    assert seen.count == 2


# -- the listener -------------------------------------------------------------

CORE = "pydhcp.listener._core"


def _listener(clock: Clock, **kwargs: ty.Any) -> DHCPListener:
    listener = DHCPListener(listen=("127.0.0.1", 0), **kwargs)
    listener._read_clock = clock.instant  # type: ignore[method-assign]
    listener.bind()
    return listener


def test_an_undecodable_datagram_is_limited_and_counted(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    listener = _listener(clock)
    sock = listener._sockets[0]
    try:
        _assert_bounded(
            caplog,
            clock,
            CORE,
            lambda: listener._dispatch(b"\x00", SocketAddress("127.0.0.1", 68), sock),
        )
    finally:
        listener.close()
    assert listener.metrics.packets_dropped_error == INSIDE + 1


def test_an_undecodable_datagram_names_the_octets_it_had_not_the_octets(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    listener = _listener(clock)
    try:
        with caplog.at_level(logging.WARNING, logger="pydhcp"):
            listener._dispatch(b"\x1b[31m\n", SocketAddress("127.0.0.1", 68), None)  # type: ignore[arg-type]
    finally:
        listener.close()
    text = _written(caplog, CORE)[0].getMessage()
    assert "\x1b" not in text and "\n" not in text
    assert "6-octet" in text


class _Raises(DHCPListener):
    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        raise KeyError("lease backend lookup")


def test_a_handler_error_is_limited_counted_and_traced_once(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    listener = _Raises(listen=("127.0.0.1", 0))
    listener._read_clock = clock.instant  # type: ignore[method-assign]
    listener.bind()
    sock = listener._sockets[0]
    data = build_request().encode()
    try:
        _assert_bounded(
            caplog,
            clock,
            CORE,
            lambda: listener._dispatch(data, SocketAddress("127.0.0.1", 68), sock),
        )
    finally:
        listener.close()
    lines = _written(caplog, CORE)
    assert lines[0].exc_info is not None
    assert not lines[1].exc_info
    assert listener.metrics.packets_dropped_error == INSIDE + 1


def test_handler_errors_of_different_classes_are_limited_apart(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    errors: "list[Exception]" = [KeyError("a"), ValueError("b")]

    class Varies(DHCPListener):
        def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
            raise errors[0]

    listener = Varies(listen=("127.0.0.1", 0))
    listener._read_clock = clock.instant  # type: ignore[method-assign]
    listener.bind()
    data = build_request().encode()
    try:
        with caplog.at_level(logging.ERROR, logger="pydhcp"):
            for error in errors + errors:
                errors[0] = error
                listener._dispatch(
                    data, SocketAddress("127.0.0.1", 68), listener._sockets[0]
                )
    finally:
        listener.close()
    assert len(_written(caplog, CORE)) == 2


def test_an_oversized_datagram_is_limited_and_counted_by_the_sync_listener(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    listener = _listener(clock, max_packet_size=576)
    sock = listener._sockets[0]
    port = listener.bound_addresses[0].port
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:

        def send() -> None:
            sender.sendto(b"\x01" * 1200, ("127.0.0.1", port))
            listener._receive_one(sock)

        _assert_bounded(caplog, clock, CORE, send)
    finally:
        sender.close()
        listener.close()
    assert listener.metrics.packets_dropped_truncated == INSIDE + 1


def test_an_oversized_datagram_is_limited_and_counted_by_the_async_listener(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    import asyncio

    async def scenario() -> AsyncDHCPListener:
        listener = AsyncDHCPListener(listen=("127.0.0.1", 0), max_packet_size=576)
        listener._read_clock = clock.instant  # type: ignore[method-assign]
        await listener.start()
        port = listener.bound_addresses[0].port
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with caplog.at_level(logging.DEBUG, logger="pydhcp"):
                for _ in range(INSIDE):
                    sender.sendto(b"\x01" * 1200, ("127.0.0.1", port))
                for _ in range(200):
                    if listener.metrics.packets_dropped_truncated >= INSIDE:
                        break
                    await asyncio.sleep(0.02)
                assert len(_written(caplog, CORE)) == 1
                clock.t += AFTER
                sender.sendto(b"\x01" * 1200, ("127.0.0.1", port))
                for _ in range(200):
                    if listener.metrics.packets_dropped_truncated >= INSIDE + 1:
                        break
                    await asyncio.sleep(0.02)
        finally:
            sender.close()
            await listener.aclose()
        return listener

    listener = asyncio.new_event_loop().run_until_complete(scenario())
    lines = _written(caplog, CORE)
    assert len(lines) == 2
    assert f"[{INSIDE + 1} occurrences so far" in lines[1].getMessage()
    assert listener.metrics.packets_dropped_truncated == INSIDE + 1


def test_a_receive_error_is_limited_and_counted(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    listener = _listener(clock)
    sock = listener._sockets[0]

    class Broken:
        def recv(self, *_args: ty.Any, **_kwargs: ty.Any) -> ty.Any:
            raise ConnectionResetError(10054, "forcibly closed")

        def close(self) -> None:
            sock.close()

    listener._endpoints[sock] = Broken()  # type: ignore[assignment]
    try:
        _assert_bounded(caplog, clock, CORE, lambda: listener._receive_one(sock))
    finally:
        listener.close()
    assert listener.metrics.packets_dropped_error == INSIDE + 1


def test_truncated_control_data_is_limited(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    listener = _listener(clock)
    datagram = netimps.Datagram(
        data=b"x" * 300,
        sender=("127.0.0.1", 68),
        control_truncated=True,
    )

    def arrive() -> None:
        _arrival(datagram, 65535, listener._control_truncated)

    try:
        _assert_bounded(caplog, clock, "pydhcp.listener._core", arrive)
    finally:
        listener.close()


class _FailingEndpoint:
    has_src_pinning = True

    def send(self, *_args: ty.Any, **_kwargs: ty.Any) -> int:
        raise OSError(19, "No such device")


def test_a_pin_that_keeps_failing_is_limited(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from pydhcp.listener import PktInfoUDPTransport

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    transport = PktInfoUDPTransport(sock, _FailingEndpoint())  # type: ignore[arg-type]
    transport.local_ip = ipaddress.IPv4Address("127.0.0.1")
    transport.ifindex = 9999
    transport.limit = _LogLimit()
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    port = peer.getsockname()[1]
    try:
        with caplog.at_level(logging.WARNING, logger="pydhcp"):
            for _ in range(INSIDE):
                transport.send(
                    b"x" * 40,
                    ipaddress.IPv4Address("127.0.0.1"),
                    port=port,
                    client_mac=CHADDR,
                )
    finally:
        sock.close()
        peer.close()
    assert len(_written(caplog, "pydhcp.listener._transport")) == 1


# -- the server ----------------------------------------------------------------

HANDLERS = "pydhcp.server._handlers"


def _server(clock: Clock) -> DHCPServer:
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())
    server._read_clock = clock.instant  # type: ignore[method-assign]
    return server


def _with_type_octets(raw: bytes) -> DHCPMessage:
    options = DHCPOptions()
    options._options[int(DHCPOptionCode.DHCP_MESSAGE_TYPE)] = bytearray(raw)
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray(b"\x01" + CHADDR)
    return build_request(None, options=options)


def _bootreply() -> DHCPMessage:
    return build_request(op=DHCPOpcode.BOOTREPLY)


def _unidentifiable() -> DHCPMessage:
    return build_request(chaddr=b"", hlen=0)


def _foreign_server() -> DHCPMessage:
    message = build_request(DHCPMessageType.DHCPDISCOVER)
    message.options[DHCPOptionCode.SERVER_IDENTIFIER] = ipaddress.IPv4Address(
        "198.51.100.77"
    )
    return message


def _init_reboot() -> DHCPMessage:
    message = build_request(DHCPMessageType.DHCPREQUEST)
    message.options[DHCPOptionCode.REQUESTED_IP] = ipaddress.IPv4Address("10.0.0.60")
    return message


def _renewing_unknown() -> DHCPMessage:
    return build_request(
        DHCPMessageType.DHCPREQUEST, ciaddr=ipaddress.IPv4Address("10.0.0.60")
    )


def _names_no_address() -> DHCPMessage:
    return build_request(DHCPMessageType.DHCPREQUEST)


def _inform_for_another_address() -> DHCPMessage:
    return build_request(
        DHCPMessageType.DHCPINFORM, ciaddr=ipaddress.IPv4Address("203.0.113.9")
    )


def _relayed_from_another_network() -> DHCPMessage:
    message = build_request(DHCPMessageType.DHCPDISCOVER)
    message.giaddr = ipaddress.IPv4Address("10.5.5.1")
    message.options[DHCPOptionCode.REQUESTED_IP] = ipaddress.IPv4Address("10.0.0.60")
    return message


def _off_subnet_discover() -> DHCPMessage:
    message = build_request(DHCPMessageType.DHCPDISCOVER)
    message.options[DHCPOptionCode.REQUESTED_IP] = ipaddress.IPv4Address("172.16.9.9")
    return message


SERVER_SITES: "list[tuple[str, ty.Callable[[], DHCPMessage], ty.Optional[str]]]" = [
    ("a BOOTREPLY", _bootreply, None),
    ("an unidentifiable client", _unidentifiable, "packets_dropped_no_client_id"),
    ("an unusable message type", lambda: _with_type_octets(b""), None),
    ("a message for another server", _foreign_server, "packets_dropped_other_server"),
    (
        "a message type not handled",
        lambda: build_request(DHCPMessageType.DHCPOFFER),
        None,
    ),
    ("an INIT-REBOOT from an unknown client", _init_reboot, None),
    ("a RENEWING request from an unknown client", _renewing_unknown, None),
    ("a REQUEST that names no address", _names_no_address, None),
    (
        "a DHCPINFORM for another address",
        _inform_for_another_address,
        "informs_ignored",
    ),
    (
        "a request relayed from another network",
        _relayed_from_another_network,
        "addresses_refused",
    ),
    (
        "a DHCPDECLINE",
        lambda: build_request(DHCPMessageType.DHCPDECLINE),
        "leases_declined",
    ),
    ("a refused address", _off_subnet_discover, "addresses_refused"),
]


@pytest.mark.parametrize(
    "build,counter", [s[1:] for s in SERVER_SITES], ids=[s[0] for s in SERVER_SITES]
)
def test_a_server_site_is_limited_and_counted(
    build: "ty.Callable[[], DHCPMessage]",
    counter: "ty.Optional[str]",
    caplog: pytest.LogCaptureFixture,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The host's own adapters are not under test: serve from 10.0.0.1/24.
    monkeypatch.setattr(
        "pydhcp.server._policy._servable_interface",
        lambda _ip: NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
    )
    server = _server(clock)
    message = build()
    _assert_bounded(
        caplog,
        clock,
        HANDLERS if counter != "addresses_refused" else "pydhcp.server._policy",
        lambda: server.handle(message, _context(clock)),
    )
    if counter is not None:
        assert getattr(server.metrics, counter) == INSIDE + 1


def test_a_release_naming_an_address_the_client_does_not_hold_is_limited_and_counted(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    server = _server(clock)
    release = build_request(
        DHCPMessageType.DHCPRELEASE, ciaddr=ipaddress.IPv4Address("10.0.0.99")
    )
    server.lease_backend.allocate(
        release.get_client_id(), ipaddress.IPv4Address("10.0.0.60"), 600, DHCPOptions()
    )
    _assert_bounded(
        caplog, clock, HANDLERS, lambda: server.handle(release, _context(clock))
    )
    assert server.metrics.releases_ignored == INSIDE + 1


def test_a_reply_that_leaves_out_the_relay_information_is_limited_and_counted(
    caplog: pytest.LogCaptureFixture,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pydhcp.server._policy._servable_interface",
        lambda _ip: NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
    )
    server = _server(clock)
    discover = build_request(DHCPMessageType.DHCPDISCOVER)
    discover.giaddr = ipaddress.IPv4Address("10.0.0.2")
    discover.options[DHCPOptionCode.REQUESTED_IP] = ipaddress.IPv4Address("10.0.0.60")
    discover.options[DHCPOptionCode.RELAY_AGENT_INFORMATION] = bytearray(
        bytes([1, 250]) + b"c" * 250 + bytes([2, 250]) + b"r" * 250
    )
    _assert_bounded(
        caplog,
        clock,
        "pydhcp.server._reply",
        lambda: server.handle(discover, _context(clock)),
    )
    assert server.metrics.relay_info_omitted == INSIDE + 1


def test_a_reply_that_does_not_decode_is_limited(
    caplog: pytest.LogCaptureFixture,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pydhcp.server._policy._servable_interface",
        lambda _ip: NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
    )
    server = _server(clock)
    server.lease_backend.allocate(
        build_request().get_client_id(),
        ipaddress.IPv4Address("10.0.0.60"),
        600,
        DHCPOptions(),
    )
    discover = build_request(DHCPMessageType.DHCPDISCOVER)

    def refuses(*_args: ty.Any, **_kwargs: ty.Any) -> DHCPMessage:
        raise ValueError("cannot decode")

    monkeypatch.setattr(DHCPMessage, "decode", classmethod(refuses))
    _assert_bounded(
        caplog,
        clock,
        "pydhcp.server._reply",
        lambda: server.handle(discover, _context(clock)),
    )


def test_what_the_server_prints_of_a_client_is_hex_and_short(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    server = _server(clock)
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPOFFER
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray(b"\x00" + b"\x1b[31m\n" * 40)
    message = build_request(None, options=options)
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        server.handle(message, _context(clock))
    text = _written(caplog, HANDLERS)[0].getMessage()
    assert "\x1b" not in text and "\n" not in text
    assert len(text) < 400


# -- the relay -----------------------------------------------------------------

RELAY = "pydhcp.relay._core"


def _relay(clock: Clock, **kwargs: ty.Any) -> DHCPRelay:
    relay = DHCPRelay(
        listen=("127.0.0.1", 6767), server_addresses=["192.0.2.1"], **kwargs
    )
    relay._read_clock = clock.instant  # type: ignore[method-assign]
    return relay


def _relay_request(giaddr: str = "0.0.0.0", with_info: bool = False) -> DHCPMessage:
    message = build_request(
        DHCPMessageType.DHCPDISCOVER, giaddr=ipaddress.IPv4Address(giaddr)
    )
    if with_info:
        message.options._options[int(DHCPOptionCode.RELAY_AGENT_INFORMATION)] = (
            bytearray(b"\x01\x02ab")
        )
    return message


def test_a_relay_request_with_untrusted_option_82_is_limited_and_counted(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    relay = _relay(clock)
    message = _relay_request(with_info=True)
    _assert_bounded(
        caplog, clock, RELAY, lambda: relay.handle(message, _context(clock))
    )
    assert relay.metrics.packets_dropped_untrusted == INSIDE + 1


def test_a_bootreply_from_an_unconfigured_source_is_limited_and_counted(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    relay = _relay(clock)
    message = build_request(DHCPMessageType.DHCPOFFER, op=DHCPOpcode.BOOTREPLY)
    _assert_bounded(
        caplog, clock, RELAY, lambda: relay.handle(message, _context(clock))
    )
    assert relay.metrics.packets_dropped_untrusted == INSIDE + 1


def test_an_unknown_op_is_limited(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    relay = _relay(clock)
    message = _relay_request()
    message.op = 7  # type: ignore[assignment]
    _assert_bounded(
        caplog, clock, RELAY, lambda: relay.handle(message, _context(clock))
    )


def test_a_reused_transaction_from_another_address_is_limited_and_counted(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    relay = _relay(clock)
    relay.PENDING_TTL_SECONDS = 10_000.0  # the entry outlives the interval
    message = _relay_request()
    relay.handle(message, _context(clock, client="10.0.0.50"))
    _assert_bounded(
        caplog,
        clock,
        RELAY,
        lambda: relay.handle(message, _context(clock, client="10.0.0.51")),
    )


def test_a_request_already_carrying_option_82_is_limited(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    relay = _relay(clock, insert_relay_agent_info=True, circuit_id=b"c")
    message = _relay_request(giaddr="10.0.0.1", with_info=True)
    _assert_bounded(
        caplog, clock, RELAY, lambda: relay.handle(message, _context(clock))
    )


# -- the client and the capture -------------------------------------------------


def test_an_offer_without_a_server_identifier_is_limited(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    client = DHCPClient(listen=("127.0.0.1", 0))
    offer = build_request(DHCPMessageType.DHCPOFFER, op=DHCPOpcode.BOOTREPLY)
    _assert_bounded(
        caplog,
        clock,
        "pydhcp.client._core",
        lambda: client._request_after(
            offer,
            CHADDR,
            client_identifier=None,
            parameter_request_list=None,
            broadcast=True,
            now=clock.t,
        ),
    )


def test_a_hook_that_fails_every_time_is_limited(
    caplog: pytest.LogCaptureFixture, clock: Clock
) -> None:
    def bad(_event: ty.Any) -> None:
        raise RuntimeError("boom")

    capture = DHCPCapture(listen=("127.0.0.1", 6767), hook=bad)
    message = build_request()
    _assert_bounded(
        caplog,
        clock,
        "pydhcp.capture._core",
        lambda: capture.handle(message, _context(clock)),
    )
    first = _written(caplog, "pydhcp.capture._core")[0]
    assert first.exc_info is not None
    assert not _written(caplog, "pydhcp.capture._core")[1].exc_info


def test_every_listener_owns_its_own_limiter() -> None:
    one = DHCPListener(listen=("127.0.0.1", 0))
    two = DHCPListener(listen=("127.0.0.1", 0))
    assert one._log_limit is not two._log_limit
