from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import pytest

from pydhcp import (
    AsyncDhcpCapture,
    CaptureEvent,
    DhcpCapture,
    DhcpMessage,
    DhcpOptions,
    NetworkInterface,
    RequestContext,
)
from pydhcp.capture import compile_capture_filter
from pydhcp.packet import DhcpMessageType, Flags
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4, SocketAddress
from conftest import build_request

CHADDR = b"\x00\x11\x22\x33\x44\x55"
# A hardware address with hex letters in it, so a case-insensitive comparison is
# actually exercised; this is the address `pydhcp interfaces` was measured
# printing as `68-F7-D8-E5-1E-83`.
ALPHA_CHADDR = bytes.fromhex("68f7d8e51e83")


@pytest.fixture(params=[DhcpCapture, AsyncDhcpCapture], ids=["sync", "async"])
def capture_class(request):
    """Every capture-policy test runs against both captures.

    Parametrized rather than duplicated: `AsyncDhcpCapture` takes the same
    arguments minus `select_timeout`, and `handle()` is ordinary synchronous
    code on both -- on the async listener it runs on the handler worker thread,
    not on the event loop, so calling it directly here is the same call the
    listener makes.
    """
    return request.param


class _Transport:
    def send(self, data, dest, port, client_mac):
        return len(data)


def _message(
    message_type: DhcpMessageType = DhcpMessageType.DHCPDISCOVER,
    chaddr: bytes = CHADDR,
) -> DhcpMessage:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = message_type
    options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray(b"\x01" + chaddr)
    return build_request(
        options=options, xid=0x1234ABCD, flags=Flags.BROADCAST, chaddr=chaddr
    )


def _context() -> RequestContext:
    return RequestContext(
        transport=_Transport(),
        interface=NetworkInterface("eth-test", ipaddress.IPv4Interface("192.0.2.1/24")),
        client=SocketAddress("192.0.2.55", 68),
        client_mac=CHADDR,
        local_ip=IPv4("192.0.2.1"),
    )


def _event(message: DhcpMessage | None = None) -> CaptureEvent:
    return CaptureEvent(
        message=message or _message(),
        context=_context(),
        captured_at=datetime(2026, 7, 14, 12, 30, 15, tzinfo=timezone.utc),
    )


@pytest.mark.parametrize(
    "filter_text",
    [
        None,
        "",
        "op=BOOTREQUEST",
        "msg_type=DHCPDISCOVER and src_port=68",
        "xid=0x1234ABCD",
        "client_id=01:00:11:22:33:44:55",
        "chaddr=00:11:22:33:44:55",
        "src=192.0.2.55 and dst=192.0.2.1",
        "interface=eth-test",
        "option.DHCP_MESSAGE_TYPE=DHCPDISCOVER",
        "option.53=DHCPDISCOVER",
    ],
)
def test_compile_capture_filter_accepts_supported_expressions(filter_text) -> None:
    assert compile_capture_filter(filter_text)(_event())


@pytest.mark.parametrize(
    "filter_text",
    [
        "msg_type=DHCPREQUEST",
        "src_port=67",
        "option.DHCP_MESSAGE_TYPE=DHCPREQUEST",
    ],
)
def test_compile_capture_filter_rejects_non_matching_events(filter_text: str) -> None:
    assert not compile_capture_filter(filter_text)(_event())


@pytest.mark.parametrize(
    "filter_text",
    [
        "msg_type",
        "=DHCPDISCOVER",
        "foo=bar",
        "option.NOT_A_REAL_OPTION=1",
        "msg_type=DHCPDISCOVER or xid=1",
    ],
)
def test_compile_capture_filter_rejects_malformed_expressions(filter_text: str) -> None:
    with pytest.raises(ValueError):
        compile_capture_filter(filter_text)


@pytest.mark.parametrize("joiner", ["and", "AND", "And"])
def test_compile_capture_filter_joins_clauses_in_any_case(joiner: str) -> None:
    """An uppercase `AND` used to be swallowed into the preceding value.

    Measured before this: `src=192.0.2.55 AND msg_type=DHCPDISCOVER` compiled to
    a single `src=` clause whose value was the whole remainder, so the capture
    matched nothing and exited 0 -- the same output as a quiet segment.
    """
    event = _event()

    assert compile_capture_filter(f"src=192.0.2.55 {joiner} msg_type=DHCPDISCOVER")(
        event
    )
    # the second clause is really evaluated, not just parsed away
    assert not compile_capture_filter(f"src=192.0.2.55 {joiner} msg_type=DHCPREQUEST")(
        event
    )


@pytest.mark.parametrize("joiner", ["or", "OR", "Or"])
def test_compile_capture_filter_rejects_or_in_any_case(joiner: str) -> None:
    with pytest.raises(ValueError, match="'and' only"):
        compile_capture_filter(f"msg_type=DHCPDISCOVER {joiner} msg_type=DHCPOFFER")


@pytest.mark.parametrize(
    "filter_text",
    [
        "xid=zz",
        "xid=0xnope",
        "src_port=abc",
        "dst_port=six",
        "src=not.an.ip",
        "dst=192.0.2.300",
    ],
)
def test_compile_capture_filter_rejects_bad_values_at_compile_time(
    filter_text: str,
) -> None:
    """A bad value is one startup error, not one per packet.

    These used to compile and then raise from inside the listener's per-packet
    handler for every packet on the segment (or, for `src`/`dst`, to silently
    match nothing).
    """
    with pytest.raises(ValueError):
        compile_capture_filter(filter_text)


@pytest.mark.parametrize(
    "filter_text",
    [
        f"xid={0x1234ABCD}",
        "xid=0x1234abcd",
        "src_port=68",
        "src=192.0.2.55",
        "dst=192.0.2.1",
    ],
)
def test_compile_capture_filter_accepts_well_formed_values(filter_text: str) -> None:
    assert compile_capture_filter(filter_text)(_event())


@pytest.mark.parametrize(
    "value",
    [
        "68-F7-D8-E5-1E-83",  # exactly what `pydhcp interfaces` prints
        "68:F7:D8:E5:1E:83",
        "68:f7:d8:e5:1e:83",
        "68f7.d8e5.1e83",
        "68f7d8e51e83",
    ],
)
def test_chaddr_filter_ignores_separator_and_case(value: str) -> None:
    """Copy-pasting a MAC out of `pydhcp interfaces` has to work.

    The comparison was colon-form-only, which is the one form that command does
    not print -- so the pasted filter matched nothing, silently.
    """
    event = _event(_message(chaddr=ALPHA_CHADDR))

    assert compile_capture_filter(f"chaddr={value}")(event)


@pytest.mark.parametrize(
    "value",
    [
        "01-68-F7-D8-E5-1E-83",
        "01:68:F7:D8:E5:1E:83",
        "01:68:f7:d8:e5:1e:83",
        "0168f7d8e51e83",
    ],
)
def test_client_id_filter_ignores_separator_and_case(value: str) -> None:
    event = _event(_message(chaddr=ALPHA_CHADDR))

    assert compile_capture_filter(f"client_id={value}")(event)


def test_hardware_address_filters_still_reject_other_addresses() -> None:
    event = _event(_message(chaddr=ALPHA_CHADDR))

    assert not compile_capture_filter("chaddr=68-F7-D8-E5-1E-84")(event)
    assert not compile_capture_filter("client_id=01-68-F7-D8-E5-1E-84")(event)


def test_capture_event_formats_safe_filenames() -> None:
    event = _event()

    assert event.message_type == "DHCPDISCOVER"
    assert event.source == SocketAddress("192.0.2.55", 68)
    assert event.destination == SocketAddress("192.0.2.1", 0)
    assert event.format_filename(
        "out/{client_id}/{timestamp}_{msg_type}_{xid}.{format}", "json"
    ) == ("out/01_00_11_22_33_44_55/20260714T123015.000000Z_DHCPDISCOVER_1234ABCD.json")


def test_dhcp_capture_invokes_sink_and_hook_for_accepted_packet(capture_class) -> None:
    seen = []
    hooked = []
    capture = capture_class(
        listen=("127.0.0.1", 6767),
        packet_filter="msg_type=DHCPDISCOVER",
        sink=seen.append,
        hook=hooked.append,
    )

    capture.handle(_message(), _context())

    assert capture.accepted_count == 1
    assert len(seen) == 1
    assert hooked == seen


def test_dhcp_capture_logs_hook_errors_without_fail_fast(capture_class) -> None:
    seen = []

    def bad_hook(event):
        seen.append(event)
        raise RuntimeError("boom")

    capture = capture_class(listen=("127.0.0.1", 6767), hook=bad_hook)

    capture.handle(_message(), _context())

    assert capture.accepted_count == 1
    assert len(seen) == 1


def test_dhcp_capture_hook_fail_fast_raises(capture_class) -> None:
    def bad_hook(event):
        raise RuntimeError("boom")

    capture = capture_class(
        listen=("127.0.0.1", 6767), hook=bad_hook, hook_fail_fast=True
    )

    with pytest.raises(RuntimeError):
        capture.handle(_message(), _context())


def test_dhcp_capture_hook_fail_fast_stops_the_capture(capture_class) -> None:
    """Re-raising alone changed nothing.

    handle() runs inside the listener's per-packet try, which logs and carries
    on, so a capture with --hook-fail-fast kept running through every packet and
    still exited 0. Measured on loopback before this: the hook fired for all
    three packets and the listener thread was still alive.

    The two listeners stop by different mechanisms (a cancellation token versus
    closing the endpoints), so what is asserted here is the part that has to be
    the same on both: the real `stop()` is called and the reason is recorded.
    `tests/test_async.py` drives the async mechanism itself, on a live loop.
    """

    def bad_hook(event):
        raise RuntimeError("boom")

    class RecordingCapture(capture_class):  # type: ignore[valid-type,misc]
        stop_calls = 0

        def stop(self):
            type(self).stop_calls += 1
            return super().stop()

    capture = RecordingCapture(
        listen=("127.0.0.1", 6767), hook=bad_hook, hook_fail_fast=True
    )

    with pytest.raises(RuntimeError):
        capture.handle(_message(), _context())

    # the loop is asked to stop, and the reason is recorded so a caller can tell
    # this from an ordinary shutdown
    assert isinstance(capture.hook_error, RuntimeError)
    assert RecordingCapture.stop_calls == 1


def test_dhcp_capture_sync_fail_fast_sets_the_cancellation_token() -> None:
    """The sync mechanism specifically: `stop()` sets the token `listen()` polls."""

    def bad_hook(event):
        raise RuntimeError("boom")

    import threading

    capture = DhcpCapture(
        listen=("127.0.0.1", 6767), hook=bad_hook, hook_fail_fast=True
    )
    # listen() creates this; the token is what stop() acts on, so the loop has to
    # look like it is running for the test to say anything about stopping it.
    capture._cancellation_token = threading.Event()

    with pytest.raises(RuntimeError):
        capture.handle(_message(), _context())

    assert capture._cancellation_token.is_set()


def test_dhcp_capture_hook_error_stays_none_without_fail_fast(capture_class) -> None:
    def bad_hook(event):
        raise RuntimeError("boom")

    capture = capture_class(listen=("127.0.0.1", 6767), hook=bad_hook)

    capture.handle(_message(), _context())

    assert capture.hook_error is None
