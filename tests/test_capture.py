from __future__ import annotations

import ipaddress
import logging
import socket
from datetime import datetime, timezone

import pktcap
import pytest

from pydhcp import (
    AsyncDHCPCapture,
    CaptureEvent,
    DHCPCapture,
    DHCPMessage,
    DHCPOptions,
    NetworkInterface,
    DHCPRequestContext,
)
from pydhcp.capture import compile_capture_filter
from pydhcp.packet import DHCPMessageType, DHCPFlags
from pydhcp.options import DHCPOptionCode
from ipaddress import IPv4Address as IPv4
from pydhcp import SocketAddress
from conftest import build_request

CHADDR = b"\x00\x11\x22\x33\x44\x55"
# A hardware address with hex letters in it, so a case-insensitive comparison is
# actually exercised; this is the address `pydhcp interfaces` was measured
# printing as `68-F7-D8-E5-1E-83`.
ALPHA_CHADDR = bytes.fromhex("68f7d8e51e83")


@pytest.fixture(params=[DHCPCapture, AsyncDHCPCapture], ids=["sync", "async"])
def capture_class(request):
    """Every capture-policy test runs against both captures.

    Parametrized rather than duplicated: `AsyncDHCPCapture` takes the same
    arguments minus `poll_interval`, and `handle()` is ordinary synchronous
    code on both -- on the async listener it runs on the handler worker thread,
    not on the event loop, so calling it directly here is the same call the
    listener makes.
    """
    return request.param


class _Transport:
    def send(self, data, dst, port, client_mac):
        return len(data)


def _message(
    message_type: DHCPMessageType = DHCPMessageType.DHCPDISCOVER,
    chaddr: bytes = CHADDR,
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = message_type
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray(b"\x01" + chaddr)
    return build_request(
        options=options, xid=0x1234ABCD, flags=DHCPFlags.BROADCAST, chaddr=chaddr
    )


def _context() -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=_Transport(),
        interface=NetworkInterface("eth-test", ipaddress.IPv4Interface("192.0.2.1/24")),
        client=SocketAddress("192.0.2.55", 68),
        client_mac=CHADDR,
        local_ip=IPv4("192.0.2.1"),
    )


def _event(message: DHCPMessage | None = None) -> CaptureEvent:
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


# -- what a value may be: one that no packet could match is refused at compile time ----


@pytest.mark.parametrize(
    "filter_text",
    [
        "msg_type=DISCOVER",  # the name is DHCPDISCOVER
        "msg_type=256",
        "msg_type=0x100",
        "msg_type=TYPE_999",
        "op=REQUEST",  # the names are BOOTREQUEST and BOOTREPLY
        "op=300",
        "client_id=not-hex",
        "client_id=01:zz",
        "client_id=abc",  # an odd number of digits is no octets
        "client_id=" + "ab" * 256,  # an option holds 255 octets at most
        "chaddr=zz:zz",
        "chaddr=0:",
        "chaddr=" + "ab" * 17,  # `hlen` is 16 at most
        "xid=0x100000000",
        "xid=-1",
        "src_port=70000",
        "dst_port=-1",
        "option.999=x",
        "option.0=x",
        "option.255=x",
        "msg_type=,",
    ],
)
def test_a_value_no_packet_could_match_is_refused_when_compiled(
    filter_text: str,
) -> None:
    with pytest.raises(pktcap.CaptureFilterError):
        compile_capture_filter(filter_text)


def test_the_refusal_of_a_name_lists_the_names() -> None:
    with pytest.raises(ValueError) as refused:
        compile_capture_filter("msg_type=DISCOVER")
    assert "DHCPDISCOVER" in str(refused.value) and "DHCPNAK" in str(refused.value)
    with pytest.raises(ValueError, match="BOOTREPLY"):
        compile_capture_filter("op=REQUEST")


@pytest.mark.parametrize(
    "filter_text",
    [
        "msg_type=dhcpdiscover",
        "msg_type=DhcpDiscover",
        "msg_type=1",
        "msg_type=0x01",
        "op=bootrequest",
        "op=1",
        "op=0x1",
    ],
)
def test_a_name_in_any_case_or_a_number_selects_the_message(filter_text: str) -> None:
    assert compile_capture_filter(filter_text)(_event())


@pytest.mark.parametrize(
    "filter_text", ["msg_type=2", "msg_type=dhcpoffer", "op=2", "op=bootreply"]
)
def test_a_name_or_number_of_another_value_selects_nothing(filter_text: str) -> None:
    assert not compile_capture_filter(filter_text)(_event())


def test_an_unnamed_message_type_is_selected_by_its_number_or_its_label() -> None:
    event = _event(_message(DHCPMessageType(99)))

    assert compile_capture_filter("msg_type=99")(event)
    assert compile_capture_filter("msg_type=TYPE_99")(event)
    assert not compile_capture_filter("msg_type=TYPE_98")(event)
    assert not compile_capture_filter("msg_type=UNKNOWN")(event)


def test_a_message_with_no_type_is_selected_as_unknown_and_by_no_number() -> None:
    event = _event(build_request(message_type=None))

    assert compile_capture_filter("msg_type=UNKNOWN")(event)
    assert compile_capture_filter("msg_type!=DHCPDISCOVER")(event)
    assert not compile_capture_filter("msg_type=DHCPDISCOVER")(event)
    assert not compile_capture_filter("msg_type=0")(event)


def test_a_clause_negated_selects_everything_the_clause_does_not() -> None:
    discover, offer = _event(), _event(_message(DHCPMessageType.DHCPOFFER))
    not_offer = compile_capture_filter("msg_type!=DHCPOFFER")

    assert not_offer(discover) and not not_offer(offer)
    both = compile_capture_filter("msg_type!=DHCPOFFER and src=192.0.2.55")
    assert both(discover) and not both(offer)


def test_a_comma_means_any_of_for_every_key_but_an_option() -> None:
    discover, offer = _event(), _event(_message(DHCPMessageType.DHCPOFFER))
    for text in (
        "msg_type=DHCPDISCOVER,DHCPREQUEST",
        "msg_type=dhcpack, 1",
        "op=BOOTREPLY,BOOTREQUEST",
        "xid=1,0x1234ABCD",
        "client_id=ff:ff,01:00:11:22:33:44:55",
        "chaddr=aa:bb:cc:dd:ee:ff,00-11-22-33-44-55",
        "src=192.0.2.1,192.0.2.55",
        "src_port=67,68",
        "dst=192.0.2.9,192.0.2.1",
        "interface=eth0,eth-test",
    ):
        assert compile_capture_filter(text)(discover), text
    assert not compile_capture_filter("msg_type=DHCPACK,DHCPREQUEST")(discover)
    assert compile_capture_filter("msg_type=DHCPDISCOVER,DHCPOFFER")(offer)
    assert not compile_capture_filter("src=192.0.2.1,192.0.2.2")(discover)
    assert not compile_capture_filter("msg_type!=DHCPDISCOVER,DHCPOFFER")(offer)


def test_the_text_of_an_option_is_compared_whole_with_its_commas() -> None:
    message = _message()
    message.options[DHCPOptionCode.HOSTNAME] = "a,b"
    event = _event(message)

    assert compile_capture_filter("option.HOSTNAME=a,b")(event)
    assert compile_capture_filter("option.12=a,b")(event)
    assert not compile_capture_filter("option.HOSTNAME=a")(event)


@pytest.mark.parametrize(
    "filter_text",
    ["msg_type=DHCPDISCOVER and", "option.12=x and", "and", "src=192.0.2.55 and "],
)
def test_a_filter_ending_in_and_is_refused(filter_text: str) -> None:
    """`option.12=x and` used to compile, with the word `and` as part of the value."""
    with pytest.raises(pktcap.CaptureFilterError):
        compile_capture_filter(filter_text)


def test_a_filter_names_the_clause_it_refuses() -> None:
    with pytest.raises(pktcap.CaptureFilterError, match="msg_type=DISCOVER"):
        compile_capture_filter("src=192.0.2.55 and msg_type=DISCOVER")


def test_capture_event_reports_the_message_and_where_it_went() -> None:
    event = _event()

    assert event.message_type == "DHCPDISCOVER"
    assert event.client_id == "01:00:11:22:33:44:55"
    assert event.xid == "1234ABCD"
    assert event.source == SocketAddress("192.0.2.55", 68)
    assert event.destination == SocketAddress("192.0.2.1", 0)


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


def test_dhcp_capture_logs_hook_errors_without_fail_fast(capture_class, caplog) -> None:
    """ "logs hook errors" was in the name and nothing read the log.

    A hook that fails silently is the failure mode the try/except creates: the
    capture carries on and the operator has no way to know their hook never
    ran. The traceback matters too -- `LOGGER.exception`, not `LOGGER.error` --
    because the hook is the user's own code and the line number is the only
    thing that locates it.
    """
    seen = []

    def bad_hook(event):
        seen.append(event)
        raise RuntimeError("boom")

    capture = capture_class(listen=("127.0.0.1", 6767), hook=bad_hook)

    with caplog.at_level(logging.ERROR, logger="pydhcp.capture._core"):
        capture.handle(_message(), _context())

    assert capture.accepted_count == 1
    assert len(seen) == 1
    # Not fail-fast: the capture is still usable and says so.
    assert capture.hook_error is None

    records = [r for r in caplog.records if r.name == "pydhcp.capture._core"]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].getMessage() == "Capture hook failed"
    assert records[0].exc_info is not None
    assert isinstance(records[0].exc_info[1], RuntimeError)
    assert "boom" in caplog.text
    assert "bad_hook" in caplog.text  # the traceback, not just the message


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

    The two listeners shut down by different mechanisms (a wake socket versus
    an event on the loop), so what is asserted here is the part that has to be
    the same on both: the real `shutdown()` is called and the reason is recorded.
    `tests/test_async.py` drives the async mechanism itself, on a live loop.
    """

    def bad_hook(event):
        raise RuntimeError("boom")

    class RecordingCapture(capture_class):  # type: ignore[valid-type,misc]
        stop_calls = 0

        def shutdown(self):
            type(self).stop_calls += 1
            return super().shutdown()

    capture = RecordingCapture(
        listen=("127.0.0.1", 6767), hook=bad_hook, hook_fail_fast=True
    )

    with pytest.raises(RuntimeError):
        capture.handle(_message(), _context())

    # the loop is asked to stop, and the reason is recorded so a caller can tell
    # this from an ordinary shutdown
    assert isinstance(capture.hook_error, RuntimeError)
    assert RecordingCapture.stop_calls == 1


def test_dhcp_capture_sync_fail_fast_ends_the_receive_loop() -> None:
    """The sync mechanism specifically: `shutdown()` wakes the loop that `start()`
    runs, so the capture ends on its own after the failing hook."""

    def bad_hook(event):
        raise RuntimeError("boom")

    capture = DHCPCapture(listen=("127.0.0.1", 0), hook=bad_hook, hook_fail_fast=True)
    capture.start()
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        address = capture.bound_addresses[0]
        sender.sendto(_message().encode(), (str(address.ip), address.port))
        assert capture.wait_closed(5.0), "the capture kept receiving after the failure"
        assert isinstance(capture.hook_error, RuntimeError)
    finally:
        sender.close()
        capture.close()


def test_dhcp_capture_hook_error_stays_none_without_fail_fast(capture_class) -> None:
    def bad_hook(event):
        raise RuntimeError("boom")

    capture = capture_class(listen=("127.0.0.1", 6767), hook=bad_hook)

    capture.handle(_message(), _context())

    assert capture.hook_error is None


def _event_sent_to(destination: str | None) -> CaptureEvent:
    context = _context()._replace(
        destination=IPv4(destination) if destination else None,
        is_unicast=None if destination is None else destination == "192.0.2.1",
    )
    return CaptureEvent(
        message=_message(),
        context=context,
        captured_at=datetime(2026, 7, 14, 12, 30, 15, tzinfo=timezone.utc),
    )


def test_a_capture_event_reports_where_the_datagram_was_sent() -> None:
    """A broadcast is addressed to the broadcast, not to the interface that heard
    it; the `dst` filter selects on it."""
    broadcast = _event_sent_to("255.255.255.255")
    unicast = _event_sent_to("192.0.2.1")

    assert broadcast.destination.ip == IPv4("255.255.255.255")
    assert unicast.destination.ip == IPv4("192.0.2.1")
    assert compile_capture_filter("dst=255.255.255.255")(broadcast)
    assert not compile_capture_filter("dst=255.255.255.255")(unicast)
    assert not compile_capture_filter("dst=192.0.2.1")(broadcast)


def test_a_capture_event_without_packet_info_reports_the_reply_address() -> None:
    assert _event_sent_to(None).destination.ip == IPv4("192.0.2.1")
