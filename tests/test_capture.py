from __future__ import annotations

import ipaddress
from datetime import datetime, timezone, timedelta

import pytest

from pydhcp import CaptureEvent, DhcpCapture, DhcpMessage, DhcpOptions, NetworkInterface, RequestContext
from pydhcp.capture import compile_capture_filter
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4, SocketAddress


CHADDR = b"\x00\x11\x22\x33\x44\x55"


class _Transport:
    def send(self, data, dest, port, client_mac):
        return len(data)


def _message(message_type: DhcpMessageType = DhcpMessageType.DHCPDISCOVER) -> DhcpMessage:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = message_type
    options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray(b"\x01" + CHADDR)
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x1234ABCD,
        secs=timedelta(seconds=0),
        flags=Flags.BROADCAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=CHADDR,
        sname="",
        file="",
        options=options,
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
    ["msg_type", "=DHCPDISCOVER", "foo=bar", "option.NOT_A_REAL_OPTION=1", "msg_type=DHCPDISCOVER or xid=1"],
)
def test_compile_capture_filter_rejects_malformed_expressions(filter_text: str) -> None:
    with pytest.raises(ValueError):
        compile_capture_filter(filter_text)


def test_capture_event_formats_safe_filenames() -> None:
    event = _event()

    assert event.message_type == "DHCPDISCOVER"
    assert event.source == SocketAddress("192.0.2.55", 68)
    assert event.destination == SocketAddress("192.0.2.1", 0)
    assert event.format_filename("out/{client_id}/{timestamp}_{msg_type}_{xid}.{format}", "json") == (
        "out/01_00_11_22_33_44_55/20260714T123015.000000Z_DHCPDISCOVER_1234ABCD.json"
    )


def test_dhcp_capture_invokes_sink_and_hook_for_accepted_packet() -> None:
    seen = []
    hooked = []
    capture = DhcpCapture(
        listen=("127.0.0.1", 6767),
        packet_filter="msg_type=DHCPDISCOVER",
        sink=seen.append,
        hook=hooked.append,
    )

    capture.handle(_message(), _context())

    assert capture.accepted_count == 1
    assert len(seen) == 1
    assert hooked == seen


def test_dhcp_capture_logs_hook_errors_without_fail_fast() -> None:
    seen = []

    def bad_hook(event):
        seen.append(event)
        raise RuntimeError("boom")

    capture = DhcpCapture(listen=("127.0.0.1", 6767), hook=bad_hook)

    capture.handle(_message(), _context())

    assert capture.accepted_count == 1
    assert len(seen) == 1


def test_dhcp_capture_hook_fail_fast_raises() -> None:
    def bad_hook(event):
        raise RuntimeError("boom")

    capture = DhcpCapture(listen=("127.0.0.1", 6767), hook=bad_hook, hook_fail_fast=True)

    with pytest.raises(RuntimeError):
        capture.handle(_message(), _context())
