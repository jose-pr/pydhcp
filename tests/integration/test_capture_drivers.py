"""One capture core under two sibling drivers.

`DHCPCapture` and `AsyncDHCPCapture` compose the same private core over their
own listener; neither is a subclass of the other, and a subclass of either that
overrides `handle` is the method called, on the handler thread.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import threading
import typing as _ty
from unittest.mock import Mock

import pytest

from helpers import CHADDR, build_request
from driving import WAIT_SECONDS, driver_params, serve, wait_for
from pydhcp import (
    AsyncDHCPCapture,
    CaptureEvent,
    DHCPCapture,
    DHCPMessage,
    DHCPRequestContext,
    SocketAddress,
)
from pydhcp.capture._core import _CaptureCore
from pydhcp.listener import AsyncDHCPListener, DHCPListener
from pydhcp.packet import DHCPMessageType

IPv4 = ipaddress.IPv4Address


def test_the_drivers_are_siblings_over_one_core() -> None:
    assert issubclass(DHCPCapture, _CaptureCore)
    assert issubclass(AsyncDHCPCapture, _CaptureCore)
    assert not issubclass(AsyncDHCPCapture, DHCPCapture)
    assert not issubclass(DHCPCapture, AsyncDHCPCapture)
    assert not issubclass(_CaptureCore, (DHCPListener, AsyncDHCPListener))
    assert issubclass(DHCPCapture, DHCPListener)
    assert issubclass(AsyncDHCPCapture, AsyncDHCPListener)


def test_an_async_capture_has_no_synchronous_lifecycle() -> None:
    capture = AsyncDHCPCapture(listen=("127.0.0.1", 0))
    for name in ("__enter__", "__exit__", "close"):
        assert not hasattr(capture, name), name
    assert not isinstance(capture, DHCPCapture)


class _Recording:
    handled: "list[str]"

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        self.handled.append(threading.current_thread().name)
        super().handle(msg, context)  # type: ignore[misc]


class _RecordingSync(_Recording, DHCPCapture):
    pass


class _RecordingAsync(_Recording, AsyncDHCPCapture):
    pass


@pytest.mark.parametrize(
    "capture_class, loop_type", driver_params(_RecordingSync, _RecordingAsync)
)
def test_an_overridden_handle_is_called_and_the_sink_gets_the_event(
    capture_class: type, loop_type: _ty.Optional[type]
) -> None:
    events: "list[CaptureEvent]" = []
    sink_threads: "list[str]" = []

    def sink(event: CaptureEvent) -> None:
        events.append(event)
        sink_threads.append(threading.current_thread().name)

    capture = capture_class(
        listen=("127.0.0.1", 0), packet_filter="msg_type=DHCPDISCOVER", sink=sink
    )
    capture.handled = []

    def exercise(port: int) -> None:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for kind in (DHCPMessageType.DHCPDISCOVER, DHCPMessageType.DHCPREQUEST):
                data = bytes(build_request(kind).encode())
                client.sendto(data, ("127.0.0.1", port))
            wait_for(lambda: len(capture.handled) == 2, "both datagrams to be handled")
        finally:
            client.close()

    serve(capture, exercise, loop_type)
    assert capture.accepted_count == 1
    (event,) = events
    assert event.message_type == "DHCPDISCOVER"
    assert event.captured_at.tzinfo is not None
    assert len(set(capture.handled)) == 1
    assert sink_threads == capture.handled[:1]
    assert capture.handled[0] != threading.current_thread().name


@pytest.mark.parametrize("capture_class", [DHCPCapture, AsyncDHCPCapture])
def test_the_events_time_is_the_time_stamped_on_the_context(
    capture_class: type,
) -> None:
    stamp = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    events: "list[CaptureEvent]" = []
    capture = capture_class(listen=("127.0.0.1", 0), sink=events.append)
    context = DHCPRequestContext(
        transport=Mock(),
        interface=Mock(ip=IPv4("127.0.0.1")),
        client=SocketAddress(IPv4("127.0.0.1"), 68),
        client_mac=CHADDR,
        received_at=stamp,
        received_monotonic=1.0,
    )
    capture.handle(build_request(DHCPMessageType.DHCPDISCOVER), context)
    assert [e.captured_at for e in events] == [stamp]
