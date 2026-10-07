"""The octets of the datagram a capture heard, as the client sent them.

`encode` pads a message to 300 octets and a decode drops what follows the end
option, so a message put back together is not, in general, the packet that
arrived. The listener keeps the datagram on the request context, and a capture
file is written from it.
"""

from __future__ import annotations

import socket
import typing as _ty

import pytest

from helpers import build_request
from driving import driver_params, serve, wait_for
from capture_input import short_datagram
from pydhcp import AsyncDHCPCapture, CaptureEvent, DHCPCapture
from pydhcp.packet import DHCPMessageType


def test_an_event_built_by_hand_has_no_payload() -> None:
    from hook_programs import capture_event

    event = capture_event()
    assert event.context.payload is None and event.payload is None


@pytest.mark.parametrize(
    "capture_class, loop_type", driver_params(DHCPCapture, AsyncDHCPCapture)
)
def test_an_event_holds_the_octets_the_client_sent(
    capture_class: type, loop_type: _ty.Optional[type]
) -> None:
    sent = [
        short_datagram(),
        bytes(build_request(DHCPMessageType.DHCPREQUEST).encode()),
    ]
    assert len(sent[0]) < 300 <= len(sent[1])
    events: "list[CaptureEvent]" = []
    capture = capture_class(listen=("127.0.0.1", 0), sink=events.append)

    def exercise(port: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for data in sent:
                client.sendto(data, ("127.0.0.1", port))
        wait_for(lambda: len(events) == 2, "both datagrams to be captured")

    serve(capture, exercise, loop_type)

    assert [event.payload for event in events] == sent
    for event in events:
        assert type(event.payload) is bytes
        assert event.context.payload is event.payload
