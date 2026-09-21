"""A truncated option must not raise out of a handler.

`DhcpOptions.decode` is deliberately lenient about malformed lengths: it logs
and carries on, because rejecting the whole packet would make one bad option
cost a client its lease. But it used to *keep* a trailing option that declared
a length and supplied nothing, storing an empty payload — so the option read as
present and then raised the moment anything decoded it. That moves the failure
out of the tolerant decoder and into whatever handler touches the value.

Found while auditing `tests-16`'s truncated-option coverage, not by any
recorded finding.
"""

import ipaddress
from unittest.mock import Mock

import pytest

from pydhcp import NetworkInterface, RequestContext
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.network import SocketAddress
from pydhcp.options import DhcpOptionCode
from pydhcp.options import type as T
from pydhcp.packet.message import DhcpMessage
from pydhcp.server import DhcpServer


def _packet_ending_in(tail: bytes) -> bytes:
    """A minimal BOOTREQUEST whose options field ends with `tail`."""
    header = bytearray(236)
    header[0] = 1  # op = BOOTREQUEST
    header[1] = 1  # htype = ethernet
    header[2] = 6  # hlen
    return bytes(header) + bytes([99, 130, 83, 99]) + bytes([53, 1, 3]) + tail


def _context() -> RequestContext:
    return RequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=bytes(6),
    )


def test_an_option_that_declares_a_length_and_supplies_nothing_is_dropped() -> None:
    """Two bytes on the wire: `50 04` and the packet ends."""
    msg = DhcpMessage.decode(memoryview(_packet_ending_in(bytes([50, 4]))))

    assert (
        msg.options.get(DhcpOptionCode.REQUESTED_IP, decode=False) is None
    ), "an empty payload was kept, so the option reads as present"
    # The decode that used to raise.
    assert msg.options.get(DhcpOptionCode.REQUESTED_IP, decode=T.IPv4Address) is None


def test_a_partially_truncated_option_keeps_what_arrived() -> None:
    """The half that must NOT change: real bytes are still worth keeping.

    Dropping every truncated option would throw away a value that a lenient
    decoder exists to preserve — only the empty case is unusable.
    """
    msg = DhcpMessage.decode(memoryview(_packet_ending_in(bytes([50, 4, 10, 0]))))

    raw = msg.options.get(DhcpOptionCode.REQUESTED_IP, decode=False)
    assert raw is not None and bytes(raw) == bytes([10, 0])


def test_the_server_does_not_raise_on_a_truncated_trailing_option() -> None:
    """Remotely reachable: any sender could make `handle()` raise.

    The listener's per-packet guard caught it, but an attacker-driven traceback
    on every packet is the same trap this codebase already closed for the
    per-packet unknown-htype warning.
    """
    msg = DhcpMessage.decode(memoryview(_packet_ending_in(bytes([50, 4]))))
    server = DhcpServer(lease_backend=InMemoryLeaseBackend())

    server.handle(msg, _context())  # must not raise


@pytest.mark.parametrize(
    "tail",
    [
        bytes([50, 4]),
        bytes([1, 4]),
        bytes([54, 4]),
        bytes([61, 7]),
    ],
)
def test_no_truncated_trailing_option_escapes_the_handler(tail) -> None:
    msg = DhcpMessage.decode(memoryview(_packet_ending_in(tail)))
    DhcpServer(lease_backend=InMemoryLeaseBackend()).handle(msg, _context())
