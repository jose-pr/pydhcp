"""The reply header is the server's, not the client's (`server-19`).

`_create_response` clones the request, so every field it does not overwrite is
whatever the client sent. RFC 2131 Table 3 says what each reply carries, and it
is not symmetric -- which is the whole difficulty: two of the fields that look
like leaks are required echoes, and clearing them would break relayed clients.
"""

from datetime import timedelta

import pytest

from pydhcp import DhcpMessage, DhcpOptions
from pydhcp.lease import DhcpLease, InMemoryLeaseBackend
from pydhcp.network import IPv4
from pydhcp.options import DhcpOptionCode
from pydhcp.packet import DhcpMessageType, OpCode
from pydhcp.server import DhcpServer
from conftest import build_request

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
SERVER_ID = IPv4("10.0.0.1")


def _request() -> DhcpMessage:
    """A request whose sender filled in fields that are not its to choose."""
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    return build_request(
        options=options,
        hops=3,
        secs=timedelta(seconds=41),
        ciaddr=IPv4("10.9.9.9"),
        yiaddr=IPv4("10.8.8.8"),
        siaddr=IPv4("10.7.7.7"),
        giaddr=IPv4("10.6.6.6"),
        sname="attacker-tftp.example",
        file="evil/boot.img",
    )


@pytest.fixture
def server() -> DhcpServer:
    return DhcpServer(lease_backend=InMemoryLeaseBackend())


@pytest.fixture
def lease() -> DhcpLease:
    return DhcpLease(IPv4("10.0.0.50"), float("inf"), DhcpOptions())


@pytest.mark.parametrize(
    "resp_ty",
    [DhcpMessageType.DHCPOFFER, DhcpMessageType.DHCPACK, DhcpMessageType.DHCPNAK],
)
def test_next_server_fields_are_never_the_clients(server, lease, resp_ty) -> None:
    """siaddr/sname/file name the next bootstrap server -- the server's choice.

    Echoing them let a client nominate its own next-server and boot file and
    receive them back stamped with the server identifier, which is the pair a
    PXE client acts on.
    """
    resp = server._create_response(_request(), lease, SERVER_ID, resp_ty)
    assert resp.siaddr == IPv4("0.0.0.0")
    assert resp.sname == ""
    assert resp.file == ""


def test_offer_carries_no_ciaddr(server, lease) -> None:
    """Table 3: ciaddr is 0 in a DHCPOFFER."""
    resp = server._create_response(
        _request(), lease, SERVER_ID, DhcpMessageType.DHCPOFFER
    )
    assert resp.ciaddr == IPv4("0.0.0.0")


def test_ack_still_echoes_ciaddr(server, lease) -> None:
    """Table 3: in a DHCPACK, ciaddr IS the ciaddr from the DHCPREQUEST.

    The counterpart to the OFFER rule above, and the reason that fix must not
    be widened to cover both: a client renewing from BOUND puts its address in
    ciaddr and expects it back.
    """
    resp = server._create_response(
        _request(), lease, SERVER_ID, DhcpMessageType.DHCPACK
    )
    assert resp.ciaddr == IPv4("10.9.9.9")


@pytest.mark.parametrize(
    "resp_ty",
    [DhcpMessageType.DHCPOFFER, DhcpMessageType.DHCPACK, DhcpMessageType.DHCPNAK],
)
def test_giaddr_is_echoed_so_a_relay_can_route_the_reply(
    server, lease, resp_ty
) -> None:
    """Not a leak: Table 3 requires the echo.

    giaddr is how the relay that forwarded the request knows to send the answer
    back to that segment. Clearing it as part of "stop cloning the header"
    would strand every relayed client, which is exactly the kind of
    over-broad fix this review has already had to back out twice.
    """
    resp = server._create_response(_request(), lease, SERVER_ID, resp_ty)
    assert resp.giaddr == IPv4("10.6.6.6")


@pytest.mark.parametrize(
    "resp_ty",
    [DhcpMessageType.DHCPOFFER, DhcpMessageType.DHCPACK, DhcpMessageType.DHCPNAK],
)
def test_hops_and_secs_are_reset(server, lease, resp_ty) -> None:
    resp = server._create_response(_request(), lease, SERVER_ID, resp_ty)
    assert resp.hops == 0
    assert resp.secs == timedelta(0)
    assert resp.op is OpCode.BOOTREPLY
