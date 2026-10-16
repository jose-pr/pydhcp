"""The reply header is the server's, not the client's (`server-19`).

`_create_response` clones the request, so every field it does not overwrite is
whatever the client sent. RFC 2131 Table 3 says what each reply carries, and it
is not symmetric -- which is the whole difficulty: two of the fields that look
like leaks are required echoes, and clearing them would break relayed clients.
"""

import ipaddress
from datetime import timedelta

import pytest

from pydhcp import DHCPMessage, DHCPOptions
from pydhcp.lease import DHCPLease, InMemoryLeaseBackend
from ipaddress import IPv4Address as IPv4
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType, DHCPOpcode
from pydhcp.server import DHCPServer
from helpers import build_request

CHADDR = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
SERVER_ID = IPv4("10.0.0.1")


def _request() -> DHCPMessage:
    """A request whose sender filled in fields that are not its to choose."""
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    return build_request(
        options=options,
        hops=3,
        secs=timedelta(seconds=41),
        ciaddr=IPv4("203.0.113.9"),
        yiaddr=IPv4("203.0.113.8"),
        siaddr=IPv4("203.0.113.7"),
        giaddr=IPv4("203.0.113.6"),
        sname="attacker-tftp.example",
        file="evil/boot.img",
    )


@pytest.fixture
def server() -> DHCPServer:
    return DHCPServer(lease_backend=InMemoryLeaseBackend())


@pytest.fixture
def lease() -> DHCPLease:
    return DHCPLease(IPv4("10.0.0.50"), None, DHCPOptions())


@pytest.mark.parametrize(
    "resp_ty",
    [DHCPMessageType.DHCPOFFER, DHCPMessageType.DHCPACK, DHCPMessageType.DHCPNAK],
)
def test_next_server_fields_are_never_the_clients(server, lease, resp_ty) -> None:
    """siaddr/sname/file name the next bootstrap server -- the server's choice.

    Echoing them let a client nominate its own next-server and boot file and
    receive them back stamped with the server identifier, which is the pair a
    PXE client acts on.
    """
    # private: the reply builder, called directly to read the reply it makes
    resp = server._create_response(_request(), lease, SERVER_ID, resp_ty)
    assert resp.siaddr == IPv4("0.0.0.0")
    assert resp.sname == ""
    assert resp.file == ""


def test_offer_carries_no_ciaddr(server, lease) -> None:
    """Table 3: ciaddr is 0 in a DHCPOFFER."""
    # private: the reply builder, called directly to read the reply it makes
    resp = server._create_response(
        _request(), lease, SERVER_ID, DHCPMessageType.DHCPOFFER
    )
    assert resp.ciaddr == IPv4("0.0.0.0")


def test_ack_still_echoes_ciaddr(server, lease) -> None:
    """Table 3: in a DHCPACK, ciaddr IS the ciaddr from the DHCPREQUEST.

    The counterpart to the OFFER rule above, and the reason that fix must not
    be widened to cover both: a client renewing from BOUND puts its address in
    ciaddr and expects it back.
    """
    # private: the reply builder, called directly to read the reply it makes
    resp = server._create_response(
        _request(), lease, SERVER_ID, DHCPMessageType.DHCPACK
    )
    assert resp.ciaddr == IPv4("203.0.113.9")


@pytest.mark.parametrize(
    "resp_ty",
    [DHCPMessageType.DHCPOFFER, DHCPMessageType.DHCPACK, DHCPMessageType.DHCPNAK],
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
    # private: the reply builder, called directly to read the reply it makes
    resp = server._create_response(_request(), lease, SERVER_ID, resp_ty)
    assert resp.giaddr == IPv4("203.0.113.6")


@pytest.mark.parametrize(
    "resp_ty",
    [DHCPMessageType.DHCPOFFER, DHCPMessageType.DHCPACK, DHCPMessageType.DHCPNAK],
)
def test_hops_and_secs_are_reset(server, lease, resp_ty) -> None:
    # private: the reply builder, called directly to read the reply it makes
    resp = server._create_response(_request(), lease, SERVER_ID, resp_ty)
    assert resp.hops == 0
    assert resp.secs == timedelta(0)
    assert resp.op is DHCPOpcode.BOOTREPLY


# --- the boot fields come from the lease -------------------------------------------

BOOT = dict(siaddr=IPv4("10.0.0.2"), sname="tftp.example", file="ipxe.efi")


@pytest.mark.parametrize(
    "resp_ty", [DHCPMessageType.DHCPOFFER, DHCPMessageType.DHCPACK]
)
def test_an_offer_and_an_ack_carry_the_leases_boot_fields(server, resp_ty) -> None:
    lease = DHCPLease(IPv4("10.0.0.50"), None, DHCPOptions(), **BOOT)
    # private: the reply builder, called directly to read the reply it makes
    resp = server._create_response(_request(), lease, SERVER_ID, resp_ty)
    assert (resp.siaddr, resp.sname, resp.file) == (
        BOOT["siaddr"],
        BOOT["sname"],
        BOOT["file"],
    )
    assert DHCPMessage.decode(resp.encode()).file == "ipxe.efi"


def test_a_nak_never_carries_the_leases_boot_fields(server) -> None:
    lease = DHCPLease(IPv4("10.0.0.50"), None, DHCPOptions(), **BOOT)
    # private: the reply builder, called directly to read the reply it makes
    resp = server._create_response(
        _request(), lease, SERVER_ID, DHCPMessageType.DHCPNAK
    )
    assert (resp.siaddr, resp.sname, resp.file) == (IPv4("0.0.0.0"), "", "")


class _Reservations(DHCPServer):
    """Hands every client the lease it was given, as an override would."""

    def __init__(self, lease: DHCPLease) -> None:
        super().__init__(lease_backend=InMemoryLeaseBackend())
        self.lease = lease
        self.sent: list = []

    def acquire_lease(self, client_id, server_id, msg, *, commit=True):  # type: ignore[override]
        return self.lease

    def _filter_and_send(self, msg, resp, context, resp_ty) -> None:  # type: ignore[override]
        self.sent.append(resp)


def test_a_lease_with_no_address_is_never_offered(caplog) -> None:
    server = _Reservations(DHCPLease("0.0.0.0", strict=False, **BOOT))
    server.handle_discover(_discover(), _context())
    assert server.sent == []
    assert "no address" in caplog.text


def test_a_reservation_with_boot_fields_is_offered_with_them() -> None:
    server = _Reservations(DHCPLease("10.0.0.50", **BOOT))
    server.handle_discover(_discover(), _context())
    (offer,) = server.sent
    assert offer.yiaddr == IPv4("10.0.0.50") and offer.file == "ipxe.efi"


def _discover() -> DHCPMessage:
    return build_request(DHCPMessageType.DHCPDISCOVER)


def _context():
    from unittest.mock import Mock

    from pydhcp import DHCPRequestContext, NetworkInterface, SocketAddress

    return DHCPRequestContext(
        transport=Mock(),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )
