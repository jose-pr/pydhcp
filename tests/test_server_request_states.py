"""The stock server's answers, held to RFC 2131's tables clause by clause.

Every expectation is the RFC's sentence or table (`s4.3.2` tells SELECTING,
INIT-REBOOT, RENEWING and REBINDING apart and Table 3 says what a NAK carries),
never what the server happened to do. Each test names its clause.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import typing as _ty
from ipaddress import IPv4Address as IPv4
from unittest.mock import Mock

import pytest

from pydhcp import (
    DHCPFlags,
    DHCPLease,
    DHCPMessage,
    DHCPOptions,
    DHCPRequestContext,
    DHCPServer,
    InMemoryLeaseBackend,
    NetworkInterface,
    RelayAgentInformation,
    SocketAddress,
)
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType

# The allocator reads the host's adapters through this name in the private
# module that owns it; a test serves a fixed interface by replacing it there.
from pydhcp.server import _policy
from conftest import build_request

SERVED = ipaddress.IPv4Interface("10.0.0.1/24")
SERVER = SERVED.ip
BROADCAST = IPv4("255.255.255.255")
A, B = bytes([2, 0, 0, 0, 0, 1]), bytes([2, 0, 0, 0, 0, 2])
C = DHCPOptionCode


@pytest.fixture(autouse=True)
def _served_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _policy,
        "_servable_interface",
        lambda server_id: (
            NetworkInterface("eth0", SERVED) if server_id == SERVED.ip else None
        ),
    )


class _Sent(_ty.NamedTuple):
    message: DHCPMessage
    data: bytes
    dest: IPv4
    port: int

    @property
    def type(self) -> DHCPMessageType:
        found = self.message.options.get(C.DHCP_MESSAGE_TYPE)
        assert found is not None
        return found

    @property
    def codes(self) -> _ty.Set[int]:
        return {int(code) for code, _ in self.message.options.items(decoded=False)}


def _message(
    message_type: DHCPMessageType,
    chaddr: bytes = A,
    *,
    ciaddr: str = "0.0.0.0",
    giaddr: str = "0.0.0.0",
    requested: _ty.Optional[str] = None,
    server_id: _ty.Optional[str] = None,
    client_identifier: _ty.Optional[bytes] = None,
    extra: _ty.Optional[_ty.Dict[int, _ty.Any]] = None,
    flags: int = 0,
) -> DHCPMessage:
    options = DHCPOptions()
    options[C.DHCP_MESSAGE_TYPE] = message_type
    if requested is not None:
        options[C.REQUESTED_IP] = IPv4(requested)
    if server_id is not None:
        options[C.SERVER_IDENTIFIER] = IPv4(server_id)
    if client_identifier is not None:
        options[C.CLIENT_IDENTIFIER] = bytearray(client_identifier)
    for code, value in (extra or {}).items():
        options[code] = value
    return build_request(
        options=options,
        chaddr=chaddr,
        ciaddr=IPv4(ciaddr),
        giaddr=IPv4(giaddr),
        flags=DHCPFlags(flags),
    )


def _send(
    server: DHCPServer,
    message: DHCPMessage,
    *,
    unicast: _ty.Optional[bool] = None,
    source: str = "10.0.0.50",
) -> _ty.List[_Sent]:
    transport = Mock(send=Mock(return_value=1))
    context = DHCPRequestContext(
        transport=transport,
        interface=NetworkInterface("eth0", SERVED),
        client=SocketAddress(source, 68),
        client_mac=message.chaddr,
        destination=None if unicast is None else (SERVER if unicast else BROADCAST),
        is_unicast=unicast,
    )
    server.handle(message, context)
    return [
        _Sent(
            DHCPMessage.decode(memoryview(bytes(call.args[0]))),
            bytes(call.args[0]),
            call.args[1],
            call.kwargs["port"],
        )
        for call in transport.send.call_args_list
    ]


def _cid(chaddr: bytes) -> str:
    return _message(DHCPMessageType.DHCPDISCOVER, chaddr).get_client_id()


@pytest.fixture
def server() -> DHCPServer:
    return DHCPServer(lease_backend=InMemoryLeaseBackend())


def _bind(server: DHCPServer, chaddr: bytes, ip: str) -> DHCPLease:
    options = DHCPOptions()
    options[C.SUBNET_MASK] = SERVED.network.netmask
    lease = server.lease_backend.allocate(_cid(chaddr), IPv4(ip), 3600, options)
    assert lease is not None
    return lease


def _offer(server: DHCPServer, chaddr: bytes, ip: str) -> None:
    assert server.lease_backend.offer(_cid(chaddr), IPv4(ip), 120.0) is not None


# --- RFC 2131 s3.1 step 4 and s4.3.2: SELECTING --------------------------------


def test_s3_1_step4_a_selecting_request_for_an_offered_address_is_acked(server) -> None:
    _offer(server, A, "10.0.0.50")
    (reply,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST,
            A,
            requested="10.0.0.50",
            server_id="10.0.0.1",
        ),
    )
    assert reply.type is DHCPMessageType.DHCPACK
    assert reply.message.yiaddr == IPv4("10.0.0.50")


def test_s3_1_step4_a_selecting_request_for_an_address_another_client_holds_is_nakked(
    server,
) -> None:
    _bind(server, A, "10.0.0.50")
    (reply,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST,
            B,
            requested="10.0.0.50",
            server_id="10.0.0.1",
        ),
    )
    assert reply.type is DHCPMessageType.DHCPNAK
    assert server.lease_backend.lookup(_cid(B)) is None


def test_s3_1_step4_a_selecting_request_for_an_address_off_the_network_is_nakked(
    server,
) -> None:
    (reply,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST,
            B,
            requested="192.168.9.9",
            server_id="10.0.0.1",
        ),
    )
    assert reply.type is DHCPMessageType.DHCPNAK


def test_s3_1_step4_a_selecting_request_with_no_offer_is_nakked_and_allocates_nothing(
    server,
) -> None:
    """The offer lapsed or never was: nothing is committed on a bare REQUEST."""
    (reply,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST,
            A,
            requested="10.0.0.50",
            server_id="10.0.0.1",
        ),
    )
    assert reply.type is DHCPMessageType.DHCPNAK
    assert server.lease_backend.lookup(_cid(A)) is None
    assert server.metrics.leases_allocated == 0


def test_s3_1_step4_a_selecting_request_for_another_address_than_the_offer_is_nakked(
    server,
) -> None:
    _offer(server, A, "10.0.0.50")
    (reply,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST,
            A,
            requested="10.0.0.51",
            server_id="10.0.0.1",
        ),
    )
    assert reply.type is DHCPMessageType.DHCPNAK


# --- RFC 2131 s4.3.2: INIT-REBOOT, RENEWING, REBINDING -------------------------


def test_s4_3_2_init_reboot_from_a_known_client_for_its_address_is_acked(
    server,
) -> None:
    _bind(server, A, "10.0.0.50")
    (reply,) = _send(
        server, _message(DHCPMessageType.DHCPREQUEST, A, requested="10.0.0.50")
    )
    assert reply.type is DHCPMessageType.DHCPACK


def test_s4_3_2_init_reboot_from_a_known_client_for_another_address_is_nakked(
    server,
) -> None:
    """ "If not [correct], then the server SHOULD send a DHCPNAK message"."""
    _bind(server, A, "10.0.0.50")
    (reply,) = _send(
        server, _message(DHCPMessageType.DHCPREQUEST, A, requested="10.77.0.5")
    )
    assert reply.type is DHCPMessageType.DHCPNAK


def test_s4_3_2_init_reboot_from_an_unknown_client_is_silence(server) -> None:
    """ "If the DHCP server has no record of this client, then it MUST remain silent"."""
    assert (
        _send(server, _message(DHCPMessageType.DHCPREQUEST, A, requested="10.0.0.50"))
        == []
    )
    assert server.lease_backend.lookup(_cid(A)) is None


@pytest.mark.parametrize(
    "unicast", [True, False, None], ids=["RENEWING", "REBINDING", "unknown"]
)
def test_s4_3_2_a_renewing_or_rebinding_request_from_an_unknown_client_allocates_nothing(
    server, unicast
) -> None:
    """The client is completely configured: a server with no binding for it
    does not make one (a request is answered from what the server holds)."""
    replies = _send(
        server,
        _message(DHCPMessageType.DHCPREQUEST, A, ciaddr="10.0.0.77"),
        unicast=unicast,
        source="10.0.0.77",
    )
    assert replies == []
    assert server.lease_backend.lookup(_cid(A)) is None
    assert server.metrics.leases_allocated == 0
    assert server.metrics.leases_offered == 0


@pytest.mark.parametrize("unicast", [True, False], ids=["RENEWING", "REBINDING"])
def test_s4_3_2_a_renewing_or_rebinding_request_from_a_known_client_is_acked_to_ciaddr(
    server, unicast
) -> None:
    before = _bind(server, A, "10.0.0.50")
    (reply,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPREQUEST,
            A,
            ciaddr="10.0.0.50",
            extra={C.IP_ADDRESS_LEASE_TIME: 7200},
        ),
        unicast=unicast,
        source="10.0.0.50",
    )
    assert reply.type is DHCPMessageType.DHCPACK
    assert reply.dest == IPv4("10.0.0.50")
    assert reply.message.ciaddr == IPv4("10.0.0.50")
    renewed = server.lease_backend.lookup(_cid(A))
    assert renewed is not None and renewed.expires > before.expires  # type: ignore[operator]


def test_s4_3_2_a_rebinding_request_that_names_an_address_the_client_does_not_hold_is_nakked(
    server,
) -> None:
    """ "The DHCP server SHOULD check 'ciaddr' for correctness before replying"."""
    _bind(server, A, "10.0.0.50")
    (reply,) = _send(
        server,
        _message(DHCPMessageType.DHCPREQUEST, A, ciaddr="10.0.0.77"),
        unicast=False,
    )
    assert reply.type is DHCPMessageType.DHCPNAK


def test_s4_3_2_the_request_shape_is_named_from_how_it_arrived(
    server, caplog: pytest.LogCaptureFixture
) -> None:
    """Table 4: RENEWING is unicast to the server, REBINDING is broadcast."""
    request = _message(DHCPMessageType.DHCPREQUEST, A, ciaddr="10.0.0.77")
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        _send(server, request, unicast=True)
        _send(server, request, unicast=False)
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "RENEWING from" in text
    assert "REBINDING from" in text


def test_s4_3_2_a_request_that_names_no_address_is_dropped(server) -> None:
    """Table 4: every shape carries a server identifier, a requested address or ciaddr."""
    assert _send(server, _message(DHCPMessageType.DHCPREQUEST, A)) == []


def test_s4_3_2_init_reboot_is_answered_from_acquire_lease_alone() -> None:
    """An override that returns leases and stores nothing is the extension point
    the header documents: a rebooting client is ACKed for the address it holds."""

    class Fixed(DHCPServer):
        def acquire_lease(self, client_id, server_id, msg, *, commit=True):  # type: ignore[no-untyped-def]
            expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
            return DHCPLease(IPv4("10.0.0.50"), expires, DHCPOptions())

    fixed = Fixed()
    (ack,) = _send(
        fixed, _message(DHCPMessageType.DHCPREQUEST, A, requested="10.0.0.50")
    )
    assert ack.type is DHCPMessageType.DHCPACK
    (nak,) = _send(
        fixed, _message(DHCPMessageType.DHCPREQUEST, A, requested="10.0.0.51")
    )
    assert nak.type is DHCPMessageType.DHCPNAK
    assert fixed.lease_backend.lookup(_cid(A)) is None


# --- RFC 2131 Table 3 and RFC 6842 s3: the DHCPNAK -----------------------------


def _nak(server: DHCPServer, **kwargs: _ty.Any) -> _Sent:
    request = kwargs.pop("request", None) or _message(
        DHCPMessageType.DHCPREQUEST,
        A,
        requested="10.0.0.99",
        server_id="10.0.0.1",
        **kwargs,
    )
    (reply,) = _send(server, request)
    assert reply.type is DHCPMessageType.DHCPNAK
    return reply


def test_rfc6842_s3_a_nak_carries_no_client_identifier_the_client_did_not_send(
    server,
) -> None:
    nak = _nak(server)
    assert C.CLIENT_IDENTIFIER not in nak.message.options


@pytest.mark.parametrize(
    "identifier",
    [
        b"\x01\xaa\xbb\xcc\xdd\xee\xff",
        b"\x00opaque-id",
        b"\xff\x00\x00\x00\x01\x00\x01abc",
    ],
    ids=["hardware", "opaque", "iaid-duid"],
)
def test_rfc6842_s3_a_nak_returns_the_client_identifier_unaltered(
    server, identifier
) -> None:
    nak = _nak(server, client_identifier=identifier)
    assert (
        bytes(nak.message.options.get(C.CLIENT_IDENTIFIER, decode=False)) == identifier
    )


def test_rfc6842_s3_an_ack_and_an_offer_follow_the_same_rule(server) -> None:
    (offer,) = _send(
        server,
        _message(DHCPMessageType.DHCPDISCOVER, A, requested="10.0.0.50"),
    )
    assert C.CLIENT_IDENTIFIER not in offer.message.options
    sent = b"\x01" + B
    (offer_b,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPDISCOVER,
            B,
            requested="10.0.0.51",
            client_identifier=sent,
        ),
    )
    assert bytes(offer_b.message.options.get(C.CLIENT_IDENTIFIER, decode=False)) == sent


def test_table3_a_nak_has_no_address_no_boot_fields_and_the_clients_routing_fields(
    server,
) -> None:
    request = _message(
        DHCPMessageType.DHCPREQUEST,
        A,
        requested="10.0.0.99",
        server_id="10.0.0.1",
        giaddr="10.0.0.2",
        flags=0x0001,
    )
    request.siaddr = IPv4("10.9.9.9")
    request.sname = "elsewhere"
    request.file = "boot.img"
    request.secs = dt.timedelta(seconds=9)
    request.hops = 1
    request.xid = 0xCAFE0001

    nak = _nak(server, request=request).message

    assert nak.op.name == "BOOTREPLY"
    assert (nak.ciaddr, nak.yiaddr, nak.siaddr) == (IPv4("0.0.0.0"),) * 3
    assert nak.sname == "" and nak.file == ""
    assert nak.hops == 0 and nak.secs == dt.timedelta(0)
    assert nak.xid == 0xCAFE0001
    assert nak.giaddr == IPv4("10.0.0.2")
    assert nak.chaddr == A
    assert nak.htype == request.htype


def test_table3_a_nak_carries_the_message_the_server_identifier_and_nothing_else(
    server,
) -> None:
    """ "All others MUST NOT": not the lease time, not the parameters asked for."""
    nak = _nak(
        server,
        extra={
            C.PARAMETER_REQUEST_LIST: [C.SUBNET_MASK, C.ROUTER, C.DNS],
            C.IP_ADDRESS_LEASE_TIME: 7200,
            C.MAXIMUM_DHCP_MESSAGE_SIZE: 1500,
            C.VENDOR_CLASS_IDENTIFIER: "vendor",
        },
    )
    assert nak.codes == {
        int(C.DHCP_MESSAGE_TYPE),
        int(C.SERVER_IDENTIFIER),
        int(C.DHCP_MESSAGE),
    }
    assert nak.message.options.get(C.SERVER_IDENTIFIER) == SERVER
    assert nak.message.options.get(C.DHCP_MESSAGE)  # "Message: SHOULD"


def test_table3_a_nak_keeps_the_relay_agent_information(server) -> None:
    info = RelayAgentInformation([(1, b"port-7")])
    nak = _nak(server, extra={C.RELAY_AGENT_INFORMATION: info})
    assert C.RELAY_AGENT_INFORMATION in nak.message.options


def test_s4_3_2_a_nak_without_a_relay_is_broadcast(server) -> None:
    nak = _nak(server, flags=0x0001)
    assert nak.dest == BROADCAST
    assert nak.message.flags == DHCPFlags(0x0001)  # Table 3: from the client


def test_s4_3_2_a_nak_through_a_relay_sets_the_broadcast_bit_and_keeps_the_rest(
    server,
) -> None:
    nak = _nak(server, giaddr="10.0.0.2", flags=0x0001)
    assert nak.dest == IPv4("10.0.0.2")
    assert nak.message.flags == DHCPFlags(0x8001)


# --- RFC 2131 s4.3.1: the subnet a relayed client is served from ----------------


def test_s4_3_1_a_discover_relayed_from_outside_the_served_network_is_refused(
    server,
) -> None:
    """The stock allocator has the one network to give: it does not answer a
    client behind a relay on another network with this network's mask."""
    assert (
        _send(
            server,
            _message(
                DHCPMessageType.DHCPDISCOVER,
                A,
                giaddr="10.5.5.1",
                requested="10.0.0.60",
            ),
            source="10.5.5.1",
        )
        == []
    )
    assert server.lease_backend.lookup(_cid(A)) is None
    assert server.metrics.addresses_refused == 1


def test_s4_3_1_a_discover_relayed_from_inside_the_served_network_is_offered(
    server,
) -> None:
    (offer,) = _send(
        server,
        _message(
            DHCPMessageType.DHCPDISCOVER, A, giaddr="10.0.0.2", requested="10.0.0.61"
        ),
        source="10.0.0.2",
    )
    assert offer.type is DHCPMessageType.DHCPOFFER
    assert offer.dest == IPv4("10.0.0.2")


# --- RFC 2131 s4.3.5 and s3.4: DHCPINFORM ---------------------------------------


@pytest.mark.parametrize(
    "ciaddr, source",
    [
        ("10.0.0.66", "10.0.0.66"),
        ("10.0.0.7", "10.0.0.66"),
        ("203.0.113.9", "203.0.113.9"),
    ],
    ids=["the sender's", "in the served network", "the sender's, off the network"],
)
def test_s4_3_5_an_inform_is_answered_at_ciaddr_when_it_is_the_senders_or_ours(
    server, ciaddr, source
) -> None:
    (ack,) = _send(
        server,
        _message(DHCPMessageType.DHCPINFORM, A, ciaddr=ciaddr),
        source=source,
    )
    assert ack.type is DHCPMessageType.DHCPACK
    assert ack.dest == IPv4(ciaddr)
    assert ack.message.yiaddr == IPv4("0.0.0.0")
    assert C.IP_ADDRESS_LEASE_TIME not in ack.message.options


def test_s4_3_5_an_inform_naming_an_address_that_is_not_the_senders_is_not_answered(
    server,
) -> None:
    """The ACK goes to ciaddr: one that is neither where the datagram came from
    nor in the network served would send a reply wherever the sender chose."""
    assert (
        _send(
            server,
            _message(DHCPMessageType.DHCPINFORM, A, ciaddr="203.0.113.9"),
            source="10.0.0.66",
        )
        == []
    )
    assert server.metrics.informs_ignored == 1


def test_s4_4_3_an_inform_with_no_ciaddr_is_not_answered(server) -> None:
    assert _send(server, _message(DHCPMessageType.DHCPINFORM, A)) == []
    assert server.metrics.informs_ignored == 1


# --- RFC 3046 s2.2: the echoed relay agent information --------------------------


def _wire_codes(data: bytes) -> _ty.List[int]:
    codes, index = [], 240
    while index < len(data) and data[index] != 255:
        if data[index] == 0:
            index += 1
            continue
        codes.append(data[index])
        index += 2 + data[index + 1]
    return codes


def _relayed_discover(size: int, *, maximum: _ty.Optional[int] = None) -> DHCPMessage:
    info = RelayAgentInformation([(1, b"c" * (size // 2)), (2, b"r" * (size // 2 - 4))])
    extra: _ty.Dict[int, _ty.Any] = {C.RELAY_AGENT_INFORMATION: info}
    if maximum is not None:
        extra[C.MAXIMUM_DHCP_MESSAGE_SIZE] = maximum
    return _message(
        DHCPMessageType.DHCPDISCOVER,
        A,
        giaddr="10.0.0.2",
        requested="10.0.0.62",
        client_identifier=b"\x01" + A,
        extra=extra,
    )


def test_rfc3046_s2_2_the_echoed_relay_information_is_the_last_option(server) -> None:
    (offer,) = _send(server, _relayed_discover(12), source="10.0.0.2")
    codes = _wire_codes(offer.data)
    assert codes[-1] == int(C.RELAY_AGENT_INFORMATION), codes
    assert int(C.CLIENT_IDENTIFIER) in codes
    assert server.metrics.relay_info_omitted == 0


def test_rfc3046_s2_2_a_reply_that_would_overload_is_sent_without_the_option_and_counted(
    server, caplog: pytest.LogCaptureFixture
) -> None:
    """The option is never placed in `sname` or `file`: "it SHALL send the
    response without the Relay Information Field, and SHOULD increment an error
    counter"."""
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        (offer,) = _send(server, _relayed_discover(300), source="10.0.0.2")

    assert offer.type is DHCPMessageType.DHCPOFFER
    assert C.RELAY_AGENT_INFORMATION not in offer.message.options
    assert int(C.OPTION_OVERLOAD) not in _wire_codes(offer.data)
    assert offer.data[44:236].count(bytes([int(C.RELAY_AGENT_INFORMATION)])) == 0
    assert server.metrics.relay_info_omitted == 1
    assert any("relay agent information" in r.getMessage() for r in caplog.records)


def test_rfc3046_s2_2_the_option_is_kept_when_the_client_allows_a_larger_reply(
    server,
) -> None:
    (offer,) = _send(server, _relayed_discover(300, maximum=1500), source="10.0.0.2")
    assert _wire_codes(offer.data)[-1] == int(C.RELAY_AGENT_INFORMATION)
    assert int(C.OPTION_OVERLOAD) not in _wire_codes(offer.data)
    assert server.metrics.relay_info_omitted == 0


def test_rfc3046_s2_2_an_option_too_large_for_the_reply_even_overloaded_is_left_out(
    server,
) -> None:
    """504 octets of relay information do not fit a 576-octet reply at all: the
    reply is still sent, without it."""
    (offer,) = _send(server, _relayed_discover(500), source="10.0.0.2")
    assert offer.type is DHCPMessageType.DHCPOFFER
    assert C.RELAY_AGENT_INFORMATION not in offer.message.options
    assert server.metrics.relay_info_omitted == 1
