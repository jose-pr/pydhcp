"""The UDP port a reply goes to is set by where it goes, never by the request's source port.

RFC 1542 section 5.4 gives the server three MUSTs: a reply sent to `ciaddr` has
destination port 68 (BOOTPC), one sent to a relay at `giaddr` has destination
port 67 (BOOTPS), and "in any case, the UDP destination port MUST be set to
BOOTPC (68)". The source port is the sender's to choose, so honouring it would
let one unauthenticated datagram steer a reply to any port on any host.
"""

from __future__ import annotations

import ipaddress
import socket
import typing as _ty
from unittest.mock import Mock

import pytest

from helpers import (
    CHADDR,
    LOOPBACK_ALIAS_BINDABLE,
    FixedLeaseServer,
    build_request,
    running,
)
from pydhcp import DHCPMessage, DHCPRequestContext, NetworkInterface, SocketAddress
from pydhcp.packet import DHCPFlags, DHCPMessageType

IPv4 = ipaddress.IPv4Address
RELAY = IPv4("198.51.100.1")


def _sent_to(
    message: DHCPMessage,
    source_port: int,
    server: _ty.Optional[FixedLeaseServer] = None,
) -> "tuple[str, int]":
    server = server or FixedLeaseServer()
    context = DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("192.0.2.1/24")),
        client=SocketAddress("192.0.2.77", source_port),
        client_mac=CHADDR,
    )
    server.handle(message, context)
    call = context.transport.send.call_args
    return str(call.args[1]), call.kwargs["port"]


@pytest.mark.parametrize("source_port", [67, 68, 1024, 4444])
def test_a_reply_to_a_relay_goes_to_port_67_whatever_the_source_port(
    source_port: int,
) -> None:
    """RFC 1542 s5.4: "The UDP destination port MUST be set to BOOTPS (67)." """
    message = build_request(giaddr=RELAY)
    assert _sent_to(message, source_port) == (str(RELAY), 67)


@pytest.mark.parametrize("source_port", [67, 68, 1024, 4444])
def test_a_nak_through_a_relay_goes_to_port_67_too(source_port: int) -> None:
    request = build_request(DHCPMessageType.DHCPREQUEST, giaddr=RELAY)
    from pydhcp.options import DHCPOptionCode

    request.options[DHCPOptionCode.SERVER_IDENTIFIER] = IPv4("192.0.2.1")
    request.options[DHCPOptionCode.REQUESTED_IP] = IPv4("192.0.2.99")
    server = FixedLeaseServer()
    server.acquire_lease = lambda *a, **k: None  # type: ignore[method-assign]
    assert _sent_to(request, source_port, server) == (str(RELAY), 67)


@pytest.mark.parametrize(
    "fields",
    [
        {"ciaddr": IPv4("192.0.2.50")},
        {"flags": DHCPFlags.BROADCAST},
        {},
    ],
    ids=["ciaddr", "broadcast flag", "yiaddr or broadcast"],
)
@pytest.mark.parametrize("source_port", [67, 68, 1024, 4444])
def test_a_reply_to_a_client_goes_to_port_68_whatever_the_source_port(
    fields: "dict[str, _ty.Any]", source_port: int
) -> None:
    """RFC 1542 s5.4: for `ciaddr`, "MUST be set to BOOTPC (68)", and "in any case"."""
    destination, port = _sent_to(build_request(**fields), source_port)
    assert port == 68


def test_the_two_ports_are_class_attributes_a_harness_may_set() -> None:
    class Harness(FixedLeaseServer):
        REPLY_TO_RELAY_PORT = 6767
        REPLY_TO_CLIENT_PORT = 6868

    assert _sent_to(build_request(giaddr=RELAY), 4444, Harness())[1] == 6767
    assert (
        _sent_to(build_request(ciaddr=IPv4("192.0.2.50")), 4444, Harness())[1] == 6868
    )
    # And the defaults are the RFC's.
    assert FixedLeaseServer.REPLY_TO_RELAY_PORT == 67
    assert FixedLeaseServer.REPLY_TO_CLIENT_PORT == 68


@pytest.mark.skipif(
    not LOOPBACK_ALIAS_BINDABLE, reason="needs a second loopback address, 127.0.0.2"
)
def test_one_datagram_cannot_steer_a_reply_to_a_port_of_its_choosing() -> None:
    """Real sockets. The sender names a relay, 127.0.0.2, and sends from port X.

    A bystander on 127.0.0.2 at the same port X, which never sent anything, used
    to receive the reply. The reply now goes to the relay port, so the bystander
    hears it only on the port the harness set for the relay, and the sender
    hears nothing.
    """
    server = FixedLeaseServer(listen=[("0.0.0.0", 0)])
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bystander = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.bind(("127.0.0.1", 0))
        chosen = sender.getsockname()[1]
        bystander.bind(("127.0.0.2", chosen))
        relay.bind(("127.0.0.2", 0))
        for sock in (sender, bystander, relay):
            sock.settimeout(0.5)
        server.REPLY_TO_RELAY_PORT = relay.getsockname()[1]
        with running(server):
            port = server.bound_addresses[0].port
            sender.sendto(
                build_request(giaddr=IPv4("127.0.0.2")).encode(), ("127.0.0.1", port)
            )
            data, _ = relay.recvfrom(4096)
            assert DHCPMessage.decode(data).giaddr == IPv4("127.0.0.2")
            for sock in (sender, bystander):
                sock.settimeout(0.3)
                with pytest.raises(socket.timeout):
                    sock.recvfrom(4096)
    finally:
        for sock in (sender, bystander, relay):
            sock.close()
