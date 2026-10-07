"""The server's extension point: who owns the backend, what a hook is told, and a store kept elsewhere."""

from __future__ import annotations

import ipaddress
import logging
import socket
import typing as _ty
from unittest.mock import Mock

import pytest

from helpers import CHADDR, build_request
from driving import WAIT_SECONDS, driver_params, serve
from pydhcp import (
    AsyncDHCPServer,
    DHCPLease,
    DHCPMessage,
    DHCPOptions,
    DHCPRequestContext,
    DHCPServer,
    NetworkInterface,
    SocketAddress,
)
from pydhcp.lease import InMemoryLeaseBackend
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType

IPv4 = ipaddress.IPv4Address
SERVED = ipaddress.IPv4Interface("10.0.0.1/24")
LOOPBACK = IPv4("127.0.0.1")


# --- a backend the caller passed in is the caller's ----------------------------


class _SizedBackend(InMemoryLeaseBackend):
    """Reports how many leases it holds, so it is falsy while empty."""

    def __init__(self) -> None:
        super().__init__()
        self.closed = 0

    def __len__(self) -> int:
        return len(self._leases)

    def close(self) -> None:
        self.closed += 1


@pytest.mark.parametrize("server_class", [DHCPServer, AsyncDHCPServer])
def test_a_backend_that_is_falsy_when_empty_is_still_the_servers(server_class) -> None:
    mine = _SizedBackend()
    assert not mine
    assert server_class(lease_backend=mine).lease_backend is mine


@pytest.mark.parametrize("server_class", [DHCPServer, AsyncDHCPServer])
def test_a_server_without_a_backend_makes_its_own(server_class) -> None:
    server = server_class()
    assert isinstance(server.lease_backend, InMemoryLeaseBackend)


def test_close_leaves_a_backend_the_server_was_given_open() -> None:
    mine = _SizedBackend()
    server = DHCPServer(listen=("127.0.0.1", 0), lease_backend=mine)
    server.bind()
    server.close()
    assert mine.closed == 0


def test_close_closes_the_backend_the_server_made(monkeypatch) -> None:
    closed: "list[object]" = []
    monkeypatch.setattr(
        InMemoryLeaseBackend, "close", lambda self: closed.append(self), raising=False
    )
    server = DHCPServer(listen=("127.0.0.1", 0))
    server.bind()
    server.close()
    server.close()  # repeatable
    assert closed and all(item is server.lease_backend for item in closed)


def test_the_asyncio_server_follows_the_same_rule(monkeypatch) -> None:
    """Given is kept, made is closed, on `aclose()` too."""
    import asyncio

    given = _SizedBackend()
    closed: "list[object]" = []
    monkeypatch.setattr(
        InMemoryLeaseBackend, "close", lambda self: closed.append(self), raising=False
    )

    async def run() -> AsyncDHCPServer:
        kept = AsyncDHCPServer(listen=("127.0.0.1", 0), lease_backend=given)
        made = AsyncDHCPServer(listen=("127.0.0.1", 0))
        for server in (kept, made):
            await server.start()
            await server.aclose()
        return made

    made = asyncio.run(run())
    assert closed == [made.lease_backend]
    assert given.closed == 0


# --- release_lease is always told this server's own address --------------------


class _Audit(DHCPServer):
    def __init__(self) -> None:
        super().__init__(lease_backend=InMemoryLeaseBackend())
        self.seen: "list[IPv4]" = []

    def release_lease(self, client_id, server_id, msg):  # type: ignore[no-untyped-def]
        self.seen.append(server_id)
        return super().release_lease(client_id, server_id, msg)


def _message(kind: DHCPMessageType, **fields: _ty.Any) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = kind
    if "requested" in fields:
        options[DHCPOptionCode.REQUESTED_IP] = fields.pop("requested")
    if "server_id" in fields:
        options[DHCPOptionCode.SERVER_IDENTIFIER] = fields.pop("server_id")
    return build_request(options=options, **fields)


def _context() -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=Mock(send=Mock(return_value=1)),
        interface=NetworkInterface("eth0", SERVED),
        client=SocketAddress("10.0.0.50", 68),
        client_mac=CHADDR,
    )


def test_release_lease_is_told_the_local_address_on_every_path(monkeypatch) -> None:
    monkeypatch.setattr(
        "pydhcp.server._policy._servable_interface",
        lambda _ip: NetworkInterface("eth0", SERVED),
    )
    monkeypatch.setattr(
        "pydhcp.server._policy._netimps.is_local_address",
        lambda address, **_kw: address == SERVED.ip,
    )
    server = _Audit()
    client_id = _message(DHCPMessageType.DHCPREQUEST).get_client_id()
    address = IPv4("10.0.0.50")

    server.lease_backend.allocate(client_id, address, 3600.0)
    server.handle(_message(DHCPMessageType.DHCPRELEASE, ciaddr=address), _context())

    server.lease_backend.allocate(client_id, address, 3600.0)
    server.handle(_message(DHCPMessageType.DHCPDECLINE, requested=address), _context())

    # The client chose another server: that server's address is in the message,
    # not in what the hook is told.
    server.lease_backend.offer(client_id, address, 120.0)
    server.handle(
        _message(
            DHCPMessageType.DHCPREQUEST, requested=address, server_id=IPv4("192.0.2.77")
        ),
        _context(),
    )
    assert server.seen == [SERVED.ip] * 3


# --- a server that keeps its leases elsewhere overrides one lookup -------------


class _Elsewhere:
    """Keeps every lease in a dict of its own and nothing in `lease_backend`.

    It overrides the allocation hook, `lookup_lease` and `release_lease`: the
    last two are all the handlers of RELEASE, DECLINE and a REQUEST naming
    another server ask it.
    """

    held: "dict[str, DHCPLease]"
    asked: "list[str]"

    def acquire_lease(self, client_id, server_id, msg, *, commit=True):  # type: ignore[no-untyped-def]
        existing = self.lookup_lease(client_id)
        if existing is not None:
            return existing
        if msg.message_type is not DHCPMessageType.DHCPDISCOVER:
            return None
        lease = DHCPLease(LOOPBACK, offered=not commit)
        self.held[client_id] = lease
        return lease

    def lookup_lease(self, client_id):  # type: ignore[no-untyped-def]
        self.asked.append(client_id)
        return self.held.get(client_id)

    def release_lease(self, client_id, server_id, msg):  # type: ignore[no-untyped-def]
        return self.held.pop(client_id, None) is not None


class _ElsewhereSync(_Elsewhere, DHCPServer):
    pass


class _ElsewhereAsync(_Elsewhere, AsyncDHCPServer):
    pass


def _wire(kind: DHCPMessageType, xid: int, **fields: _ty.Any) -> bytes:
    return bytes(_message(kind, xid=xid, **fields).encode())


@pytest.mark.parametrize(
    "server_class, loop_type", driver_params(_ElsewhereSync, _ElsewhereAsync)
)
def test_one_overridden_lookup_answers_init_reboot_release_and_decline(
    server_class, loop_type
) -> None:
    server = server_class(listen=("127.0.0.1", 0))
    server.held, server.asked = {}, []

    def exercise(port: int) -> "list[DHCPMessageType]":
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(WAIT_SECONDS)
        # The client is on an ephemeral port, not 68.
        server.REPLY_TO_CLIENT_PORT = client.getsockname()[1]
        kinds: "list[DHCPMessageType]" = []

        def ask(data: bytes) -> DHCPMessageType:
            client.sendto(data, ("127.0.0.1", port))
            reply = DHCPMessage.decode(client.recvfrom(2048)[0])
            kind = reply.message_type
            assert kind is not None
            return kind

        try:
            kinds.append(ask(_wire(DHCPMessageType.DHCPDISCOVER, 1)))
            kinds.append(
                ask(
                    _wire(
                        DHCPMessageType.DHCPREQUEST,
                        2,
                        requested=LOOPBACK,
                        server_id=LOOPBACK,
                    )
                )
            )
            # INIT-REBOOT: an address, no server identifier, no ciaddr.
            kinds.append(ask(_wire(DHCPMessageType.DHCPREQUEST, 3, requested=LOOPBACK)))
            # DECLINE and RELEASE are not answered: look at the store instead.
            client.sendto(
                _wire(DHCPMessageType.DHCPDECLINE, 4, requested=LOOPBACK),
                ("127.0.0.1", port),
            )
            deadline = WAIT_SECONDS
            import time

            end = time.monotonic() + deadline
            while server.held and time.monotonic() < end:
                time.sleep(0.01)
            assert not server.held, "the DECLINE did not reach the store kept elsewhere"
        finally:
            client.close()
        return kinds

    kinds = serve(server, exercise, loop_type)
    assert kinds == [
        DHCPMessageType.DHCPOFFER,
        DHCPMessageType.DHCPACK,
        DHCPMessageType.DHCPACK,
    ]
    assert server.is_quarantined(LOOPBACK)
    assert server.metrics.leases_declined == 1
    assert server.lease_backend.lookup(server.asked[0]) is None, "backend untouched"
    assert len(server.lease_backend._leases) == 0  # type: ignore[attr-defined]


def test_release_through_the_overridden_lookup_checks_the_address(monkeypatch) -> None:
    """RELEASE asks `lookup_lease` what the sender holds before it acts."""
    server = _ElsewhereSync()
    server.held, server.asked = {}, []
    client_id = _message(DHCPMessageType.DHCPRELEASE).get_client_id()
    server.held[client_id] = DHCPLease(IPv4("10.0.0.50"))

    server.handle(
        _message(DHCPMessageType.DHCPRELEASE, ciaddr=IPv4("10.0.0.99")), _context()
    )
    assert client_id in server.held and server.metrics.releases_ignored == 1

    server.handle(
        _message(DHCPMessageType.DHCPRELEASE, ciaddr=IPv4("10.0.0.50")), _context()
    )
    assert not server.held and server.metrics.leases_released == 1
    assert server.asked == [client_id, client_id]


# --- the reply is not decoded again unless DEBUG will print it -----------------


def _discover_reply_decodes(monkeypatch, level: int) -> int:
    monkeypatch.setattr(
        "pydhcp.server._policy._servable_interface",
        lambda _ip: NetworkInterface("eth0", SERVED),
    )
    calls = []
    real = DHCPMessage.decode.__func__  # type: ignore[attr-defined]

    def spy(cls, data, *args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(1)
        return real(cls, data, *args, **kwargs)

    monkeypatch.setattr(DHCPMessage, "decode", classmethod(spy))
    server = DHCPServer(lease_backend=InMemoryLeaseBackend())
    discover = _message(DHCPMessageType.DHCPDISCOVER, requested=IPv4("10.0.0.50"))
    context = _context()
    logging.getLogger("pydhcp.server._reply").setLevel(level)
    try:
        server.handle(discover, context)
    finally:
        logging.getLogger("pydhcp.server._reply").setLevel(logging.NOTSET)
    assert context.transport.send.call_count == 1
    return len(calls)


def test_a_reply_is_not_decoded_again_when_debug_is_off(monkeypatch) -> None:
    assert _discover_reply_decodes(monkeypatch, logging.INFO) == 0


def test_a_reply_is_decoded_again_to_be_logged_when_debug_is_on(monkeypatch) -> None:
    assert _discover_reply_decodes(monkeypatch, logging.DEBUG) == 1
