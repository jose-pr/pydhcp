"""`DHCPLease` as a value: frozen, hashable, options copied in and read-only,
an address always, and an expiry that is an aware instant or `None`.

Also the lease file's format: a file written before the lease became a value
still loads."""

from __future__ import annotations

import copy
import datetime as dt
import ipaddress
import multiprocessing
import pathlib
import pickle
import shutil
from ipaddress import IPv4Address as IPv4
from unittest.mock import Mock

import pytest
from helpers import build_request

from pydhcp import (
    DHCPLease,
    DHCPMessage,
    DHCPOptions,
    DHCPServer,
    DHCPValueError,
    FileLeaseBackend,
    DHCPRequestContext,
    InMemoryLeaseBackend,
    NetworkInterface,
    SocketAddress,
)
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType

UTC = dt.timezone.utc
LATER = dt.datetime(2100, 1, 1, 12, 0, tzinfo=UTC)
DATA = pathlib.Path(__file__).parent / "data"


def _options() -> DHCPOptions:
    options = DHCPOptions()
    options[DHCPOptionCode.ROUTER] = ["192.0.2.1"]
    return options


def _lease(**overrides: object) -> DHCPLease:
    fields: dict[str, object] = dict(
        ip=IPv4("192.0.2.50"), expires=LATER, options=_options()
    )
    fields.update(overrides)
    return DHCPLease(**fields)  # type: ignore[arg-type]


def test_a_lease_is_hashable_and_equal_leases_hash_equal() -> None:
    first, second = _lease(), _lease()
    assert first == second
    assert hash(first) == hash(second)
    assert len({first, second}) == 1
    assert first != _lease(ip=IPv4("192.0.2.51"))
    assert first != _lease(expires=None)
    other = DHCPOptions()
    other[DHCPOptionCode.ROUTER] = ["192.0.2.2"]
    assert first != _lease(options=other)


def test_a_lease_compared_with_another_type_returns_not_implemented() -> None:
    lease = _lease()
    assert lease.__eq__(object()) is NotImplemented
    assert lease != (lease.ip, lease.expires, lease.options)


def test_a_lease_cannot_be_changed() -> None:
    lease = _lease()
    for name in ("ip", "expires", "options"):
        with pytest.raises(AttributeError):
            setattr(lease, name, None)
        with pytest.raises(AttributeError):
            delattr(lease, name)
    with pytest.raises(AttributeError):
        lease.invented = 1  # type: ignore[attr-defined]


def test_the_options_are_copied_in_and_cannot_be_changed_in_place() -> None:
    source = _options()
    lease = _lease(options=source)
    source[DHCPOptionCode.DOMAIN_NAME] = "changed.example"
    assert DHCPOptionCode.DOMAIN_NAME not in lease.options

    with pytest.raises(TypeError):
        lease.options[DHCPOptionCode.DOMAIN_NAME] = "x"
    with pytest.raises(TypeError):
        del lease.options[DHCPOptionCode.ROUTER]
    with pytest.raises(TypeError):
        lease.options.clear()
    with pytest.raises(TypeError):
        lease.options.update({DHCPOptionCode.DOMAIN_NAME: b"x"})
    with pytest.raises(TypeError):
        lease.options.append((DHCPOptionCode.DOMAIN_NAME, "x"))
    with pytest.raises(TypeError):
        lease.options.pop(DHCPOptionCode.ROUTER)
    raw = lease.options[DHCPOptionCode.ROUTER]
    assert not isinstance(raw, bytearray)
    assert dict(lease.options.items(decoded=False)) == {3: b"\xc0\x00\x02\x01"}
    assert lease.options.get(DHCPOptionCode.ROUTER) == [IPv4("192.0.2.1")]


def test_a_copy_of_the_options_is_an_ordinary_bag_to_change() -> None:
    lease = _lease()
    bag = lease.options.copy()
    bag[DHCPOptionCode.DOMAIN_NAME] = "changed.example"
    assert DHCPOptionCode.DOMAIN_NAME in bag
    assert DHCPOptionCode.DOMAIN_NAME not in lease.options
    assert type(bag) is DHCPOptions


def test_options_default_to_none_and_the_expiry_to_no_expiry() -> None:
    lease = DHCPLease(IPv4("192.0.2.50"))
    assert lease.expires is None
    assert len(lease.options) == 0
    assert hash(lease) == hash(DHCPLease(IPv4("192.0.2.50")))


def test_a_lease_has_an_address() -> None:
    with pytest.raises(TypeError):
        DHCPLease()  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        DHCPLease(None, LATER, _options())  # type: ignore[arg-type]
    with pytest.raises(DHCPValueError):
        DHCPLease(IPv4("0.0.0.0"), LATER, _options())
    assert _lease(ip="192.0.2.50").ip == IPv4("192.0.2.50")


def test_the_expiry_is_an_aware_instant_or_none() -> None:
    with pytest.raises(DHCPValueError):
        _lease(expires=dt.datetime(2100, 1, 1))
    for wrong in (float("inf"), 3600, "2100-01-01"):
        with pytest.raises(TypeError):
            _lease(expires=wrong)
    offset = dt.timezone(dt.timedelta(hours=-5))
    local = dt.datetime(2100, 1, 1, 7, 0, tzinfo=offset)
    lease = _lease(expires=local)
    assert lease.expires == local
    assert lease.expires is not None and lease.expires.utcoffset() == dt.timedelta(0)
    assert lease == _lease(expires=local.astimezone(UTC))
    assert hash(lease) == hash(_lease(expires=local.astimezone(UTC)))


def test_repr_names_the_fields() -> None:
    text = repr(_lease())
    assert text.startswith("DHCPLease(ip=IPv4Address('192.0.2.50'), expires=")
    assert "options=DHCPOptions([3])" in text


def test_a_lease_copies_and_pickles_to_an_equal_lease() -> None:
    lease = _lease()
    for twin in (
        copy.copy(lease),
        copy.deepcopy(lease),
        pickle.loads(pickle.dumps(lease)),
    ):
        assert twin == lease
        assert type(twin) is DHCPLease
        assert twin.options.get(DHCPOptionCode.ROUTER) == [IPv4("192.0.2.1")]
        with pytest.raises(TypeError):
            twin.options[DHCPOptionCode.DOMAIN_NAME] = "x"


def test_a_lease_crosses_a_process_boundary() -> None:
    leases = [_lease(), _lease(expires=None), DHCPLease(IPv4("192.0.2.9"))]
    with multiprocessing.get_context("spawn").Pool(1) as pool:
        returned = pool.map(copy.deepcopy, leases)
    assert returned == leases


# --- the backends ----------------------------------------------------------


def test_a_backend_hands_back_leases_with_an_aware_expiry() -> None:
    backend = InMemoryLeaseBackend()
    before = dt.datetime.now(UTC)
    lease = backend.allocate("c", IPv4("192.0.2.50"), 60, _options())
    assert lease is not None and lease.expires is not None
    assert lease.expires.tzinfo is not None
    assert before + dt.timedelta(seconds=59) < lease.expires
    renewed = backend.renew("c", 600)
    assert renewed is not None and renewed.expires is not None
    assert renewed.expires > lease.expires
    assert backend.allocate("forever", IPv4("192.0.2.51"), float("inf")).expires is None  # type: ignore[union-attr]
    assert backend.lookup("forever") is not None


def test_a_lease_file_written_before_the_lease_was_a_value_still_loads(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    shutil.copy(DATA / "lease_file_before_value.json", path)

    backend = FileLeaseBackend(str(path))
    held = backend.lookup("01:00:11:22:33:44:55")
    assert held is not None
    assert held.ip == IPv4("192.0.2.50")
    assert held.expires is not None and held.expires.tzinfo is not None
    # The stored time is naive local time of the year 2121; the same instant.
    assert held.expires > dt.datetime(2121, 10, 29, tzinfo=UTC)
    assert held.expires < dt.datetime(2121, 11, 1, tzinfo=UTC)
    assert held.options.get(DHCPOptionCode.ROUTER) == [IPv4("192.0.2.1")]
    assert held.options.get(DHCPOptionCode.DOMAIN_NAME) == "lab.example"
    forever = backend.lookup("infinite-client")
    assert forever is not None and forever.expires is None


def test_a_lease_file_round_trips_through_the_current_writer(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    shutil.copy(DATA / "lease_file_before_value.json", path)
    backend = FileLeaseBackend(str(path))
    backend.renew("01:00:11:22:33:44:55", 4_000_000_000)
    backend.close()

    again = FileLeaseBackend(str(path))
    renewed = again.lookup("01:00:11:22:33:44:55")
    original = backend.lookup("01:00:11:22:33:44:55")
    assert renewed == original
    assert renewed is not None and renewed.expires is not None
    assert renewed.expires.utcoffset() == dt.timedelta(0)
    forever = again.lookup("infinite-client")
    assert forever is not None and forever.expires is None


def test_an_entry_of_the_file_with_no_address_is_skipped_not_fatal(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    path.write_bytes(
        b'{"a": {"ip": null, "expires": "inf", "options": {}},'
        b' "b": {"ip": "192.0.2.7", "expires": "inf", "options": {}}}'
    )
    backend = FileLeaseBackend(str(path))
    assert backend.lookup("a") is None
    held = backend.lookup("b")
    assert held is not None and held.ip == IPv4("192.0.2.7")
    assert not (tmp_path / "leases.json.corrupt").exists()


# --- the server ------------------------------------------------------------


class _Fixed(DHCPServer):
    def __init__(self, lease: DHCPLease) -> None:
        super().__init__()
        self._fixed = lease

    def acquire_lease(self, client_id, server_id, msg, *, commit=True):  # type: ignore[no-untyped-def]
        return self._fixed


def _context(transport: Mock) -> DHCPRequestContext:
    return DHCPRequestContext(
        transport=transport,
        interface=NetworkInterface("lo", ipaddress.IPv4Interface("127.0.0.1/24")),
        client=SocketAddress("127.0.0.1", 68),
        client_mac=b"\x00\x11\x22\x33\x44\x55",
    )


def _reply(server: DHCPServer, message: DHCPMessage) -> DHCPMessage:
    transport = Mock()
    server.handle(message, _context(transport))
    return DHCPMessage.decode(transport.send.call_args.args[0])


def test_a_lease_with_no_expiry_is_an_infinite_lease_in_the_reply() -> None:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    server = _Fixed(DHCPLease(IPv4("127.0.0.10")))
    reply = _reply(server, build_request(options=options))
    assert reply.yiaddr == IPv4("127.0.0.10")
    assert reply.options.get(DHCPOptionCode.IP_ADDRESS_LEASE_TIME) == 0xFFFFFFFF


def test_an_inform_is_answered_from_options_and_builds_no_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("an INFORM must not build a lease")

    monkeypatch.setattr(DHCPLease, "__init__", refuse)

    class Inform(DHCPServer):
        def get_inform_options(self, server_id, msg):  # type: ignore[no-untyped-def]
            options = DHCPOptions()
            options[DHCPOptionCode.DNS] = [IPv4("9.9.9.9")]
            return options

    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPINFORM
    reply = _reply(Inform(), build_request(options=options, ciaddr=IPv4("127.0.0.1")))
    assert reply.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == (
        DHCPMessageType.DHCPACK
    )
    assert reply.yiaddr == IPv4("0.0.0.0")
    assert DHCPOptionCode.IP_ADDRESS_LEASE_TIME not in reply.options
    assert reply.options.get(DHCPOptionCode.DNS) == [IPv4("9.9.9.9")]
    assert DHCPOptionCode.SERVER_IDENTIFIER in reply.options
