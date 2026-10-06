"""The `LeaseBackend` contract, run against both shipped backends.

Each test states one sentence of the contract in the shipped header, with the
clock passed in: a backend's `_now` is the one seam, and no test sleeps.
"""

from __future__ import annotations

import datetime as dt
import pathlib
import shutil
import typing as _ty
from ipaddress import IPv4Address as IPv4

import pytest

from pydhcp import DHCPOptions, FileLeaseBackend, InMemoryLeaseBackend
from pydhcp.lease import LeaseBackend
from pydhcp.options import DHCPOptionCode

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
DATA = pathlib.Path(__file__).parent / "data"
HOLD = 120.0


class _Clocked:
    """A backend whose clock the test steps."""

    now = T0

    def _now(self) -> dt.datetime:
        return self.now

    def step(self, seconds: float) -> None:
        self.now = self.now + dt.timedelta(seconds=seconds)


class _Memory(_Clocked, InMemoryLeaseBackend):
    MAX_LEASES = 6


class _File(_Clocked, FileLeaseBackend):
    MAX_LEASES = 6


@pytest.fixture(params=["memory", "file"])
def backend(request: pytest.FixtureRequest, tmp_path: pathlib.Path) -> _ty.Any:
    if request.param == "memory":
        return _Memory()
    return _File(str(tmp_path / "leases.json"))


def _ip(n: int) -> IPv4:
    return IPv4(f"10.0.0.{n}")


def test_a_backend_satisfies_the_protocol(backend) -> None:
    held: LeaseBackend = backend
    assert held is backend


def test_an_offer_is_held_until_the_end_of_the_hold(backend) -> None:
    """LeaseBackend.offer: an offered lease whose `expires` is the end of the hold."""
    lease = backend.offer("a", _ip(5), HOLD)
    assert lease is not None
    assert lease.offered is True
    assert lease.ip == _ip(5)
    assert lease.expires == T0 + dt.timedelta(seconds=HOLD)
    assert backend.lookup("a") == lease


def test_an_offer_carries_the_options_it_was_given(backend) -> None:
    options = DHCPOptions()
    options[DHCPOptionCode.SUBNET_MASK] = IPv4("255.255.255.0")
    lease = backend.offer("a", _ip(5), HOLD, options)
    assert lease is not None
    assert lease.options.get(DHCPOptionCode.SUBNET_MASK) == IPv4("255.255.255.0")


@pytest.mark.parametrize("hold", [0, -1, float("inf"), float("nan")])
def test_an_offer_is_held_for_a_finite_positive_time(backend, hold) -> None:
    with pytest.raises(ValueError):
        backend.offer("a", _ip(5), hold)
    assert backend.lookup("a") is None


def test_an_offer_for_an_address_another_client_is_offered_is_refused(backend) -> None:
    assert backend.offer("a", _ip(5), HOLD) is not None
    assert backend.offer("b", _ip(5), HOLD) is None
    assert backend.lookup("b") is None
    assert backend.lookup_by_ip(_ip(5)) == "a"


def test_an_offer_for_an_address_another_client_is_bound_to_is_refused(backend) -> None:
    assert backend.allocate("a", _ip(5), 3600) is not None
    assert backend.offer("b", _ip(5), HOLD) is None


def test_an_offer_that_is_not_committed_lapses_and_frees_its_address(backend) -> None:
    """The hold is a bound: an unanswered offer is an expired record."""
    backend.offer("a", _ip(5), HOLD)

    backend.step(HOLD - 1)
    assert backend.lookup("a") is not None
    assert backend.offer("b", _ip(5), HOLD) is None

    backend.step(1)  # `expires` is reached: the record is over
    assert backend.lookup("a") is None
    assert backend.lookup_by_ip(_ip(5)) is None
    taken = backend.offer("b", _ip(5), HOLD)
    assert taken is not None and taken.offered


def test_a_commit_turns_the_offer_into_a_binding(backend) -> None:
    backend.offer("a", _ip(5), HOLD)
    backend.step(30)

    bound = backend.commit("a", 3600)

    assert bound is not None
    assert bound.offered is False
    assert bound.ip == _ip(5)
    assert bound.expires == backend.now + dt.timedelta(seconds=3600)
    assert backend.lookup("a") == bound
    # past the hold, the binding is still there
    backend.step(HOLD)
    assert backend.lookup("a") == bound


def test_a_commit_keeps_the_options_of_the_offer(backend) -> None:
    options = DHCPOptions()
    options[DHCPOptionCode.SUBNET_MASK] = IPv4("255.255.255.0")
    backend.offer("a", _ip(5), HOLD, options)
    bound = backend.commit("a", 3600)
    assert bound is not None
    assert bound.options.get(DHCPOptionCode.SUBNET_MASK) == IPv4("255.255.255.0")


def test_an_infinite_commit_never_expires(backend) -> None:
    backend.offer("a", _ip(5), HOLD)
    bound = backend.commit("a", float("inf"))
    assert bound is not None and bound.expires is None


def test_a_commit_with_no_offer_is_refused(backend) -> None:
    assert backend.commit("nobody", 3600) is None


def test_a_commit_after_the_hold_is_refused(backend) -> None:
    backend.offer("a", _ip(5), HOLD)
    backend.step(HOLD)
    assert backend.commit("a", 3600) is None
    assert backend.lookup("a") is None


def test_a_commit_of_a_binding_is_refused(backend) -> None:
    backend.allocate("a", _ip(5), 3600)
    assert backend.commit("a", 7200) is None
    assert backend.lookup("a").expires == T0 + dt.timedelta(seconds=3600)


def test_an_offer_is_not_renewed(backend) -> None:
    backend.offer("a", _ip(5), HOLD)
    assert backend.renew("a", 3600) is None
    held = backend.lookup("a")
    assert held is not None and held.offered


def test_a_binding_is_renewed_to_ttl_from_now(backend) -> None:
    backend.allocate("a", _ip(5), 60)
    backend.step(30)
    renewed = backend.renew("a", 3600)
    assert renewed is not None
    assert renewed.offered is False
    assert renewed.expires == backend.now + dt.timedelta(seconds=3600)


def test_release_drops_an_offer_and_frees_the_address(backend) -> None:
    backend.offer("a", _ip(5), HOLD)
    assert backend.release("a") is True
    assert backend.lookup("a") is None
    assert backend.release("a") is False
    assert backend.offer("b", _ip(5), HOLD) is not None


def test_release_drops_a_binding(backend) -> None:
    backend.allocate("a", _ip(5), 3600)
    assert backend.release("a") is True
    assert backend.lookup("a") is None
    assert backend.lookup_by_ip(_ip(5)) is None


def test_an_offer_to_a_client_that_holds_the_address_returns_the_binding(
    backend,
) -> None:
    bound = backend.allocate("a", _ip(5), 3600)
    assert backend.offer("a", _ip(5), HOLD) == bound
    assert backend.lookup("a") == bound


def test_an_offer_never_replaces_a_binding_on_another_address(backend) -> None:
    bound = backend.allocate("a", _ip(5), 3600)
    assert backend.offer("a", _ip(6), HOLD) is None
    assert backend.lookup("a") == bound
    assert backend.lookup_by_ip(_ip(6)) is None


def test_a_new_offer_replaces_the_clients_outstanding_one(backend) -> None:
    backend.offer("a", _ip(5), HOLD)
    second = backend.offer("a", _ip(6), HOLD)
    assert second is not None and second.ip == _ip(6)
    assert backend.lookup("a") == second
    assert backend.lookup_by_ip(_ip(5)) is None
    assert backend.offer("b", _ip(5), HOLD) is not None


def test_allocate_is_an_offer_and_its_commit(backend) -> None:
    bound = backend.allocate("a", _ip(5), 3600)
    assert bound is not None
    assert bound.offered is False
    assert bound.expires == T0 + dt.timedelta(seconds=3600)
    assert backend.lookup("a") == bound


def test_allocate_refuses_an_address_another_client_holds(backend) -> None:
    backend.offer("a", _ip(5), HOLD)
    assert backend.allocate("b", _ip(5), 3600) is None
    assert backend.lookup("b") is None
    assert backend.lookup("a").offered is True


def test_allocate_replaces_what_the_client_held(backend) -> None:
    backend.allocate("a", _ip(5), 3600)
    moved = backend.allocate("a", _ip(6), 3600)
    assert moved is not None and moved.ip == _ip(6)
    assert backend.lookup_by_ip(_ip(5)) is None
    assert backend.lookup_by_ip(_ip(6)) == "a"


def test_offers_count_toward_the_bound_on_the_store(backend) -> None:
    for n in range(backend.MAX_LEASES):
        assert backend.offer(f"c{n}", _ip(10 + n), HOLD) is not None
    assert backend.offer("one-too-many", _ip(40), HOLD) is None
    assert backend.refused_while_full == 1
    # An established client is not evicted for it, and a lapsed offer makes room.
    backend.step(HOLD)
    assert backend.offer("one-too-many", _ip(40), HOLD) is not None


def test_lookup_by_ip_does_not_walk_the_store(backend) -> None:
    """The address index answers a miss and a hit with one `lookup`."""
    for n in range(backend.MAX_LEASES):
        backend.offer(f"c{n}", _ip(10 + n), HOLD)
    calls: _ty.List[str] = []
    real = backend.lookup
    backend.lookup = lambda client_id: (calls.append(client_id), real(client_id))[1]

    assert backend.lookup_by_ip(_ip(200)) is None
    assert backend.lookup_by_ip(_ip(12)) == "c2"

    assert calls == ["c2"]


def test_the_address_index_follows_every_change(backend) -> None:
    backend.allocate("a", _ip(5), 60)
    backend.renew("a", 120)
    assert backend.lookup_by_ip(_ip(5)) == "a"
    backend.step(121)
    assert backend.lookup_by_ip(_ip(5)) is None
    assert backend.allocate("b", _ip(5), 60) is not None
    assert backend.lookup_by_ip(_ip(5)) == "b"


# --- the lease file --------------------------------------------------------


def test_the_file_records_the_state_of_each_lease(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "leases.json"
    first = _File(str(path))
    first.offer("offered", _ip(5), HOLD)
    first.allocate("bound", _ip(6), 3600)  # saves, and writes the offer with it
    first.close()

    again = _File(str(path))
    assert again.lookup("offered").offered is True
    assert again.lookup("bound").offered is False
    assert again.lookup_by_ip(_ip(5)) == "offered"
    again.step(HOLD)
    assert again.lookup("offered") is None
    assert again.lookup("bound") is not None


def test_an_offer_alone_writes_nothing(tmp_path: pathlib.Path) -> None:
    """A forged DISCOVER must not cost a whole-file rewrite."""
    path = tmp_path / "leases.json"
    store = _File(str(path))
    store.offer("a", _ip(5), HOLD)
    store.release("a")
    assert not path.exists()


def test_a_lease_file_written_before_the_offered_state_loads_as_bindings(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    shutil.copy(DATA / "lease_file_before_state.json", path)

    backend = FileLeaseBackend(str(path))

    held = backend.lookup("01:00:11:22:33:44:55")
    assert held is not None
    assert held.offered is False
    assert held.ip == IPv4("192.0.2.50")
    assert held.expires == dt.datetime(2121, 10, 30, 19, 41, 14, 361954, tzinfo=UTC)
    forever = backend.lookup("infinite-client")
    assert forever is not None and forever.offered is False and forever.expires is None
    assert backend.lookup_by_ip(IPv4("192.0.2.50")) == "01:00:11:22:33:44:55"


def test_an_older_file_is_rewritten_with_the_state_field(
    tmp_path: pathlib.Path,
) -> None:
    import json

    path = tmp_path / "leases.json"
    shutil.copy(DATA / "lease_file_before_state.json", path)
    backend = FileLeaseBackend(str(path))
    backend.renew("01:00:11:22:33:44:55", 7200)
    backend.close()

    written = json.loads(path.read_text(encoding="utf-8"))
    assert {entry["state"] for entry in written.values()} == {"bound"}


def test_a_file_with_an_unknown_state_is_set_aside_as_unreadable(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    path.write_bytes(
        b'{"a": {"ip": "192.0.2.7", "expires": "inf", "state": "maybe", "options": {}}}'
    )
    backend = FileLeaseBackend(str(path))
    assert backend.lookup("a") is None
    assert (tmp_path / "leases.json.corrupt").exists()
