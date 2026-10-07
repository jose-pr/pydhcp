"""The lease file: what a load keeps, when a change reaches the disk, and the clock it is read on.

Every assertion about durability is on the bytes of a real file in pytest's
temporary directory, read back after each step, never on the object that wrote it.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import pathlib
import shutil
import threading
import time
import typing as _ty
from ipaddress import IPv4Address as IPv4

import pytest

from pydhcp import FileLeaseBackend
from pydhcp.options import DHCPOptionCode

UTC = dt.timezone.utc
DATA = pathlib.Path(__file__).parent / "data"
#: The 2026 clock changes of US Eastern time, as instants.
SPRING = dt.datetime(2026, 3, 8, 7, 0, tzinfo=UTC)  # 02:00 EST -> 03:00 EDT
FALL = dt.datetime(2026, 11, 1, 6, 0, tzinfo=UTC)  # 02:00 EDT -> 01:00 EST
T0 = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)


class _Clocked(FileLeaseBackend):
    """A file backend whose clock the test sets."""

    now = T0

    def _now(self) -> dt.datetime:
        return self.now


def _on_disk(path: pathlib.Path) -> "dict[str, _ty.Any]":
    return json.loads(path.read_bytes().decode("utf-8"))  # type: ignore[no-any-return]


def _entry(ip: str, expires: dt.datetime, state: str = "bound") -> "dict[str, _ty.Any]":
    return {"ip": ip, "expires": expires.isoformat(), "state": state, "options": {}}


def _write(path: pathlib.Path, entries: "dict[str, _ty.Any]") -> bytes:
    data = json.dumps(entries).encode("utf-8")
    path.write_bytes(data)
    return data


# --- a load is all or nothing ---------------------------------------------------


def _file_with_one_bad_entry(path: pathlib.Path) -> bytes:
    entries = {
        f"good-{n}": _entry(f"10.0.0.{n}", T0 + dt.timedelta(hours=1))
        for n in range(10, 15)
    }
    entries["bad"] = {"ip": "not-an-address", "expires": "inf", "options": {}}
    entries.update(
        {
            f"later-{n}": _entry(f"10.0.1.{n}", T0 + dt.timedelta(hours=1))
            for n in range(10, 15)
        }
    )
    return _write(path, entries)


def test_a_bad_entry_leaves_the_store_empty_and_the_file_set_aside(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    original = _file_with_one_bad_entry(path)

    backend = _Clocked(str(path))
    assert all(backend.lookup(f"good-{n}") is None for n in range(10, 15))
    assert all(backend.lookup(f"later-{n}") is None for n in range(10, 15))

    # The only copy of the state is kept byte for byte, and nothing is written
    # in its place until something changes.
    assert (tmp_path / "leases.json.corrupt").read_bytes() == original
    assert not path.exists()

    backend.allocate("new-client", IPv4("10.0.0.99"), 60)
    assert list(_on_disk(path)) == ["new-client"]


def test_two_damaged_files_are_both_kept(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "leases.json"
    first = b"{ truncated"
    path.write_bytes(first)
    _Clocked(str(path)).lookup("x")
    second = b"[1, 2, 3]"
    path.write_bytes(second)
    _Clocked(str(path)).lookup("x")
    third = _file_with_one_bad_entry(path)
    _Clocked(str(path)).lookup("x")

    assert (tmp_path / "leases.json.corrupt").read_bytes() == first
    assert (tmp_path / "leases.json.corrupt.1").read_bytes() == second
    assert (tmp_path / "leases.json.corrupt.2").read_bytes() == third


def test_a_file_over_max_leases_is_an_error_naming_both_numbers(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    class Small(_Clocked):
        MAX_LEASES = 3

    path = tmp_path / "leases.json"
    original = _write(
        path,
        {
            f"c{n}": _entry(f"10.0.0.{n}", T0 + dt.timedelta(hours=1))
            for n in range(1, 5)
        },
    )
    with caplog.at_level(logging.ERROR, logger="pydhcp"):
        backend = Small(str(path))
        assert backend.lookup("c1") is None
    assert "4 leases" in caplog.text and "MAX_LEASES (3)" in caplog.text
    assert (tmp_path / "leases.json.corrupt").read_bytes() == original


def test_leases_that_have_run_out_do_not_count_toward_max_leases(
    tmp_path: pathlib.Path,
) -> None:
    class Small(_Clocked):
        MAX_LEASES = 3

    entries = {
        f"c{n}": _entry(f"10.0.0.{n}", T0 + dt.timedelta(hours=1)) for n in range(1, 4)
    }
    entries["old"] = _entry("10.0.0.9", T0 - dt.timedelta(hours=1))
    path = tmp_path / "leases.json"
    _write(path, entries)

    backend = Small(str(path))
    assert all(backend.lookup(f"c{n}") is not None for n in range(1, 4))
    assert backend.lookup("old") is None
    assert not (tmp_path / "leases.json.corrupt").exists()


def test_an_address_held_by_two_clients_is_a_bad_file(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "leases.json"
    original = _write(
        path,
        {
            "a": _entry("10.0.0.5", T0 + dt.timedelta(hours=1)),
            "b": _entry("10.0.0.5", T0 + dt.timedelta(hours=1)),
        },
    )
    backend = _Clocked(str(path))
    assert backend.lookup("a") is None and backend.lookup("b") is None
    assert (tmp_path / "leases.json.corrupt").read_bytes() == original


# --- the file's form: every earlier one still loads ------------------------------


def test_the_file_is_written_with_unix_line_endings_and_an_offset(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    _Clocked(str(path)).allocate("a", IPv4("10.0.0.5"), 3600)
    raw = path.read_bytes()
    assert b"\r" not in raw
    assert _on_disk(path)["a"]["expires"] == "2026-10-06T13:00:00+00:00"


def test_the_current_form_loads_and_rewrites_to_the_same_content(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    shutil.copy(DATA / "lease_file_with_state.json", path)
    before = _on_disk(path)

    backend = FileLeaseBackend(str(path))
    offered = backend.lookup("offered-client")
    assert offered is not None and offered.offered
    bound = backend.lookup("01:00:11:22:33:44:55")
    assert bound is not None and not bound.offered
    assert bound.options.get(DHCPOptionCode.SUBNET_MASK) == IPv4("255.255.255.0")
    forever = backend.lookup("infinite-client")
    assert forever is not None and forever.expires is None

    backend.release("last")
    backend.close()
    after = _on_disk(path)
    assert after == {k: v for k, v in before.items() if k != "last"}


@pytest.mark.parametrize(
    "fixture", ["lease_file_before_state.json", "lease_file_before_value.json"]
)
def test_a_file_written_by_an_earlier_form_still_loads(
    tmp_path: pathlib.Path, fixture: str
) -> None:
    path = tmp_path / "leases.json"
    shutil.copy(DATA / fixture, path)
    backend = FileLeaseBackend(str(path))
    held = [client for client in _on_disk(path) if backend.lookup(client) is not None]
    assert held, "nothing loaded"
    assert not (tmp_path / "leases.json.corrupt").exists()


# --- a change reaches the disk within the interval ------------------------------


class _Coalescing(FileLeaseBackend):
    SAVE_INTERVAL_SECONDS = 0.1


def _wait_for(
    predicate: "_ty.Callable[[], bool]", what: str, seconds: float = 5.0
) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out after {seconds} s waiting for {what}")


def _names_on_disk(path: pathlib.Path) -> "list[str]":
    """The clients in the file, or nothing while the file is being replaced.

    Windows refuses a read for an instant while the rename over it is under way.
    """
    try:
        return sorted(_on_disk(path))
    except (OSError, ValueError):
        return []


def _timers() -> int:
    return sum(t.name == "pydhcp-lease-save" for t in threading.enumerate())


def test_a_change_made_inside_the_interval_is_written_by_the_timer(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    backend = _Coalescing(str(path))
    backend.allocate("first", IPv4("10.0.0.10"), 3600)  # due at once
    assert list(_on_disk(path)) == ["first"]

    backend.allocate("second", IPv4("10.0.0.11"), 3600)  # inside the interval
    backend.allocate("third", IPv4("10.0.0.12"), 3600)
    # Nothing else happens: no further change, no flush, no close.
    _wait_for(
        lambda: _names_on_disk(path) == ["first", "second", "third"],
        "the timer to write the two changes",
    )
    _wait_for(lambda: _timers() == 0, "the timer thread to end")


def test_flush_writes_at_once_and_cancels_the_timer(tmp_path: pathlib.Path) -> None:
    class Slow(FileLeaseBackend):
        SAVE_INTERVAL_SECONDS = 3600.0

    path = tmp_path / "leases.json"
    backend = Slow(str(path))
    backend.allocate("first", IPv4("10.0.0.10"), 3600)
    backend.allocate("second", IPv4("10.0.0.11"), 3600)
    assert list(_on_disk(path)) == ["first"]
    assert _timers() == 1

    backend.flush()
    assert sorted(_on_disk(path)) == ["first", "second"]
    # A cancelled timer's thread ends a moment after cancel() returns.
    _wait_for(lambda: _timers() == 0, "the timer thread to end")


def test_close_writes_what_is_pending_and_leaves_no_timer(
    tmp_path: pathlib.Path,
) -> None:
    class Slow(FileLeaseBackend):
        SAVE_INTERVAL_SECONDS = 3600.0

    path = tmp_path / "leases.json"
    with Slow(str(path)) as backend:
        backend.allocate("first", IPv4("10.0.0.10"), 3600)
        backend.allocate("second", IPv4("10.0.0.11"), 3600)
    assert sorted(_on_disk(path)) == ["first", "second"]
    # A cancelled timer's thread ends a moment after cancel() returns.
    _wait_for(lambda: _timers() == 0, "the timer thread to end")


def test_the_default_writes_every_change_and_starts_no_thread(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "leases.json"
    backend = FileLeaseBackend(str(path))
    for n in range(3):
        backend.allocate(f"c{n}", IPv4(f"10.0.0.{10 + n}"), 3600)
        assert len(_on_disk(path)) == n + 1
    # A cancelled timer's thread ends a moment after cancel() returns.
    _wait_for(lambda: _timers() == 0, "the timer thread to end")


# --- expiry is an instant: a clock change does not move it -----------------------


@pytest.mark.parametrize("change", [SPRING, FALL], ids=["spring-forward", "fall-back"])
def test_every_binding_is_known_across_a_2026_clock_change(
    tmp_path: pathlib.Path, change: dt.datetime
) -> None:
    """The store's clock steps across a transition; no time zone is read.

    Each lease is written as an instant with an offset, so the file says the
    same thing whatever the host's clock does, and a second backend that reads
    it at the stepped time finds every binding with its real time left.
    """
    minute = dt.timedelta(minutes=1)
    path = tmp_path / "leases.json"
    store = _Clocked(str(path))
    store.now = change - 50 * minute
    store.allocate("a", IPv4("10.0.0.1"), 3600)  # runs out 10 minutes after
    store.now = change - minute
    store.allocate("b", IPv4("10.0.0.2"), 3600)  # 59 minutes after
    store.allocate("c", IPv4("10.0.0.3"), 86400)  # a day, less a minute, after

    written = _on_disk(path)
    assert written["a"]["expires"] == (change + 10 * minute).isoformat()
    assert written["b"]["expires"] == (change + 59 * minute).isoformat()
    assert written["c"]["expires"] == (change + 1439 * minute).isoformat()
    assert str(written["a"]["expires"]).endswith("+00:00")

    for stepped, expect in [
        (change - dt.timedelta(seconds=1), {"a": 601, "b": 3541, "c": 86341}),
        (change + dt.timedelta(seconds=1), {"a": 599, "b": 3539, "c": 86339}),
        (change + 11 * minute, {"b": 2880, "c": 85680}),
        (change + 60 * minute, {"c": 82740}),
        (change + 1440 * minute, {}),
    ]:
        reader = _Clocked(str(path))
        reader.now = stepped
        left = {}
        for client in written:
            held = reader.lookup(client)
            if held is not None:
                assert held.expires is not None
                left[client] = (held.expires - stepped).total_seconds()
        assert left == expect, stepped


def _set_time_zone(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    tzset = getattr(time, "tzset", None)
    if tzset is None:
        pytest.skip(
            "time.tzset does not exist on this platform, so the process time zone "
            "cannot be changed here; the stepped-clock test above runs everywhere"
        )
    monkeypatch.setenv("TZ", name)
    tzset()


@pytest.fixture
def restore_time_zone() -> _ty.Iterator[None]:
    yield
    tzset = getattr(time, "tzset", None)
    if tzset is not None:
        import os

        os.environ.pop("TZ", None)
        tzset()


@pytest.mark.parametrize(
    "writer_zone, reader_zone",
    [
        ("America/New_York", "Pacific/Auckland"),
        ("Pacific/Auckland", "America/New_York"),
        ("UTC", "America/New_York"),
    ],
)
def test_a_file_means_the_same_instants_in_every_time_zone(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    restore_time_zone: None,
    writer_zone: str,
    reader_zone: str,
) -> None:
    path = tmp_path / "leases.json"
    _set_time_zone(monkeypatch, writer_zone)
    store = _Clocked(str(path))
    store.now = SPRING - dt.timedelta(minutes=30)
    store.allocate("a", IPv4("10.0.0.5"), 3600)
    written = path.read_bytes()
    assert _on_disk(path)["a"]["expires"] == "2026-03-08T07:30:00+00:00"

    _set_time_zone(monkeypatch, reader_zone)
    reader = _Clocked(str(path))
    reader.now = SPRING + dt.timedelta(seconds=1)
    held = reader.lookup("a")
    assert held is not None
    assert held.expires == dt.datetime(2026, 3, 8, 7, 30, tzinfo=UTC)
    assert (held.expires - reader.now).total_seconds() == 1799
    assert path.read_bytes() == written


def test_a_time_with_no_offset_in_an_older_file_is_read_as_local_time_once(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    restore_time_zone: None,
) -> None:
    _set_time_zone(monkeypatch, "America/New_York")
    path = tmp_path / "leases.json"
    _write(
        path, {"a": {"ip": "10.0.0.5", "expires": "2026-03-08T01:30:00", "options": {}}}
    )
    backend = _Clocked(str(path))
    backend.now = dt.datetime(2026, 3, 8, 6, 0, tzinfo=UTC)
    held = backend.lookup("a")
    assert held is not None
    # 01:30 EST, half an hour before the spring change, is 06:30 UTC.
    assert held.expires == dt.datetime(2026, 3, 8, 6, 30, tzinfo=UTC)
    backend.renew("a", 3600)
    assert _on_disk(path)["a"]["expires"].endswith("+00:00")
    del backend


def test_the_lease_time_a_client_is_told_never_exceeds_the_policy_across_a_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Through `handle()`, on the stepped clock: option 51 is real time, at most a day."""
    import ipaddress
    from unittest.mock import Mock

    from helpers import CHADDR, build_request
    from pydhcp import (
        DHCPMessage,
        DHCPRequestContext,
        DHCPServer,
        NetworkInterface,
        SocketAddress,
    )
    from pydhcp.lease import InMemoryLeaseBackend
    from pydhcp.packet import DHCPMessageType

    served = ipaddress.IPv4Interface("10.0.0.1/24")
    # private: the name is looked up in the module that reads it, so the host or the clock can be stood for
    monkeypatch.setattr(
        "pydhcp.server._policy._servable_interface",
        lambda _ip: NetworkInterface("eth0", served),
    )

    class Backend(InMemoryLeaseBackend):
        now = SPRING

        def _now(self) -> dt.datetime:
            return self.now

    backend = Backend()
    server = DHCPServer(lease_backend=backend)

    def ask(kind: DHCPMessageType, at: dt.datetime, **options: _ty.Any) -> int:
        """The lease time in the reply, with the clock set to `at`."""
        backend.now = at
        message = build_request(kind)
        message.options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = 86400
        for name, value in options.items():
            message.options[DHCPOptionCode[name]] = value
        context = DHCPRequestContext(
            transport=Mock(send=Mock(return_value=1)),
            interface=NetworkInterface("eth0", served),
            client=SocketAddress("10.0.0.50", 68),
            client_mac=CHADDR,
            received_at=at,
            received_monotonic=1000.0,
        )
        server.handle(message, context)
        data = context.transport.send.call_args.args[0]
        reply = DHCPMessage.decode(data)
        return int(reply.options.get(DHCPOptionCode.IP_ADDRESS_LEASE_TIME))

    minute = dt.timedelta(minutes=1)
    address = ipaddress.IPv4Address("10.0.0.50")
    for change in (SPRING, FALL):
        offered = ask(
            DHCPMessageType.DHCPDISCOVER, change - minute, REQUESTED_IP=address
        )
        acked = ask(
            DHCPMessageType.DHCPREQUEST,
            change - minute,
            REQUESTED_IP=address,
            SERVER_IDENTIFIER=served.ip,
        )
        assert offered == 86400 and acked == 86400
        # 61 real seconds on, across the change, the binding has 61 real seconds
        # less to run: the advertised time is that, and never above the policy.
        again = ask(
            DHCPMessageType.DHCPDISCOVER,
            change + dt.timedelta(seconds=1),
            REQUESTED_IP=address,
        )
        assert again == 86400 - 61 <= server.MAX_LEASE_SECONDS
        backend.release(build_request().get_client_id())
