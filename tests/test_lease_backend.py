import datetime as _dt
import time
import os
import pytest
from math import inf as _inf

from pydhcp import (
    DhcpLease,
    InMemoryLeaseBackend,
    FileLeaseBackend,
    DhcpOptions,
    IPv4,
    IPv4Address,
)
from pydhcp.options import DhcpOptionCode


def test_in_memory_lease_backend():
    backend = InMemoryLeaseBackend()
    client_id = "test-client-1"
    ip = IPv4("192.168.1.100")
    ttl = 5
    options = DhcpOptions()
    options[DhcpOptionCode.SUBNET_MASK] = IPv4("255.255.255.0")

    # Test allocate
    lease = backend.allocate(client_id, ip, ttl, options)
    assert lease is not None
    assert lease.ip == ip
    assert lease.options.get(DhcpOptionCode.SUBNET_MASK, decode=IPv4Address) == IPv4(
        "255.255.255.0"
    )
    assert isinstance(lease.expires, _dt.datetime)

    # Test lookup
    found = backend.lookup(client_id)
    assert found == lease

    # Test renew
    renewed = backend.renew(client_id, 10)
    assert renewed is not None
    assert renewed.ip == ip
    assert (renewed.expires - _dt.datetime.now()).total_seconds() > 5

    # Test release
    assert backend.release(client_id) is True
    assert backend.lookup(client_id) is None
    assert backend.release(client_id) is False


def test_lease_expiration():
    """An already-elapsed TTL is never handed back by `lookup`.

    The comment said "0 TTL" and the call passed -1, so the boundary the
    comment described -- `expires == now`, the one an off-by-one in the
    comparison lands on -- was the single value never tried. Both are asserted
    now, along with a live lease, so "lookup always returns None" cannot pass.
    """
    ip = IPv4("192.168.1.200")

    for ttl in (0, -1):
        backend = InMemoryLeaseBackend()
        client_id = f"test-client-exp-{ttl}"
        assert backend.allocate(client_id, ip, ttl) is not None
        assert backend.lookup(client_id) is None, ttl

    # A TTL that has not elapsed is still there, so the two assertions above
    # are about expiry rather than about `allocate` silently failing.
    backend = InMemoryLeaseBackend()
    assert backend.allocate("test-client-live", ip, 60) is not None
    live = backend.lookup("test-client-live")
    assert live is not None
    assert live.ip == ip


def test_file_lease_backend(tmp_path):
    filepath = str(tmp_path / "leases.json")
    backend = FileLeaseBackend(filepath=filepath)
    client_id = "test-client-file"
    ip = IPv4("192.168.1.150")
    ttl = 60
    options = DhcpOptions()
    options[DhcpOptionCode.SUBNET_MASK] = IPv4("255.255.255.0")

    # Allocate
    lease = backend.allocate(client_id, ip, ttl, options)
    assert lease is not None
    assert os.path.exists(filepath)

    # Reload from file using a new backend instance
    new_backend = FileLeaseBackend(filepath=filepath)
    loaded = new_backend.lookup(client_id)
    assert loaded is not None
    assert loaded.ip == ip
    assert loaded.options.get(DhcpOptionCode.SUBNET_MASK, decode=IPv4Address) == IPv4(
        "255.255.255.0"
    )

    # Renew
    new_backend.renew(client_id, 120)

    third_backend = FileLeaseBackend(filepath=filepath)
    loaded_renewed = third_backend.lookup(client_id)
    assert loaded_renewed is not None
    assert (loaded_renewed.expires - _dt.datetime.now()).total_seconds() > 60

    # Release
    assert third_backend.release(client_id) is True
    assert third_backend.lookup(client_id) is None

    final_backend = FileLeaseBackend(filepath=filepath)
    assert final_backend.lookup(client_id) is None


# --- durability: the store must survive a crash and say when it cannot ---


def test_lease_file_write_is_atomic(tmp_path):
    """An interrupted write must not destroy the previous contents.

    `open(path, "w")` truncates before writing, so a crash, a full disk or two
    threads saving at once left a half-written file. `_load` then rejected it
    and silently started with no leases, and the next save overwrote the only
    copy -- every binding gone, nothing logged.
    """
    import json

    path = tmp_path / "leases.json"
    backend = FileLeaseBackend(str(path))
    for index in range(20):
        backend.allocate(f"client-{index}", IPv4(f"10.0.0.{index + 1}"), 60)

    # The file is complete and parseable at rest, and the temporary the atomic
    # write goes through is cleaned up rather than accumulating beside it --
    # that second half is what this guards, since the write-then-rename is new.
    assert len(json.loads(path.read_text(encoding="utf-8"))) == 20
    assert [p.name for p in tmp_path.iterdir()] == ["leases.json"]


def test_unreadable_lease_file_is_reported_and_kept(tmp_path, caplog):
    """A corrupt store is data loss; losing it quietly is worse."""
    import logging

    path = tmp_path / "leases.json"
    backend = FileLeaseBackend(str(path))
    backend.allocate("client-a", IPv4("10.0.0.5"), 60)

    text = path.read_text(encoding="utf-8")
    path.write_text(text[: len(text) // 2], encoding="utf-8")  # crash mid-write

    with caplog.at_level(logging.ERROR, logger="pydhcp"):
        recovered = FileLeaseBackend(str(path))

    assert recovered.lookup("client-a") is None
    assert "Could not read lease file" in caplog.text
    # kept for recovery rather than overwritten by the next save
    assert (tmp_path / "leases.json.corrupt").exists()


def test_failed_save_is_reported(tmp_path, caplog):
    """allocate() used to return a lease the caller believed was persisted."""
    import logging

    path = tmp_path / "nosuchdir" / "leases.json"
    backend = FileLeaseBackend(str(path))

    with caplog.at_level(logging.ERROR, logger="pydhcp"):
        lease = backend.allocate("client-a", IPv4("10.0.0.5"), 60)

    assert lease is not None  # still served; the server must not fall over
    assert "Could not persist leases" in caplog.text


def test_concurrent_saves_never_expose_a_partial_file(tmp_path):
    """A reader must always see a whole file.

    Measured before the fix with six threads: 226 reads got invalid JSON.
    """
    import json
    import threading

    path = tmp_path / "leases.json"
    backend = FileLeaseBackend(str(path))
    invalid: list[str] = []

    def saver(n: int) -> None:
        for index in range(40):
            backend.allocate(f"c{n}-{index}", IPv4(f"10.1.{n}.{index + 1}"), 60)
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                pass
            except ValueError as e:
                invalid.append(str(e))

    threads = [threading.Thread(target=saver, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert invalid == [], invalid[:3]
    assert len(json.loads(path.read_text(encoding="utf-8"))) == 240


def test_in_memory_backend_survives_concurrent_use():
    """One backend can be shared by a threaded server and an async one.

    This passes without the lock too: CPython's GIL makes each dict operation
    atomic, so the store does not corrupt today. It is a guard, not a
    reproduction -- it holds the line for a free-threaded build, where that
    guarantee is gone, and for anyone adding a compound operation here.
    """
    import threading

    backend = InMemoryLeaseBackend()
    errors: list[str] = []
    barrier = threading.Barrier(8)

    def hammer(n: int) -> None:
        barrier.wait()
        for index in range(200):
            try:
                backend.allocate(
                    f"c{n}-{index}", IPv4(f"10.0.{n}.{index % 250 + 1}"), 60
                )
                backend.lookup(f"c{n}-{index}")
                backend.lookup_by_ip(IPv4(f"10.0.{n}.{index % 250 + 1}"))
            except Exception as e:  # pragma: no cover - the failure being tested
                errors.append(f"{e.__class__.__name__}: {e}")

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == [], errors[:3]
    assert len(backend._leases) == 8 * 200


# --- a forged-identity flood must not be an unbounded allocation ---


class _SmallStore(InMemoryLeaseBackend):
    MAX_LEASES = 50


def test_lease_store_is_bounded():
    """Nothing about a DHCP client is authenticated.

    Every forged CLIENT_IDENTIFIER used to add an entry for good: memory, file
    size, and -- because FileLeaseBackend rewrites the whole file per mutation
    -- a quadratic amount of blocking I/O on the receive thread. Measured
    before: 4,000 forged identities cost 71 s cumulative and a 465 KiB file.
    """
    backend = _SmallStore()

    accepted = sum(
        backend.allocate(f"forged-{n}", IPv4("10.0.0.1"), 3600) is not None
        for n in range(500)
    )

    assert accepted == backend.MAX_LEASES
    assert len(backend._leases) == backend.MAX_LEASES
    assert backend.refused_while_full == 500 - backend.MAX_LEASES


def test_an_established_lease_is_never_evicted_to_make_room():
    """LRU eviction would be exactly backwards here.

    The forged identities are the *newest*, so evicting least-recently-used
    would drop the long-lived real clients and keep the attacker's entries.
    A full store refuses new clients instead.

    Passes on the unbounded store too, which never evicted anything: this is a
    guard on the eviction policy, not a reproduction of a past failure.
    """
    backend = _SmallStore()
    backend.allocate("real-client", IPv4("10.0.0.9"), 3600)

    for n in range(500):
        backend.allocate(f"forged-{n}", IPv4("10.0.0.1"), 3600)

    assert backend.lookup("real-client") is not None
    # and it can still renew, which is what keeps a working client working
    assert backend.renew("real-client", 3600) is not None


def test_expired_leases_are_reclaimed_before_refusing():
    """A flood's entries expire on their own; the sweep should notice.

    Also a guard rather than a reproduction — an unbounded store never had to
    reclaim anything. It pins that the cap does not turn a transient flood into
    a permanently full server.
    """
    backend = _SmallStore()
    for n in range(backend.MAX_LEASES):
        backend.allocate(f"transient-{n}", IPv4("10.0.0.1"), 0)  # already expiring

    time.sleep(0.01)
    assert backend.allocate("newcomer", IPv4("10.0.0.2"), 3600) is not None
    assert backend.lookup("newcomer") is not None


def test_a_full_store_does_not_flood_the_log(caplog):
    """The condition is reached once per refused packet, and what fills the
    store is a flood -- so logging each one hands the attacker the log as a
    second target."""
    import logging

    backend = _SmallStore()
    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        for n in range(500):
            backend.allocate(f"forged-{n}", IPv4("10.0.0.1"), 3600)

    full_reports = [
        r for r in caplog.records if "Lease store is full" in r.getMessage()
    ]
    assert len(full_reports) == 1, len(full_reports)
    # the count is still exact, it just is not one line each
    assert backend.refused_while_full == 450


# --- write coalescing is opt-in, and off does not change ---


def test_default_still_writes_on_every_mutation(tmp_path):
    """Durability is the property an operator cannot see going wrong.

    Coalescing trades up to an interval of leases on a crash for throughput the
    operator can already measure and that MAX_LEASES already bounds, so it must
    not arrive by default.
    """
    import json

    path = tmp_path / "leases.json"
    backend = FileLeaseBackend(str(path))
    assert backend.SAVE_INTERVAL_SECONDS == 0

    backend.allocate("client-a", IPv4("10.0.0.5"), 60)
    # on disk immediately, with no flush() call
    assert list(json.loads(path.read_text(encoding="utf-8"))) == ["client-a"]


def test_coalescing_defers_writes_and_flush_forces_one(tmp_path):
    """With an interval set, the file is written at most that often."""
    import json

    class Coalesced(FileLeaseBackend):
        SAVE_INTERVAL_SECONDS = 3600.0  # never due during the test

    path = tmp_path / "leases.json"
    backend = Coalesced(str(path))

    backend.allocate("client-a", IPv4("10.0.0.5"), 60)  # first write is due
    backend.allocate("client-b", IPv4("10.0.0.6"), 60)  # this one is not
    assert list(json.loads(path.read_text(encoding="utf-8"))) == ["client-a"]

    backend.flush()
    assert sorted(json.loads(path.read_text(encoding="utf-8"))) == [
        "client-a",
        "client-b",
    ]

    # flush with nothing pending is a no-op, not an error
    backend.flush()


def test_close_flushes_so_a_clean_shutdown_loses_nothing(tmp_path):
    import json

    class Coalesced(FileLeaseBackend):
        SAVE_INTERVAL_SECONDS = 3600.0

    path = tmp_path / "leases.json"
    with Coalesced(str(path)) as backend:
        backend.allocate("client-a", IPv4("10.0.0.5"), 60)
        backend.allocate("client-b", IPv4("10.0.0.6"), 60)

    assert sorted(json.loads(path.read_text(encoding="utf-8"))) == [
        "client-a",
        "client-b",
    ]
