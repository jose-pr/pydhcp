"""The file-backed lease store (public as `pydhcp.lease`)."""

from __future__ import annotations

import logging as _logging
import datetime as _dt
import ipaddress as _ipaddress
import json as _json
import os as _os
import tempfile as _tempfile
import time as _time
import typing as _ty

from ._lease import DHCPLease
from ._lease_store import InMemoryLeaseBackend
from .options import DHCPOptions

__all__ = ["FileLeaseBackend"]

LOGGER = _logging.getLogger(__name__)


class FileLeaseBackend(InMemoryLeaseBackend):
    """Leases persisted to JSON.

    Every mutation writes the whole file by default, which is O(store) each
    time. `SAVE_INTERVAL_SECONDS` above zero coalesces instead: a mutation marks
    the store dirty and the file is rewritten at most that often, with
    `flush()` and `close()` forcing one.

    Off by default deliberately. Coalescing trades a property the operator
    cannot see going wrong -- up to an interval of leases lost on a crash -- for
    one they can already measure and which `MAX_LEASES` already bounds. A
    default that silently gives up durability for throughput is the wrong way
    round; a deployment that wants the trade can ask for it.
    """

    #: Seconds to coalesce writes over. 0 writes on every mutation.
    SAVE_INTERVAL_SECONDS: float = 0.0

    def __init__(self, filepath: str) -> None:
        # Constructing reads nothing: the file is read by `open()`, which the
        # first lease operation (and `with`) calls.
        self._loaded = False
        super().__init__()
        self.filepath = filepath
        self._dirty = False
        self._last_save = float("-inf")

    @property
    def _leases(self) -> _ty.Dict[str, DHCPLease]:
        if not self._loaded:
            self.open()
        return self._store

    @_leases.setter
    def _leases(self, value: _ty.Dict[str, DHCPLease]) -> None:
        self._store = value

    def open(self) -> None:
        """Read the lease file, once. A missing file is an empty store.

        An unreadable file is moved aside as `<path>.corrupt`, as before, and the
        store starts empty. Called by the first lease operation if the caller
        has not, and by `with`.
        """
        with self._lock:
            if self._loaded:
                return
            self._loaded = True
            self._load()

    def flush(self) -> None:
        """Write now if anything is pending. Safe to call when nothing is."""
        with self._lock:
            if self._dirty:
                self._write_now()

    def close(self) -> None:
        """Flush before going away, so a clean shutdown loses nothing."""
        self.flush()

    def __enter__(self) -> "FileLeaseBackend":
        self.open()
        return self

    def __exit__(self, *_exc: _ty.Any) -> None:
        self.close()

    def _load(self) -> None:
        if not _os.path.exists(self.filepath):
            return
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = _json.load(f)
            for client_id, lease_data in data.items():
                ip_str = lease_data.get("ip")
                if not ip_str:
                    LOGGER.warning(
                        f"Skipping the lease of {client_id} in {self.filepath}: "
                        "it has no address"
                    )
                    continue
                state = lease_data.get("state", "bound")
                if state not in ("offered", "bound"):
                    raise ValueError(f"unknown lease state {state!r}")
                exp_str = lease_data.get("expires")
                expires: _ty.Optional[_dt.datetime] = None
                if exp_str and exp_str != "inf":
                    expires = _dt.datetime.fromisoformat(exp_str)
                    if expires.utcoffset() is None:
                        # Written as naive local time; the same instant.
                        expires = expires.astimezone()

                opts = DHCPOptions()
                opts_data = lease_data.get("options", {})
                for code_str, val_hex in opts_data.items():
                    code = int(code_str)
                    opts[code] = bytearray.fromhex(val_hex)

                self._put(
                    client_id,
                    DHCPLease(
                        ip=_ipaddress.IPv4Address(ip_str),
                        expires=expires,
                        options=opts,
                        offered=state == "offered",
                    ),
                )
        except Exception as e:
            # Swallowing this started the server with an empty store and then
            # overwrote the file on the next save, so a truncated lease file
            # destroyed every lease with nothing said. Keep the bad file: it is
            # the only copy of that state, and it is recoverable by hand.
            LOGGER.error(
                f"Could not read lease file {self.filepath}: "
                f"{e.__class__.__name__} | {e}"
            )
            self._quarantine_unreadable_file()

    def _quarantine_unreadable_file(self) -> None:
        damaged = f"{self.filepath}.corrupt"
        try:
            _os.replace(self.filepath, damaged)
        except Exception as e:  # pragma: no cover - unreadable and unmovable
            LOGGER.error(
                f"Could not set aside the unreadable lease file: "
                f"{e.__class__.__name__} | {e}"
            )
            return
        LOGGER.error(
            f"Moved the unreadable lease file to {damaged}; starting with no "
            "leases. Recover it by hand rather than losing the bindings."
        )

    def _save(self) -> None:
        """Record that the store changed, and write if a write is due."""
        with self._lock:
            self._dirty = True
            if self.SAVE_INTERVAL_SECONDS <= 0:
                self._write_now()
                return
            if _time.monotonic() - self._last_save >= self.SAVE_INTERVAL_SECONDS:
                self._write_now()

    def _write_now(self) -> None:
        with self._lock:
            self._dirty = False
            self._last_save = _time.monotonic()
            # First clean up expired leases
            for client_id in list(self._leases.keys()):
                self.lookup(client_id)

            data = {}
            for client_id, lease in self._leases.items():
                exp_str = "inf" if lease.expires is None else lease.expires.isoformat()
                opts_data = {}
                for code, option in lease.options.items(decoded=False):
                    opts_data[str(int(code))] = option.hex()
                data[client_id] = {
                    "ip": str(lease.ip),
                    "expires": exp_str,
                    "state": "offered" if lease.offered else "bound",
                    "options": opts_data,
                }
            self._write_atomically(data)

    #: Attempts at the final rename, and the pause between them.
    REPLACE_ATTEMPTS = 5
    REPLACE_BACKOFF_SECONDS = 0.02

    def _replace_with_retry(self, temp_path: str) -> None:
        """Rename the finished file over the target, retrying a held lock.

        POSIX renames over an open file happily. Windows refuses while any
        handle is open, and a search indexer, a backup agent or an antivirus
        scanner opening a file it just saw written is ordinary there -- so the
        first attempt can fail for a reason that is gone milliseconds later.
        """
        for attempt in range(self.REPLACE_ATTEMPTS):
            try:
                _os.replace(temp_path, self.filepath)
                return
            except PermissionError:
                if attempt == self.REPLACE_ATTEMPTS - 1:
                    raise
                _time.sleep(self.REPLACE_BACKOFF_SECONDS * (attempt + 1))

    def _write_atomically(self, data: _ty.Dict[str, _ty.Any]) -> None:
        """Write the whole file or none of it.

        `open(path, "w")` truncates first, so an interrupted write -- a crash, a
        full disk, two threads saving at once -- left a half-written file that
        `_load` then rejected, silently discarding every lease. Writing a
        temporary file in the same directory and renaming it over the target
        makes the replacement atomic for readers on POSIX and Windows alike, and
        leaves the previous contents intact if anything fails.
        """
        directory = _os.path.dirname(_os.path.abspath(self.filepath))
        handle = None
        temp_path = None
        try:
            fd, temp_path = _tempfile.mkstemp(
                dir=directory, prefix=".leases-", suffix=".tmp"
            )
            handle = _os.fdopen(fd, "w", encoding="utf-8")
            _json.dump(data, handle, indent=2)
            handle.flush()
            _os.fsync(handle.fileno())
            handle.close()
            handle = None
            self._replace_with_retry(temp_path)
            temp_path = None
        except Exception as e:
            # Not raised: a lease store that cannot be written must not take the
            # server down mid-exchange. But it is no longer silent -- the old
            # code returned a lease the caller believed was persisted.
            LOGGER.error(
                f"Could not persist leases to {self.filepath}: "
                f"{e.__class__.__name__} | {e}"
            )
        finally:
            if handle is not None:
                try:
                    handle.close()
                except Exception:  # pragma: no cover - already failing
                    pass
            if temp_path is not None and _os.path.exists(temp_path):
                try:
                    _os.remove(temp_path)
                except Exception:  # pragma: no cover - best effort
                    pass

    def allocate(
        self,
        client_id: str,
        ip: _ipaddress.IPv4Address,
        ttl: float,
        options: _ty.Optional[DHCPOptions] = None,
    ) -> _ty.Optional[DHCPLease]:
        lease = super().allocate(client_id, ip, ttl, options)
        if lease:
            self._save()
        return lease

    def offer(
        self,
        client_id: str,
        ip: _ipaddress.IPv4Address,
        hold_seconds: float,
        options: _ty.Optional[DHCPOptions] = None,
    ) -> _ty.Optional[DHCPLease]:
        # Not saved: an offer is short and means nothing after a restart, and a
        # whole-file rewrite per forged DISCOVER would be a cost the sender
        # chooses. A later save writes whichever offers are still held.
        return super().offer(client_id, ip, hold_seconds, options)

    def commit(self, client_id: str, ttl: float) -> _ty.Optional[DHCPLease]:
        lease = super().commit(client_id, ttl)
        if lease:
            self._save()
        return lease

    def release(self, client_id: str) -> bool:
        dropped = self._release(client_id)
        if dropped is not None and not dropped.offered:
            self._save()
        return dropped is not None

    def renew(self, client_id: str, ttl: float) -> _ty.Optional[DHCPLease]:
        lease = super().renew(client_id, ttl)
        if lease:
            self._save()
        return lease
