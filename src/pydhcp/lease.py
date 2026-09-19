from __future__ import annotations
import datetime as _dt
import json as _json
import os as _os
import tempfile as _tempfile
import time as _time
import threading as _threading
import typing as _ty
from math import inf as _inf

from .network import IPv4
from .options import DhcpOptions
from .constants import INFINITE_LEASE_TIME
from .log import LOGGER


class DhcpLease(_ty.NamedTuple):
    ip: _ty.Optional[IPv4]
    expires: _ty.Union[_dt.datetime, float]
    options: DhcpOptions


class LeaseBackend(_ty.Protocol):
    """Where leases live. `ttl` is seconds, or `math.inf` for no expiry.

    `ttl` is typed `float` rather than `int` because `math.inf` is a float and
    the implementations have always accepted it -- `InMemoryLeaseBackend`
    branches on `ttl != inf`. The Protocol said `int`, so a caller passing the
    infinity the backend was written to handle was a type error. An `int` is
    still accepted: every int is a float to the type system.
    """

    def allocate(
        self,
        client_id: str,
        ip: IPv4,
        ttl: float,
        options: _ty.Optional[DhcpOptions] = None,
    ) -> _ty.Optional[DhcpLease]: ...

    def lookup(self, client_id: str) -> _ty.Optional[DhcpLease]: ...

    def release(self, client_id: str) -> bool: ...

    def renew(self, client_id: str, ttl: float) -> _ty.Optional[DhcpLease]: ...


class InMemoryLeaseBackend:
    """Leases in a dict, guarded by a re-entrant lock.

    The lock makes each operation atomic against the others: a server started
    with `start()` handles packets on a background thread, the async server on a
    worker thread, and one backend can be shared by several of them. It does
    **not** make a caller's compound operation atomic -- "is this address free,
    and if so allocate it" is two calls, and two threads can still interleave
    across them. Hold `self._lock` around such a sequence if that matters.
    """

    def __init__(self) -> None:
        self._leases: _ty.Dict[str, DhcpLease] = {}
        #: Re-entrant: `lookup_by_ip` and `renew` call `lookup` while holding it.
        self._lock = _threading.RLock()

    def allocate(
        self,
        client_id: str,
        ip: IPv4,
        ttl: float,
        options: _ty.Optional[DhcpOptions] = None,
    ) -> _ty.Optional[DhcpLease]:
        expires = (
            _dt.datetime.now() + _dt.timedelta(seconds=ttl) if ttl != _inf else _inf
        )
        lease = DhcpLease(ip=ip, expires=expires, options=options or DhcpOptions())
        with self._lock:
            self._leases[client_id] = lease
        return lease

    def lookup(self, client_id: str) -> _ty.Optional[DhcpLease]:
        with self._lock:
            lease = self._leases.get(client_id)
            if lease is None:
                return None
            # Check expiration
            if (
                lease.expires != _inf
                and isinstance(lease.expires, _dt.datetime)
                and lease.expires < _dt.datetime.now()
            ):
                self._leases.pop(client_id, None)
                return None
            return lease

    def lookup_by_ip(self, ip: IPv4) -> _ty.Optional[str]:
        """Return the client currently holding `ip`, if any.

        Optional backend extension, not part of the `LeaseBackend` Protocol: a
        backend that does not provide it simply skips the allocator's
        already-in-use check. Without it there is no way to ask "who holds this
        address", so a server had no way to avoid handing one client an address
        another client is already using.
        """
        with self._lock:
            for client_id in list(self._leases):
                lease = self.lookup(client_id)
                if lease is not None and lease.ip == ip:
                    return client_id
            return None

    def release(self, client_id: str) -> bool:
        with self._lock:
            if client_id in self._leases:
                del self._leases[client_id]
                return True
            return False

    def renew(self, client_id: str, ttl: float) -> _ty.Optional[DhcpLease]:
        with self._lock:
            lease = self.lookup(client_id)
            if lease is None:
                return None
            expires = (
                _dt.datetime.now() + _dt.timedelta(seconds=ttl) if ttl != _inf else _inf
            )
            renewed = DhcpLease(ip=lease.ip, expires=expires, options=lease.options)
            self._leases[client_id] = renewed
            return renewed


class FileLeaseBackend(InMemoryLeaseBackend):
    def __init__(self, filepath: str = "leases.json") -> None:
        super().__init__()
        self.filepath = filepath
        self._load()

    def _load(self) -> None:
        if not _os.path.exists(self.filepath):
            return
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = _json.load(f)
            for client_id, lease_data in data.items():
                ip_str = lease_data.get("ip")
                ip = IPv4(ip_str) if ip_str else None
                exp_str = lease_data.get("expires")
                if exp_str == "inf":
                    expires: _ty.Union[_dt.datetime, float] = _inf
                elif exp_str:
                    expires = _dt.datetime.fromisoformat(exp_str)
                else:
                    expires = _inf

                opts = DhcpOptions()
                opts_data = lease_data.get("options", {})
                for code_str, val_hex in opts_data.items():
                    code = int(code_str)
                    opts[code] = bytearray.fromhex(val_hex)

                self._leases[client_id] = DhcpLease(
                    ip=ip, expires=expires, options=opts
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
        with self._lock:
            # First clean up expired leases
            for client_id in list(self._leases.keys()):
                self.lookup(client_id)

            data = {}
            for client_id, lease in self._leases.items():
                exp_str = (
                    "inf"
                    if not isinstance(lease.expires, _dt.datetime)
                    else lease.expires.isoformat()
                )
                opts_data = {}
                for code, option in lease.options.items(decoded=False):
                    opts_data[str(int(code))] = option.hex()
                data[client_id] = {
                    "ip": str(lease.ip) if lease.ip else None,
                    "expires": exp_str,
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
        ip: IPv4,
        ttl: float,
        options: _ty.Optional[DhcpOptions] = None,
    ) -> _ty.Optional[DhcpLease]:
        lease = super().allocate(client_id, ip, ttl, options)
        if lease:
            self._save()
        return lease

    def release(self, client_id: str) -> bool:
        res = super().release(client_id)
        if res:
            self._save()
        return res

    def renew(self, client_id: str, ttl: float) -> _ty.Optional[DhcpLease]:
        lease = super().renew(client_id, ttl)
        if lease:
            self._save()
        return lease
