from __future__ import annotations
import datetime as _dt
import json as _json
import os as _os
import typing as _ty
from math import inf as _inf

from .netutils import IPv4
from .options import DhcpOptions
from .contants import INIFINITE_LEASE_TIME


class DhcpLease(_ty.NamedTuple):
    ip: _ty.Optional[IPv4]
    expires: _ty.Union[_dt.datetime, float]
    options: DhcpOptions


class LeaseBackend(_ty.Protocol):
    def allocate(
        self,
        client_id: str,
        ip: IPv4,
        ttl: int,
        options: _ty.Optional[DhcpOptions] = None,
    ) -> _ty.Optional[DhcpLease]:
        ...

    def lookup(self, client_id: str) -> _ty.Optional[DhcpLease]:
        ...

    def release(self, client_id: str) -> bool:
        ...

    def renew(self, client_id: str, ttl: int) -> _ty.Optional[DhcpLease]:
        ...


class InMemoryLeaseBackend:
    def __init__(self) -> None:
        self._leases: _ty.Dict[str, DhcpLease] = {}

    def allocate(
        self,
        client_id: str,
        ip: IPv4,
        ttl: int,
        options: _ty.Optional[DhcpOptions] = None,
    ) -> _ty.Optional[DhcpLease]:
        expires = _dt.datetime.now() + _dt.timedelta(seconds=ttl) if ttl != _inf else _inf
        lease = DhcpLease(ip=ip, expires=expires, options=options or DhcpOptions())
        self._leases[client_id] = lease
        return lease

    def lookup(self, client_id: str) -> _ty.Optional[DhcpLease]:
        lease = self._leases.get(client_id)
        if lease is None:
            return None
        # Check expiration
        if lease.expires != _inf and isinstance(lease.expires, _dt.datetime) and lease.expires < _dt.datetime.now():
            self._leases.pop(client_id, None)
            return None
        return lease

    def release(self, client_id: str) -> bool:
        if client_id in self._leases:
            del self._leases[client_id]
            return True
        return False

    def renew(self, client_id: str, ttl: int) -> _ty.Optional[DhcpLease]:
        lease = self.lookup(client_id)
        if lease is None:
            return None
        expires = _dt.datetime.now() + _dt.timedelta(seconds=ttl) if ttl != _inf else _inf
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

                self._leases[client_id] = DhcpLease(ip=ip, expires=expires, options=opts)
        except Exception:
            pass

    def _save(self) -> None:
        # First clean up expired leases
        for client_id in list(self._leases.keys()):
            self.lookup(client_id)

        data = {}
        for client_id, lease in self._leases.items():
            exp_str = "inf" if not isinstance(lease.expires, _dt.datetime) else lease.expires.isoformat()
            opts_data = {}
            for code, option in lease.options.items(decoded=False):
                opts_data[str(int(code))] = option.hex()
            data[client_id] = {
                "ip": str(lease.ip) if lease.ip else None,
                "expires": exp_str,
                "options": opts_data,
            }
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                _json.dump(data, f, indent=2)
        except Exception:
            pass

    def allocate(
        self,
        client_id: str,
        ip: IPv4,
        ttl: int,
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

    def renew(self, client_id: str, ttl: int) -> _ty.Optional[DhcpLease]:
        lease = super().renew(client_id, ttl)
        if lease:
            self._save()
        return lease
