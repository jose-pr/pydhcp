"""Lease storage: the `DHCPLease` value, the `LeaseBackend` contract and its two stores."""

from __future__ import annotations

from ._lease import DHCPLease
from ._lease_file import FileLeaseBackend
from ._lease_store import InMemoryLeaseBackend, LeaseBackend

__all__ = [
    "DHCPLease",
    "FileLeaseBackend",
    "InMemoryLeaseBackend",
    "LeaseBackend",
]
