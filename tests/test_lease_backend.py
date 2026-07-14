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
    assert lease.options.get(DhcpOptionCode.SUBNET_MASK, decode=IPv4Address) == IPv4("255.255.255.0")
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
    backend = InMemoryLeaseBackend()
    client_id = "test-client-exp"
    ip = IPv4("192.168.1.200")
    
    # Allocate with 0 TTL (expires immediately or next lookup)
    backend.allocate(client_id, ip, -1)
    assert backend.lookup(client_id) is None


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
    assert loaded.options.get(DhcpOptionCode.SUBNET_MASK, decode=IPv4Address) == IPv4("255.255.255.0")

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
