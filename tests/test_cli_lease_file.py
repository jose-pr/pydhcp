"""A lease survives a restart on the backend `--lease-file` selects.

`docs/deployment.md` tells operators to keep lease persistence enabled and to
mount lease storage explicitly. That the command selects the file backend is
tested in `integration/test_cli_commands.py`; this is what the backend promises.
"""

from pydhcp.lease import FileLeaseBackend, InMemoryLeaseBackend
from ipaddress import IPv4Address as IPv4
from pydhcp.options import DHCPOptions


def test_a_lease_actually_survives_a_restart(tmp_path) -> None:
    """The end the docs promise, exercised on the backend the flag selects."""
    path = tmp_path / "leases.json"

    first = FileLeaseBackend(str(path))
    first.allocate("01:AA:BB:CC:DD:EE", IPv4("10.0.0.50"), 3600.0, DHCPOptions())
    first.close()

    second = FileLeaseBackend(str(path))
    restored = second.lookup("01:AA:BB:CC:DD:EE")
    assert restored is not None
    assert restored.ip == IPv4("10.0.0.50")

    # The contrast the finding is about: the default backend forgets.
    assert InMemoryLeaseBackend().lookup("01:AA:BB:CC:DD:EE") is None
