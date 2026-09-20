"""The CLI can persist leases (`server-26`, `cli-surface-19`, `server-28`).

`docs/deployment.md` has always told operators to "keep lease persistence
enabled" and to "mount configuration and lease storage explicitly". The CLI
server always built the default in-memory backend, so the mounted volume stayed
empty and every client renumbered on restart. `FileLeaseBackend` existed and was
documented the whole time; only the CLI could not reach it -- the same shape as
`--per-interface`, which was unreachable for the same reason.
"""

import json
from unittest.mock import patch

import pytest

from pydhcp.cli import Server
from pydhcp.lease import FileLeaseBackend, InMemoryLeaseBackend
from pydhcp.network import IPv4
from pydhcp.options import DhcpOptions


@patch("pydhcp.cli.DhcpServer")
def test_without_the_flag_the_backend_is_still_the_default(mock_server) -> None:
    Server(config=None, listen="127.0.0.1:6767")()
    assert mock_server.call_args.kwargs["lease_backend"] is None


@patch("pydhcp.cli.DhcpServer")
def test_the_flag_selects_a_file_backend(mock_server, tmp_path) -> None:
    path = tmp_path / "leases.json"
    Server(config=None, listen="127.0.0.1:6767", lease_file=str(path))()

    backend = mock_server.call_args.kwargs["lease_backend"]
    assert isinstance(backend, FileLeaseBackend)
    assert backend.filepath == str(path)


@patch("pydhcp.cli.DhcpServer")
def test_the_config_file_can_set_it_too(mock_server, tmp_path) -> None:
    cfg = tmp_path / "pydhcp.json"
    leases = tmp_path / "from-config.json"
    cfg.write_text(
        json.dumps({"server": {"lease_file": str(leases)}}), encoding="utf-8"
    )

    Server(config=str(cfg), listen="127.0.0.1:6767")()

    backend = mock_server.call_args.kwargs["lease_backend"]
    assert isinstance(backend, FileLeaseBackend)
    assert backend.filepath == str(leases)


@patch("pydhcp.cli.DhcpServer")
def test_an_explicit_flag_beats_the_config_file(mock_server, tmp_path) -> None:
    """Same precedence `--listen` already has, for the same reason."""
    cfg = tmp_path / "pydhcp.json"
    cfg.write_text(
        json.dumps({"server": {"lease_file": str(tmp_path / "from-config.json")}}),
        encoding="utf-8",
    )
    wanted = tmp_path / "from-flag.json"

    Server(config=str(cfg), listen="127.0.0.1:6767", lease_file=str(wanted))()

    assert mock_server.call_args.kwargs["lease_backend"].filepath == str(wanted)


@patch("pydhcp.cli.DhcpServer")
def test_lease_file_is_not_reported_as_an_unsupported_config_key(
    mock_server, tmp_path, caplog
) -> None:
    cfg = tmp_path / "pydhcp.json"
    cfg.write_text(
        json.dumps({"server": {"lease_file": str(tmp_path / "l.json")}}),
        encoding="utf-8",
    )
    Server(config=str(cfg), listen="127.0.0.1:6767")()
    assert "unsupported key" not in caplog.text.lower()


def test_a_lease_actually_survives_a_restart(tmp_path) -> None:
    """The end the docs promise, exercised on the backend the flag selects."""
    path = tmp_path / "leases.json"

    first = FileLeaseBackend(str(path))
    first.allocate("01:AA:BB:CC:DD:EE", IPv4("10.0.0.50"), 3600.0, DhcpOptions())
    first.close()

    second = FileLeaseBackend(str(path))
    restored = second.lookup("01:AA:BB:CC:DD:EE")
    assert restored is not None
    assert restored.ip == IPv4("10.0.0.50")

    # The contrast the finding is about: the default backend forgets.
    assert InMemoryLeaseBackend().lookup("01:AA:BB:CC:DD:EE") is None
