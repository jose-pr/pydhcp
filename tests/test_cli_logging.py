"""Per-module loggers under the `pydhcp` package logger, and no stderr by default.

`pydhcp._log` used to be a single flat `pydhcp` logger that every module shared,
so nothing could be turned down by module and nothing said which module a line
came from. And with no handler anywhere on the chain, `logging.lastResort`
printed WARNING and above straight to stderr -- a library writing to the
console of an application that never configured logging.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import logging

import pytest
import subprocess
import sys
from unittest.mock import MagicMock

# The module that logs for the capture; a logger is named for its module.
import pydhcp.capture._core as capture_module
import pydhcp.cli as cli_module
from pydhcp.cli import (
    _capture_hook as capture_hook_module,
)  # patches the hook's subprocess call
from pydhcp import CaptureEvent, NetworkInterface, DHCPRequestContext

# the logging setup is not public
from pydhcp._log import LOGGER
from ipaddress import IPv4Address as IPv4
from pydhcp import SocketAddress
from pydhcp.packet import DHCPMessageType

from conftest import build_request


def _event() -> CaptureEvent:
    context = DHCPRequestContext(
        transport=MagicMock(),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress(IPv4("10.0.0.50"), 68),
        client_mac=bytes.fromhex("001122334455"),
    )
    return CaptureEvent(
        build_request(DHCPMessageType.DHCPDISCOVER),
        context,
        _dt.datetime.now(tz=_dt.timezone.utc),
    )


def test_module_loggers_are_children_of_the_package_logger() -> None:
    assert capture_module.LOGGER.name == "pydhcp.capture._core"
    assert cli_module.LOGGER.name == "pydhcp.cli"
    for logger in (capture_module.LOGGER, cli_module.LOGGER):
        assert logger is not LOGGER
        assert logger.parent is LOGGER or logger.name.startswith("pydhcp.")


def test_a_module_logger_still_answers_to_the_package_level() -> None:
    """`-v` and `--loglevel pydhcp:DEBUG` set the level on `pydhcp` itself, so
    the split is only useful if the children inherit it."""
    previous = LOGGER.level
    try:
        LOGGER.setLevel(logging.DEBUG)
        assert capture_module.LOGGER.isEnabledFor(logging.DEBUG)
        LOGGER.setLevel(logging.ERROR)
        assert not capture_module.LOGGER.isEnabledFor(logging.WARNING)
    finally:
        LOGGER.setLevel(previous)


def test_one_module_can_be_silenced_without_the_rest() -> None:
    """The thing a flat logger could not do at all."""
    previous_package, previous_module = LOGGER.level, capture_module.LOGGER.level
    try:
        LOGGER.setLevel(logging.DEBUG)
        capture_module.LOGGER.setLevel(logging.CRITICAL)
        assert not capture_module.LOGGER.isEnabledFor(logging.WARNING)
        assert cli_module.LOGGER.isEnabledFor(logging.WARNING)
    finally:
        LOGGER.setLevel(previous_package)
        capture_module.LOGGER.setLevel(previous_module)


def test_the_package_logger_carries_a_null_handler() -> None:
    assert any(isinstance(h, logging.NullHandler) for h in LOGGER.handlers)


def test_importing_pydhcp_does_not_write_to_stderr() -> None:
    """Measured against the pre-fix tree: with no handler on the chain,
    `logging.lastResort` put the record on stderr of an embedding application
    that had never configured logging. Run out of process because pytest's own
    logging plugin installs handlers that would mask it.

    The flip side is a deliberate behaviour change for embedders: a WARNING
    that used to appear by itself now needs `logging.basicConfig()`.
    """
    program = (
        "import logging\n"
        "import pydhcp._log as log\n"
        "log.LOGGER.warning('should not reach the console')\n"
        "logging.getLogger('pydhcp.capture').warning('nor should this')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stderr == "", result.stderr
    assert result.stdout == "", result.stdout


def test_a_configured_application_still_sees_the_records() -> None:
    """A NullHandler must not swallow anything -- it only stops `lastResort`."""
    program = (
        "import logging, pydhcp._log as log\n"
        "logging.basicConfig(level=logging.WARNING)\n"
        "logging.getLogger('pydhcp.capture').warning('visible')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "visible" in result.stderr
    assert "pydhcp.capture" in result.stderr


def test_the_capture_hook_logs_through_the_module_logger(
    tmp_path, monkeypatch, caplog
) -> None:
    """`cli.py` re-fetched `logging.getLogger("pydhcp")` by name on the command
    hook path, twice, with the module's own LOGGER already imported. The record
    naming `pydhcp.cli` is what says the re-fetch is gone."""
    command = tmp_path / "hook"
    command.write_text("", encoding="utf-8")
    command.chmod(0o755)  # a command hook must be executable on POSIX

    class Result:
        stdout = "chatter"
        stderr = "boom"
        returncode = 3

    monkeypatch.setattr(capture_hook_module.subprocess, "run", lambda *a, **k: Result())

    hook = capture_hook_module._load_capture_hook(str(command), "json", fail_fast=False)
    assert hook is not None

    previous = LOGGER.level
    try:
        LOGGER.setLevel(logging.DEBUG)
        with caplog.at_level(logging.DEBUG, logger="pydhcp"):
            hook(_event())
    finally:
        LOGGER.setLevel(previous)

    by_message = {r.getMessage().split(":")[0]: r for r in caplog.records}
    failure = by_message["Capture hook command failed (3)"]
    assert failure.name == "pydhcp.cli._capture_hook"
    assert by_message["Capture hook command output"].name == "pydhcp.cli._capture_hook"


def _pydhcp_modules() -> "list[str]":
    import pkgutil

    import pydhcp

    return sorted(
        info.name
        for info in pkgutil.walk_packages(pydhcp.__path__, "pydhcp.")
        if not info.name.endswith("__main__")
    )


def test_every_module_that_logs_does_so_on_its_own_logger() -> None:
    """A record names the module that emitted it, and a level set on
    `pydhcp.<module>` silences that module and nothing else."""
    import importlib

    wrong = {}
    seen = 0
    for name in _pydhcp_modules():
        module = importlib.import_module(name)
        logger = module.__dict__.get("LOGGER")
        if not isinstance(logger, logging.Logger) or name == "pydhcp._log":
            continue
        seen += 1
        if logger.name != name:
            wrong[name] = logger.name
    assert wrong == {}, wrong
    assert seen >= 15


def test_silencing_the_server_leaves_the_listener_audible(caplog) -> None:
    """A server warning and a listener warning, one logger apart."""
    from pydhcp import DHCPServer

    # the arrival-interface lookup is not public
    from pydhcp.listener import _interfaces as interfaces
    from pydhcp.packet import DHCPOpcode

    reply = build_request(DHCPMessageType.DHCPOFFER)
    reply.op = DHCPOpcode.BOOTREPLY
    server = DHCPServer(listen=("127.0.0.1", 0))

    def emit() -> None:
        server.handle(reply, _event().context)
        interfaces._warn_synthetic.cache_clear()
        interfaces._warn_synthetic("192.0.2.77")

    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        emit()
    loud = {record.name for record in caplog.records}
    assert "pydhcp.server._handlers" in loud
    assert "pydhcp.listener._interfaces" in loud

    caplog.clear()
    quiet = logging.getLogger("pydhcp.server")
    previous = quiet.level
    quiet.setLevel(logging.CRITICAL)
    try:
        with caplog.at_level(logging.WARNING, logger="pydhcp"):
            emit()
    finally:
        quiet.setLevel(previous)
    names = {record.name for record in caplog.records}
    assert "pydhcp.server._handlers" not in names
    assert "pydhcp.listener._interfaces" in names


@pytest.fixture(autouse=True)
def _fresh_command_hook_limit(monkeypatch) -> None:
    from pydhcp.listener._limit import _LogLimit

    monkeypatch.setattr(capture_hook_module, "_FAILURES", _LogLimit())


def test_a_command_hook_that_fails_every_time_is_logged_once_per_interval(
    tmp_path, monkeypatch, caplog
) -> None:
    command = tmp_path / "hook"
    command.write_text("", encoding="utf-8")
    command.chmod(0o755)

    class Result:
        stdout = ""
        stderr = "boom\n" * 200
        returncode = 3

    monkeypatch.setattr(capture_hook_module.subprocess, "run", lambda *a, **k: Result())
    hook = capture_hook_module._load_capture_hook(str(command), "json", fail_fast=False)
    assert hook is not None
    with caplog.at_level(logging.ERROR, logger="pydhcp"):
        for _ in range(5):
            hook(_event())
    failures = [r for r in caplog.records if "command failed" in r.getMessage()]
    assert len(failures) == 1
    assert "\n" not in failures[0].getMessage()
    assert len(failures[0].getMessage()) < 600
