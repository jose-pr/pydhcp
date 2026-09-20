"""Per-module loggers under the `pydhcp` package logger, and no stderr by default.

`pydhcp.log` used to be a single flat `pydhcp` logger that every module shared,
so nothing could be turned down by module and nothing said which module a line
came from. And with no handler anywhere on the chain, `logging.lastResort`
printed WARNING and above straight to stderr -- a library writing to the
console of an application that never configured logging.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import logging
import subprocess
import sys
from unittest.mock import MagicMock

import pydhcp.capture as capture_module
import pydhcp.cli as cli_module
from pydhcp import CaptureEvent, NetworkInterface, RequestContext
from pydhcp.log import LOGGER
from pydhcp.network import IPv4, SocketAddress
from pydhcp.packet import DhcpMessageType

from conftest import build_request


def _event() -> CaptureEvent:
    context = RequestContext(
        transport=MagicMock(),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress(IPv4("10.0.0.50"), 68),
        client_mac=bytes.fromhex("001122334455"),
    )
    return CaptureEvent(
        build_request(DhcpMessageType.DHCPDISCOVER),
        context,
        _dt.datetime.now(tz=_dt.timezone.utc),
    )


def test_module_loggers_are_children_of_the_package_logger() -> None:
    assert capture_module.LOGGER.name == "pydhcp.capture"
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
        "import pydhcp.log as log\n"
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
        "import logging, pydhcp.log as log\n"
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

    class Result:
        stdout = "chatter"
        stderr = "boom"
        returncode = 3

    monkeypatch.setattr(cli_module.subprocess, "run", lambda *a, **k: Result())

    hook = cli_module._load_capture_hook(str(command), "json", fail_fast=False)
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
    assert failure.name == "pydhcp.cli"
    assert by_message["Capture hook command output"].name == "pydhcp.cli"
