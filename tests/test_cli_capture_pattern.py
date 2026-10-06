"""`--per-capture` filename patterns are checked before binding.

The pattern is only ever expanded inside the receive handler, which the
listener wraps in a per-packet `except`. So both defects here are invisible at
startup and expensive afterwards: an unknown placeholder recorded nothing while
logging once per packet, and a pattern with no per-packet component quietly
overwrote every record with the next one. The checks themselves are the writer's
(`tests/test_capture_writer.py`); these tests are that the command makes them
before it binds.
"""

from __future__ import annotations

import logging
import pathlib
from unittest.mock import MagicMock, patch

import pytest

from pydhcp.capture import UNIQUE_FILENAME_FIELDS
from pydhcp.cli import Capture, main


def _capture(pattern: "str | pathlib.Path") -> Capture:
    command = Capture()
    command.output = pathlib.Path(str(pattern))
    command.per_capture = True
    return command


def test_capture_rejects_a_bad_pattern_before_binding(tmp_path, capsys) -> None:
    """It must fail here rather than after opening sockets: without the check
    this call binds and then captures nothing at all, which is why the
    assertion is on the exit path and not on a recorded file."""
    status = main(
        [
            "capture",
            "--output",
            str(tmp_path / "cap_{mac}.{format}"),
            "--per-capture",
        ]
    )

    assert status == 2
    err = capsys.readouterr().err
    assert "{mac}" in err and "not a field" in err


@patch("pydhcp.cli._capture.DHCPCapture")
def test_a_good_pattern_still_reaches_the_capture(mock_capture_cls, tmp_path) -> None:
    mock_capture_cls.return_value = MagicMock(hook_error=None)

    _capture(tmp_path / "{xid}.{format}")()

    assert mock_capture_cls.called


@patch("pydhcp.cli._capture.DHCPCapture")
def test_capture_warns_when_records_will_overwrite(
    mock_capture_cls, tmp_path, caplog
) -> None:
    mock_capture_cls.return_value = MagicMock(hook_error=None)
    command = _capture(tmp_path / "{client_id}.{format}")

    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        command()

    warnings = [
        r for r in caplog.records if "only the last one is kept" in r.getMessage()
    ]
    assert len(warnings) == 1, caplog.text
    # A warning, deliberately, not an error: rewriting one file is also how a
    # fixed pattern stays outside the file budget, which is what keeps a long
    # run recording at all.
    assert mock_capture_cls.called


@pytest.mark.parametrize("unique", sorted(UNIQUE_FILENAME_FIELDS))
@patch("pydhcp.cli._capture.DHCPCapture")
def test_no_warning_when_the_pattern_distinguishes_packets(
    mock_capture_cls, unique, tmp_path, caplog
) -> None:
    mock_capture_cls.return_value = MagicMock(hook_error=None)
    command = _capture(tmp_path / ("{" + unique + "}.{format}"))

    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        command()

    assert not [
        r for r in caplog.records if "only the last one is kept" in r.getMessage()
    ], caplog.text
