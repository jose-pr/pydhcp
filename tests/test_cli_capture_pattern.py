"""`--output-mode per-capture` filename patterns are checked before binding.

The pattern is only ever expanded inside the receive handler, which the
listener wraps in a per-packet `except`. So both defects here are invisible at
startup and expensive afterwards: an unknown placeholder recorded nothing while
logging once per packet, and a pattern with no per-packet component quietly
overwrote every record with the next one.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import logging
import pathlib
from unittest.mock import MagicMock, patch

import pytest

from pydhcp import CaptureEvent, NetworkInterface, RequestContext
from pydhcp.capture import (
    FILENAME_FIELDS,
    UNIQUE_FILENAME_FIELDS,
    validate_filename_pattern,
)
from pydhcp.cli import Capture, _write_capture_record
from pydhcp.network import IPv4, SocketAddress
from pydhcp.packet import DhcpMessageType

from conftest import build_request


def _event(xid: int) -> CaptureEvent:
    message = build_request(DhcpMessageType.DHCPDISCOVER)
    message.xid = xid
    context = RequestContext(
        transport=MagicMock(),
        interface=NetworkInterface("eth0", ipaddress.IPv4Interface("10.0.0.1/24")),
        client=SocketAddress(IPv4("10.0.0.50"), 68),
        client_mac=bytes.fromhex("001122334455"),
    )
    return CaptureEvent(message, context, _dt.datetime.now(tz=_dt.timezone.utc))


def _capture(pattern: "str | pathlib.Path") -> Capture:
    command = Capture()
    command.output = pathlib.Path(str(pattern))
    command.output_mode = "per-capture"
    return command


# --- the check itself -------------------------------------------------------


def test_every_documented_field_is_accepted() -> None:
    pattern = "_".join("{" + name + "}" for name in FILENAME_FIELDS)
    assert validate_filename_pattern(pattern) == frozenset(FILENAME_FIELDS)


def test_a_format_spec_is_not_mistaken_for_a_field_name() -> None:
    """`Formatter().parse` yields the spec separately, so `{client_id:>12}` is
    the field `client_id`, not a field called `client_id:>12`."""
    assert validate_filename_pattern("{client_id:>12}.{format}") == {
        "client_id",
        "format",
    }


def test_doubled_braces_are_literal_text_not_a_field() -> None:
    assert validate_filename_pattern("{{literal}}-{xid}.{format}") == {
        "xid",
        "format",
    }


@pytest.mark.parametrize(
    "pattern",
    [
        "cap_{mac}.json",  # the measured one: plausible, and not a field
        "cap_{}.json",  # positional: format_filename passes keywords only
        "cap_{0}.json",
        "cap_{xid.real}.json",  # attribute access against a plain str value
        "cap_{xid:{mac}}.json",  # one level of nesting is resolved too
    ],
)
def test_an_unfillable_placeholder_is_rejected(pattern: str) -> None:
    """Pre-fix evidence: with no check, each of these compiles at startup and
    `CaptureEvent.format_filename` raises KeyError/IndexError/AttributeError
    from inside the handler -- once for every packet on the segment.
    """
    with pytest.raises(Exception):
        _event(1).format_filename(pattern, "json")

    with pytest.raises(ValueError, match="is not a capture field"):
        validate_filename_pattern(pattern)


def test_the_error_lists_what_is_available() -> None:
    with pytest.raises(ValueError) as info:
        validate_filename_pattern("cap_{mac}.json")
    message = str(info.value)
    assert "{mac}" in message
    for name in FILENAME_FIELDS:
        assert "{" + name + "}" in message


def test_a_malformed_pattern_is_reported_not_raised_as_a_bare_parse_error() -> None:
    with pytest.raises(ValueError, match="Invalid capture filename pattern"):
        validate_filename_pattern("cap_{xid.json")


# --- wiring into the command ------------------------------------------------


def test_capture_rejects_a_bad_pattern_before_binding(tmp_path, capsys) -> None:
    """It must fail here rather than after opening sockets: without the check
    this call binds and then captures nothing at all, which is why the
    assertion is on the exit path and not on a recorded file."""
    command = _capture(tmp_path / "cap_{mac}.{format}")

    with pytest.raises(SystemExit) as info:
        command()

    assert info.value.code == 1
    err = capsys.readouterr().err
    assert "{mac}" in err and "not a capture field" in err


@patch("pydhcp.cli.DhcpCapture")
def test_a_good_pattern_still_reaches_the_capture(mock_capture_cls, tmp_path) -> None:
    mock_capture_cls.return_value = MagicMock(hook_error=None)

    _capture(tmp_path / "{xid}.{format}")()

    assert mock_capture_cls.called


# --- the overwrite warning --------------------------------------------------


def test_a_pattern_with_no_per_packet_field_overwrites(tmp_path) -> None:
    """The behaviour the warning describes, measured: two packets differing
    only in xid, one file left on disk."""
    pattern = str(tmp_path / "capture.{format}")
    state: dict = {"first": True}

    for xid in (0xAAAAAAAA, 0xBBBBBBBB):
        _write_capture_record(
            _event(xid),
            output=pattern,
            output_mode="per-capture",
            packet_format="json",
            state=state,
        )

    assert [p.name for p in tmp_path.iterdir()] == ["capture.json"]


@patch("pydhcp.cli.DhcpCapture")
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
    # fixed pattern stays outside the MAX_PER_CAPTURE_FILES budget, which is
    # what keeps a long run recording at all.
    assert mock_capture_cls.called


@pytest.mark.parametrize("unique", sorted(UNIQUE_FILENAME_FIELDS))
@patch("pydhcp.cli.DhcpCapture")
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
