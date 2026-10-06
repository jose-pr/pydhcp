"""`DHCPCaptureWriter`: what a capture records, in one growing file or one file per record."""

from __future__ import annotations

import datetime as _dt
import logging as _logging
import os as _os
import string as _string
import typing as _ty
from types import TracebackType

import pktcap as _pktcap

from ._events import CaptureEvent, serialize_event

LOGGER = _logging.getLogger(__name__)

#: How many distinct files one `per_capture` writer creates unless told otherwise.
#: A file name is made of values the client chooses, so without a bound one
#: unauthenticated sender decides how many files land on the operator's disk.
MAX_CAPTURE_FILES: _ty.Final = 1000

#: The placeholders a `per_capture` filename pattern may name.
FILENAME_FIELDS: _ty.Final = (
    "client_id",
    "timestamp",
    "msg_type",
    "xid",
    "format",
    "index",
)

#: The subset of those that differs between two packets of one capture. A
#: pattern naming none of them resolves to the same file for packets that agree
#: on the rest, and each record then replaces the last.
UNIQUE_FILENAME_FIELDS: _ty.Final = frozenset({"timestamp", "xid", "index"})

#: The fields of a pattern this writer supplies, on top of pktcap's own.
_NAMES: _ty.Final = ("client_id", "msg_type", "xid")

_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)

Target = _ty.Union[str, "_os.PathLike[str]", _ty.BinaryIO]


def _open(
    target: Target, format: _ty.Optional[str], per_capture: bool, max_files: int
) -> _pktcap.CaptureWriter:
    """The pktcap writer, with the refusals that name this library's terms."""

    def build(per_record: bool) -> _pktcap.CaptureWriter:
        return _pktcap.CaptureWriter(
            target,
            format,
            per_record=per_record,
            append=True,
            fields=_NAMES,
            max_files=max_files,
        )

    try:
        return build(per_capture)
    except ImportError:
        if not _pktcap.has_output_format("toml"):
            raise ImportError(
                "TOML output needs the 'toml' extra: pip install \"pydhcp[toml]\""
            ) from None
        raise
    except ValueError:
        if not per_capture:
            try:
                alone = build(True)
            except ValueError:
                pass
            else:
                raise ValueError(
                    f"{alone.format} cannot hold more than one record in a file: "
                    "write one file per record (per-capture) under a filename "
                    "pattern, or use json (one record per line) or yaml (one "
                    "document each)"
                ) from None
        raise


def _fields_of(pattern: str) -> "_ty.Set[str]":
    found: "_ty.Set[str]" = set()
    for _literal, field, spec, _conversion in _string.Formatter().parse(pattern):
        if field is not None:
            found.add(field)
        if spec:
            found |= _fields_of(spec)
    return found


def _datagram(event: CaptureEvent) -> _pktcap.CapturedDatagram:
    """The event as pktcap's datagram: when it was heard and between whom."""
    heard = event.captured_at
    if heard.tzinfo is None:
        heard = heard.replace(tzinfo=_dt.timezone.utc)
    source, destination = event.source, event.destination
    return _pktcap.CapturedDatagram(
        (heard - _EPOCH).total_seconds(),
        (str(source.ip), source.port),
        (str(destination.ip), destination.port),
        b"",
    )


class DHCPCaptureWriter:
    """Writes each captured message as a record, to one growing file or one file per record.

    Called with a `CaptureEvent` it writes one record, so it is a `sink=` for
    `DHCPCapture` and `AsyncDHCPCapture`. A record is exactly what
    `DHCPMessage.to_text(format)` gives (one line of JSON for `json`).

    `target` is a path or a binary stream (`sys.stdout.buffer`; it stays the
    caller's to close). A path is appended to, and its directories are made when
    the first record is written. With `per_capture`, `target` is a filename
    pattern, one file per record, whose placeholders are `FILENAME_FIELDS`.
    `format` is `json`, `yaml`, `toml` or `ini`; `None` takes it from the ending
    of the target's name (`UnsupportedFormatError`, a `ValueError`, when the
    ending names none). `toml` and `ini` hold one record per file, so they need
    `per_capture`, and `toml` needs the `toml` extra.

    `max_files` bounds the distinct files a `per_capture` writer creates: a record
    that needs one more is not written and is counted in `refused`. Not safe to
    share between threads.
    """

    def __init__(
        self,
        target: Target,
        format: _ty.Optional[str] = None,
        *,
        per_capture: bool = False,
        max_files: int = MAX_CAPTURE_FILES,
    ) -> None:
        self._per_capture = per_capture
        self._writer = _open(target, format, per_capture, max_files)
        if self._writer.format not in _pktcap.RECORD_FORMATS:
            self._writer.close()
            raise ValueError(
                f"{self._writer.format} is a capture file format; the formats "
                f"written are {', '.join(_pktcap.RECORD_FORMATS)}"
            )
        if per_capture and not _fields_of(_os.fspath(_ty.cast(str, target))) & (
            UNIQUE_FILENAME_FIELDS
        ):
            LOGGER.warning(
                "The filename pattern %s names none of {timestamp}, {xid} or "
                "{index}, so any two packets agreeing on the rest of it resolve to "
                "the same file and only the last one is kept",
                target,
            )

    @property
    def format(self) -> str:
        """The format being written."""
        return self._writer.format

    @property
    def written(self) -> int:
        """The records written."""
        return self._writer.written

    @property
    def refused(self) -> int:
        """The records a full `max_files` budget turned away."""
        return self._writer.refused

    def __call__(self, event: CaptureEvent) -> None:
        """Write `event`'s record. `OSError` when it cannot be written."""
        text = serialize_event(event, self._writer.format)
        # A lone surrogate in a decoded string is written as its escape, not refused.
        text = text.encode("utf-8", "backslashreplace").decode("utf-8")
        if not self._per_capture and not text.endswith("\n"):
            text += "\n"
        self._writer.write(
            _datagram(event),
            text=text,
            names={
                "client_id": event.client_id,
                "msg_type": event.message_type,
                "xid": event.xid,
            },
        )

    def close(self) -> None:
        """Close the file this writer opened. Harmless when repeated."""
        self._writer.close()

    def __enter__(self) -> "DHCPCaptureWriter":
        return self

    def __exit__(
        self,
        exc_type: _ty.Optional[_ty.Type[BaseException]],
        exc: _ty.Optional[BaseException],
        traceback: _ty.Optional[TracebackType],
    ) -> None:
        self.close()
