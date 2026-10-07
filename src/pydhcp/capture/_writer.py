"""`DHCPCaptureWriter`: what a capture records, as records or as a capture file."""

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

    def build(per_record: bool, append: bool = False) -> _pktcap.CaptureWriter:
        return _pktcap.CaptureWriter(
            target,
            format,
            per_record=per_record,
            append=append,
            fields=_NAMES,
            max_files=max_files,
        )

    try:
        writer = build(per_capture)
        # Building opens nothing. A record file is appended to; a capture file
        # cannot be, and a second run replaces it.
        return build(per_capture, True) if _is_record(writer) else writer
    except ImportError as error:
        # pktcap names its own extra; a pydhcp user installs it through pydhcp's.
        said = str(error)
        if 'pip install "pktcap[' in said:
            raise ImportError(said.replace('"pktcap[', '"pydhcp[')) from None
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


def _is_record(writer: _pktcap.CaptureWriter) -> bool:
    return writer.format in _pktcap.RECORD_FORMATS


def _fields_of(pattern: str) -> "_ty.Set[str]":
    found: "_ty.Set[str]" = set()
    for _literal, field, spec, _conversion in _string.Formatter().parse(pattern):
        if field is not None:
            found.add(field)
        if spec:
            found |= _fields_of(spec)
    return found


def _datagram(event: CaptureEvent, payload: bytes) -> _pktcap.CapturedDatagram:
    """The event as pktcap's datagram: when it was heard, between whom, and what."""
    heard = event.captured_at
    if heard.tzinfo is None:
        heard = heard.replace(tzinfo=_dt.timezone.utc)
    source, destination = event.source, event.destination
    return _pktcap.CapturedDatagram(
        (heard - _EPOCH).total_seconds(),
        (str(source.ip), source.port),
        (str(destination.ip), destination.port),
        payload,
    )


class DHCPCaptureWriter:
    """Writes each captured message, as a record or as a datagram in a capture file.

    Called with a `CaptureEvent` it writes one item, so it is a `sink=` for
    `DHCPCapture` and `AsyncDHCPCapture`. A record is exactly what
    `DHCPMessage.to_text(format)` gives (one line of JSON for `json`). A capture
    file (`pcap`, `pcapng`) holds the datagram as the client sent it, which is the
    event's `payload`: an event with none is a `ValueError`, because a message
    encoded again is padded and is not that packet.

    `target` is a path or a binary stream (`sys.stdout.buffer`; it stays the
    caller's to close). A record file is appended to and a capture file replaced
    when the first item is written, and the directories above a path are made then.
    With `per_capture`, `target` is a filename pattern, one file per item, whose
    placeholders are `FILENAME_FIELDS`. `format` is one of `pktcap.OUTPUT_FORMATS`
    (`pcap`, `pcapng`, `json`, `yaml`, `toml`, `ini`); `None` takes it from the
    ending of the target's name (`UnsupportedFormatError`, a `ValueError`, when
    the ending names none). `toml` and `ini` hold one record per file, so they need
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
        self._records = _is_record(self._writer)
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
        """The records, or datagrams, written."""
        return self._writer.written

    @property
    def refused(self) -> int:
        """The records a full `max_files` budget turned away."""
        return self._writer.refused

    def __call__(self, event: CaptureEvent) -> None:
        """Write `event`. `OSError` when it cannot be written.

        `ValueError` for a capture file when the event has no `payload`.
        """
        names = {
            "client_id": event.client_id,
            "msg_type": event.message_type,
            "xid": event.xid,
        }
        if not self._records:
            payload = event.payload
            if payload is None:
                raise ValueError(
                    f"a {self._writer.format} capture holds the datagram a client "
                    "sent, and this event has no payload"
                )
            self._writer.write(_datagram(event, payload), names=names)
            return
        text = serialize_event(event, self._writer.format)
        # A lone surrogate in a decoded string is written as its escape, not refused.
        text = text.encode("utf-8", "backslashreplace").decode("utf-8")
        if not self._per_capture and not text.endswith("\n"):
            text += "\n"
        self._writer.write(_datagram(event, b""), text=text, names=names)

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
