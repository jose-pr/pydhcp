"""The one rate limit on every log line a sender can provoke.

A warning on a path any host on the segment can drive hands that host the log
as a second target. `_LogLimit` logs the first occurrence of a reason, then at
most one line per interval for that reason, carrying the running count. The
exact totals live in `DHCPMetrics`; this only bounds what is written.

It reads no clock: the caller passes `now` (seconds on any monotonic scale), the
listener's stamp for a datagram.
"""

from __future__ import annotations

import logging as _logging
import threading as _threading
import typing as _ty

#: Seconds between two lines for one reason.
LOG_INTERVAL_SECONDS = 60.0

#: Distinct reasons tracked. Reasons are strings the code chooses (an exception
#: class at most), so the table is small; the cap is what keeps it so if a
#: handler raises an unbounded variety of classes. Past it, new reasons share
#: one entry.
MAX_REASONS = 128

_OVERFLOW = "other reasons"

#: Longest sender-written text a log line carries.
BRIEF_OCTETS = 80


def _brief(text: object, limit: int = BRIEF_OCTETS) -> str:
    """Text a sender wrote, made safe to log: escaped, and cut at `limit`.

    Control characters, line breaks and non-ASCII become backslash escapes, so a
    value cannot forge a second log line or write to a terminal.
    """
    escaped = str(text).encode("unicode_escape", "backslashreplace").decode("ascii")
    if len(escaped) <= limit:
        return escaped
    return f"{escaped[:limit]}... ({len(escaped)} characters)"


class _LogLimit:
    """Counts occurrences per reason and decides which ones are written."""

    def __init__(
        self,
        interval: float = LOG_INTERVAL_SECONDS,
        max_reasons: int = MAX_REASONS,
    ) -> None:
        self._interval = interval
        self._max_reasons = max_reasons
        self._lock = _threading.Lock()
        #: (logger name, reason) -> [occurrences, when last written]
        self._entries: "dict[tuple[str, str], list[float]]" = {}

    def tracked(self) -> int:
        """How many entries the table holds: at most `max_reasons` plus the shared one."""
        with self._lock:
            return len(self._entries)

    def count(self, logger: _logging.Logger, reason: str) -> int:
        """How many times `reason` occurred on `logger`, written or not."""
        with self._lock:
            entry = self._entries.get((logger.name, reason))
            if entry is None:
                entry = self._entries.get((logger.name, _OVERFLOW))
            return int(entry[0]) if entry is not None else 0

    def log(
        self,
        logger: _logging.Logger,
        level: int,
        reason: str,
        message: str,
        *args: object,
        now: float,
        exc_info: bool = False,
    ) -> bool:
        """Count one occurrence of `reason`; write it when one is due.

        `message` and `args` are the logging module's, formatted only when the
        line is written. The first occurrence of a reason is written, as is the
        first one after `interval` seconds since the last line, with the running
        count appended. A traceback (`exc_info`) goes with the first occurrence
        only. Returns whether a line was written.
        """
        key = (logger.name, reason)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                if len(self._entries) >= self._max_reasons:
                    key = (logger.name, _OVERFLOW)
                    entry = self._entries.get(key)
                if entry is None:
                    entry = self._entries[key] = [0, now - self._interval - 1.0]
            entry[0] += 1
            occurrences = int(entry[0])
            if now - entry[1] < self._interval:
                return False
            entry[1] = now
        suffix = ""
        if occurrences > 1:
            suffix = (
                f" [{occurrences} occurrences so far; at most one line per "
                f"{self._interval:g} s]"
            )
        logger.log(
            level,
            message + suffix,
            *args,
            exc_info=True if exc_info and occurrences == 1 else None,
        )
        return True
