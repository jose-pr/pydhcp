"""The time a protocol core is handed, and the one place it is read.

A driver reads both clocks once when a datagram arrives and stamps the
`DHCPRequestContext` with them; a core reads the stamp and calls no clock of
its own. A hook invoked outside a driver, with a context built by hand, gets
the driver's reading through `_Timed._read_clock`.
"""

from __future__ import annotations

import datetime as _dt
import time as _time
import typing as _ty

if _ty.TYPE_CHECKING:
    from .listener._receive import DHCPRequestContext


class _Instant(_ty.NamedTuple):
    """One moment on the two clocks the library uses.

    `utc` is wall-clock time (timezone-aware); `monotonic` is `time.monotonic()`
    seconds. A lease's expiry is wall-clock (`wall`, naive local time, the form
    `DHCPLease.expires` holds); the relay's pending table and the decline
    quarantine are monotonic.
    """

    utc: _dt.datetime
    monotonic: float

    @property
    def wall(self) -> _dt.datetime:
        return self.utc.astimezone().replace(tzinfo=None)


def _read() -> _Instant:
    return _Instant(_dt.datetime.now(tz=_dt.timezone.utc), _time.monotonic())


class _Timed:
    """What a core needs to get the time of one exchange."""

    if _ty.TYPE_CHECKING:

        def _read_clock(self) -> _Instant: ...

    def _instant(self, context: "DHCPRequestContext") -> _Instant:
        """The context's stamp; the driver's reading when it carries none."""
        received_at = context.received_at
        received_monotonic = context.received_monotonic
        if received_at is None or received_monotonic is None:
            return self._read_clock()
        return _Instant(received_at, received_monotonic)
