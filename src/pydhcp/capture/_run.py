"""A capture run's sink: write each event, count it, and keep why the run had to stop."""

from __future__ import annotations

import typing as _ty

from ._events import CaptureEvent
from ._writer import DHCPCaptureWriter


class CaptureRun:
    """The sink of a run that writes events and ends itself.

    Called with each accepted event it writes it through `writer`, and calls `stop`
    (once, from the sink) when `count` events are written, when a write fails, or
    when the writer's file budget is spent. Why it stopped is left in `failure` (the
    `OSError` or `ValueError` a write raised), `over_budget` and `late` (events that
    came after the budget ran out, besides `writer.refused`); `written` is the
    number of events kept. `stop` is the driver's own end: a listener's `shutdown`,
    or a flag a file loop reads.
    """

    def __init__(
        self,
        writer: DHCPCaptureWriter,
        stop: _ty.Callable[[], None],
        *,
        count: _ty.Optional[int] = None,
    ) -> None:
        self.writer = writer
        self.stopped = False
        self.over_budget = False
        self.failure: "_ty.Optional[Exception]" = None
        self.written = 0
        self.late = 0
        self._stop = stop
        self._count = count

    def _end(self) -> None:
        self.stopped = True
        self._stop()

    def __call__(self, event: CaptureEvent) -> None:
        # The listener logs what a sink raises and carries on, so a record that
        # cannot be kept has to end the run from here.
        if self.stopped:
            self.late += self.over_budget
            return
        try:
            self.writer(event)
        except (OSError, ValueError) as error:
            self.failure = error
            self._end()
            return
        if self.writer.refused:
            self.over_budget = True
            self._end()
            return
        self.written += 1
        if self._count is not None and self.written >= self._count:
            self._end()
