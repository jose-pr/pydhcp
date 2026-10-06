"""The capture's rules: filter each message, record it, run the sink and the hook.

No socket, thread or clock lives here. A listener driver (`_sync`, `_asyncio`)
receives a datagram, stamps the context with the time it arrived and calls
`handle()`; the event's `captured_at` is that stamp.
"""

from __future__ import annotations

import logging as _logging
import typing as _ty

from .._clock import _Timed
from ..listener._receive import DHCPRequestContext
from ..packet._message import DHCPMessage
from ._events import (
    CaptureEvent,
    CaptureHook,
    CapturePredicate,
    PacketFilterLike,
    CaptureSink,
    compile_capture_filter,
)

#: This module's logger, a child of the package logger `pydhcp` (which
#: `.listener` has already imported, installing its `NullHandler`).
LOGGER = _logging.getLogger(__name__)


class _CaptureCore(_Timed):
    """Filter, sink and hook policy shared by `DHCPCapture` and `AsyncDHCPCapture`."""

    if _ty.TYPE_CHECKING:

        def shutdown(self) -> None: ...

    def _init_capture_state(
        self,
        packet_filter: _ty.Optional[PacketFilterLike] = None,
        sink: _ty.Optional[CaptureSink] = None,
        hook: _ty.Optional[CaptureHook] = None,
        hook_fail_fast: bool = False,
    ) -> None:
        """Set up the state every capture driver needs.

        Each driver's constructor takes its own listener arguments and calls
        this for the rest, so the two cannot drift apart.
        """
        self.packet_filter = (
            compile_capture_filter(packet_filter)
            if isinstance(packet_filter, str) or packet_filter is None
            else packet_filter
        )
        self.sink = sink
        self.hook = hook
        self.hook_fail_fast = hook_fail_fast
        #: The hook failure that stopped the capture, if `hook_fail_fast` is set.
        #: Lets a caller distinguish "stopped because the hook failed" from
        #: "stopped because it was asked to", which an exception swallowed by the
        #: listener loop could not.
        self.hook_error: _ty.Optional[BaseException] = None
        self.accepted_count = 0

    def handle(self, msg: DHCPMessage, context: DHCPRequestContext) -> None:
        event = CaptureEvent(
            message=msg,
            context=context,
            captured_at=self._instant(context).utc,
        )
        if not self.packet_filter(event):
            return
        self.accepted_count += 1
        if self.sink is not None:
            self.sink(event)
        if self.hook is not None:
            try:
                self.hook(event)
            except Exception as exc:
                LOGGER.exception("Capture hook failed")
                if self.hook_fail_fast:
                    # Re-raising alone achieved nothing: handle() runs inside the
                    # listener's per-packet try, which logs and carries on, so
                    # capture kept running and still exited 0. Record the failure
                    # and stop the loop, so a caller can tell that it ended
                    # because of the hook rather than because it was asked to.
                    self.hook_error = exc
                    self.shutdown()
                    raise
