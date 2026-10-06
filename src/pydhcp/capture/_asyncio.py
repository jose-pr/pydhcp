"""The asyncio capture: the capture's rules over the asyncio listener."""

from __future__ import annotations

import typing as _ty

from ..listener._asyncio import AsyncDHCPListener
from ..listener._spec import ListenSpec
from ._core import _CaptureCore
from ._events import CaptureHook, CapturePredicate, CaptureSink


class AsyncDHCPCapture(_CaptureCore, AsyncDHCPListener):
    """The capture on an event loop.

    The same filter, sink and hook rules as `DHCPCapture`. `accepted_count`,
    `hook_error` and anything a `sink` keeps are unguarded, exactly as there:
    what keeps them safe is that `AsyncDHCPListener` runs handlers on a single
    worker thread, the sink included, so the capture CLI's `--count` budget
    needs no lock. `hook_fail_fast` stops the capture from that worker thread,
    and `AsyncDHCPListener.shutdown()` reaches the event loop from any thread.
    """

    def __init__(
        self,
        listen: ListenSpec = None,
        packet_filter: _ty.Optional[_ty.Union[str, CapturePredicate]] = None,
        sink: _ty.Optional[CaptureSink] = None,
        hook: _ty.Optional[CaptureHook] = None,
        hook_fail_fast: bool = False,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
        max_queued: _ty.Optional[int] = None,
    ) -> None:
        AsyncDHCPListener.__init__(
            self,
            listen=listen,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
            max_queued=max_queued,
        )
        self._init_capture_state(
            packet_filter=packet_filter,
            sink=sink,
            hook=hook,
            hook_fail_fast=hook_fail_fast,
        )
