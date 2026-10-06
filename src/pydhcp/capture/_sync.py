"""The thread-based capture: the capture's rules over the thread-based listener."""

from __future__ import annotations

import typing as _ty

from ..listener._spec import ListenSpec
from ..listener._sync import DHCPListener
from ._core import _CaptureCore
from ._events import CaptureHook, CapturePredicate, CaptureSink


class DHCPCapture(_CaptureCore, DHCPListener):
    """Records the DHCP messages a listener receives, through a filter, a sink and a hook."""

    def __init__(
        self,
        listen: ListenSpec = None,
        packet_filter: _ty.Optional[_ty.Union[str, CapturePredicate]] = None,
        sink: _ty.Optional[CaptureSink] = None,
        hook: _ty.Optional[CaptureHook] = None,
        hook_fail_fast: bool = False,
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
    ) -> None:
        DHCPListener.__init__(
            self,
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self._init_capture_state(
            packet_filter=packet_filter,
            sink=sink,
            hook=hook,
            hook_fail_fast=hook_fail_fast,
        )
