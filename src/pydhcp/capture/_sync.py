"""The thread-based capture: the capture's rules over the thread-based listener."""

from __future__ import annotations

import typing as _ty

from ..listener._spec import ListenLike
from ..listener._sync import DHCPListener
from ._core import _CaptureCore
from ._events import CaptureHook, CapturePredicate, CaptureSink, PacketFilterLike


class DHCPCapture(_CaptureCore, DHCPListener):
    """Records the DHCP messages a listener receives, through a filter, a sink and a hook."""

    def __init__(
        self,
        listen: ListenLike = None,
        *,
        packet_filter: _ty.Optional[PacketFilterLike] = None,
        sink: _ty.Optional[CaptureSink] = None,
        hook: _ty.Optional[CaptureHook] = None,
        hook_fail_fast: bool = False,
        poll_interval: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: _ty.Optional[bool] = None,
        reuse_address: _ty.Optional[bool] = None,
        receive_buffer_size: _ty.Optional[int] = None,
    ) -> None:
        DHCPListener.__init__(
            self,
            listen=listen,
            poll_interval=poll_interval,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
            reuse_address=reuse_address,
            receive_buffer_size=receive_buffer_size,
        )
        self._init_capture_state(
            packet_filter=packet_filter,
            sink=sink,
            hook=hook,
            hook_fail_fast=hook_fail_fast,
        )
