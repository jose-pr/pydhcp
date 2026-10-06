"""Capture DHCP traffic: `DHCPCapture` on threads, `AsyncDHCPCapture` on an event loop."""

from __future__ import annotations

from ._asyncio import AsyncDHCPCapture
from ._events import (
    CaptureEvent,
    CaptureHook,
    CapturePredicate,
    CaptureSink,
    PacketFilterLike,
)
from ._filter import compile_capture_filter
from ._command import HOOK_TIMEOUT_SECONDS, command_hook
from ._dissector import DHCPLayer, dissect_dhcp, register_dhcp_dissector
from ._offline import capture_dissector, read_capture, replay_capture
from ._sync import DHCPCapture
from ._writer import (
    FILENAME_FIELDS,
    MAX_CAPTURE_FILES,
    UNIQUE_FILENAME_FIELDS,
    DHCPCaptureWriter,
)

__all__ = [
    "AsyncDHCPCapture",
    "CaptureEvent",
    "CaptureHook",
    "CapturePredicate",
    "CaptureSink",
    "DHCPCapture",
    "DHCPCaptureWriter",
    "DHCPLayer",
    "PacketFilterLike",
    "FILENAME_FIELDS",
    "HOOK_TIMEOUT_SECONDS",
    "MAX_CAPTURE_FILES",
    "UNIQUE_FILENAME_FIELDS",
    "capture_dissector",
    "command_hook",
    "compile_capture_filter",
    "dissect_dhcp",
    "read_capture",
    "register_dhcp_dissector",
    "replay_capture",
]
