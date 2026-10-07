"""Capture DHCP traffic: `DHCPCapture` on threads, `AsyncDHCPCapture` on an event loop."""

from __future__ import annotations

import typing as _ty

from .._lazy import bind as _bind
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
from ._plugin import pktcap_plugin
from ._sync import DHCPCapture
from ._writer import (
    FILENAME_FIELDS,
    MAX_CAPTURE_FILES,
    UNIQUE_FILENAME_FIELDS,
    DHCPCaptureWriter,
)

if _ty.TYPE_CHECKING:
    from ._asyncio import AsyncDHCPCapture

#: Bound on first use: the module that defines it imports asyncio.
_ASYNCIO = {"AsyncDHCPCapture": "._asyncio"}

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
    "pktcap_plugin",
    "read_capture",
    "register_dhcp_dissector",
    "replay_capture",
]


def __getattr__(name: str) -> _ty.Any:
    """Bind an asyncio class on first use, so importing this package does not import asyncio."""
    return _bind(__name__, globals(), _ASYNCIO, name)


def __dir__() -> "list[str]":
    return sorted(set(globals()) | set(__all__))
