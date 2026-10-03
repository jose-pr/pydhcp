"""The `pydhcp` command line.

`App` and `main` live here; each subcommand has its own module (`interfaces`,
`server`, `relay`, `packet`, `capture`), with what they share in `_common`.
Every name the single-module CLI had is re-exported, so imports are unchanged.
"""

from __future__ import annotations

import os
import sys

import duho
from duho import AUTO, Cli, DefaultsFormatter

from ._common import LOGGER, PACKET_FORMATS, CAPTURE_FORMATS, _Command
from .interfaces import Interfaces
from .server import Server
from .relay import _parse_server_address, Relay
from .packet import Packet
from .capture_hook import (
    HOOK_TIMEOUT_SECONDS,
    _cwd_on_sys_path,
    _load_capture_hook,
    _serialize_capture_event,
)
from .capture import (
    _infer_capture_format,
    _infer_output_mode,
    _stream_separator,
    MAX_PER_CAPTURE_FILES,
    _per_capture_budget,
    _write_capture_record,
    Capture,
)


class App(Cli):
    """pydhcp CLI Interface"""

    # duho names the program after the class, so every usage line and every
    # error read "App" -- a name that appears nowhere the user installed,
    # typed, or could look up.
    _parsername_ = "pydhcp"
    _version_ = AUTO
    _logger_name_ = "pydhcp"
    _help_formatter_ = DefaultsFormatter
    _subcommands_ = [Interfaces, Server, Relay, Packet, Capture]


def main() -> None:
    try:
        sys.exit(duho.main(App))
    except (ValueError, OSError, NotImplementedError) as error:
        # A mistyped port, a missing config, an address already in use or a bad
        # hex id is a user error, not a crash. duho lets exceptions out of the
        # command, so these arrived as tracebacks -- including the privileged-
        # port hint the listener carefully builds. Set PYDHCP_TRACEBACK=1 to see
        # the traceback anyway when diagnosing pydhcp itself.
        if os.environ.get("PYDHCP_TRACEBACK"):
            raise
        print(f"pydhcp: error: {error}", file=sys.stderr)
        sys.exit(1)


__all__ = [
    "App",
    "main",
    "LOGGER",
    "PACKET_FORMATS",
    "CAPTURE_FORMATS",
    "Interfaces",
    "Server",
    "Relay",
    "Packet",
    "HOOK_TIMEOUT_SECONDS",
    "MAX_PER_CAPTURE_FILES",
    "Capture",
]
