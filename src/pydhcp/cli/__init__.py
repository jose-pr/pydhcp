"""The `pydhcp` command line.

`App` and `main` live here; each subcommand has its own module (`_interfaces`,
`_server`, `_relay`, `_packet`, `_capture`), with what they share in `_common`.
"""

from __future__ import annotations

import logging as _logging
import os
import sys

import duho
from duho import AUTO, Cli, DefaultsFormatter

from ._common import PACKET_FORMATS, CAPTURE_FORMATS
from ._interfaces import Interfaces
from ._server import Server
from ._relay import Relay
from ._packet import Packet
from ._capture_hook import HOOK_TIMEOUT_SECONDS
from ._capture import MAX_PER_CAPTURE_FILES, Capture

#: The command line's logger, a child of the package logger `pydhcp`: the
#: `-v` and `--loglevel pydhcp:DEBUG` options configure the parent.
LOGGER = _logging.getLogger(__name__)


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
