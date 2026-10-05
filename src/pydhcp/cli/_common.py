"""What every subcommand shares: the format lists and the base class."""

from __future__ import annotations

import duho

from duho import Cmd, LoggingArgs

PACKET_FORMATS = ("json", "yaml", "toml", "ini", "summary")


CAPTURE_FORMATS = ("json", "yaml", "toml", "ini")


class _Command(LoggingArgs, Cmd):
    """Base for every subcommand, carrying the logger name.

    `_logger_name_` has to be on the *parsed* subcommand instance: duho resolves
    the logger as `getattr(self, "_logger_name_", self._parsername_)` on that
    instance, and it is the subcommand that gets parsed, not `App`. Setting it
    only on `App` meant `-v` configured a logger named after the subcommand --
    "server", "relay", "capture" -- while the library logs to "pydhcp", which
    stayed at the root level. So `pydhcp server -v` printed one line from the
    command itself and nothing at all from the server.
    """

    _logger_name_ = "pydhcp"
