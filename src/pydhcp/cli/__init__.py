"""The `pydhcp` command line.

`App` and `main` live here; each subcommand has its own module (`_interfaces`,
`_server`, `_relay`, `_packet`, `_capture`), with what they share in `_common`
and where the settings come from in `_settings`.
"""

from __future__ import annotations

import logging as _logging
import os
import sys
import typing as _ty

import duho
from duho import AUTO, Cli, DefaultsFormatter

from . import _settings
from ._common import PACKET_FORMATS, CAPTURE_FORMATS, _Configured, _Failed
from ._interfaces import Interfaces
from ._server import Server
from ._relay import Relay
from ._packet import Packet
from ._capture import Capture

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
    # No command is a tool a program calls: serve, relay and capture never
    # return, and `packet` and `interfaces` have a shell to run in. A switch per
    # command does not exist, so PYDHCP_MCP is not read.
    _mcp_ = False
    _config_loader_ = staticmethod(_settings.load_layer)
    _help_formatter_ = DefaultsFormatter
    _subcommands_ = [Interfaces, Server, Relay, Packet, Capture]


def _quiet_stdout() -> None:
    """Point stdout at the null device, so the flush at exit cannot fail again."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def main(argv: "_ty.Optional[_ty.Sequence[str]]" = None) -> int:
    """Run the command line and return its exit status; it never exits itself.

    `argv` is the arguments after the program name (default `sys.argv[1:]`).
    Status 0 is success, 1 a run that failed (an address in use, a file that
    cannot be written, a hook that failed), 2 a wrong invocation (a bad
    option, a malformed `--listen`, a configuration file that cannot be used).
    The parser's own exits (`--help`, `--version`, a usage error) are returned
    as their status. An error is one line on stderr, `pydhcp: error: ...`;
    `PYDHCP_TRACEBACK=1` raises it with its traceback instead.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    show_traceback = False
    try:
        show_traceback = _settings.traceback_requested()
        sections = _settings.sections_of(
            command
            for command in App._subcommands_ or ()
            if issubclass(command, _Configured)
        )
        _, token = _settings.begin(args, sections)
        try:
            status = duho.main(App, args, config=_settings.config_path())
        finally:
            _settings.end(token)
    except SystemExit as stop:
        code = stop.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        print(code, file=sys.stderr)
        return 1
    except BrokenPipeError:
        _quiet_stdout()
        return 1
    except ValueError as error:
        if show_traceback:
            raise
        print(f"pydhcp: error: {error}", file=sys.stderr)
        return 2
    except (OSError, NotImplementedError, _Failed) as error:
        if show_traceback:
            raise
        print(f"pydhcp: error: {error}", file=sys.stderr)
        return 1
    return 0 if status is None else int(status)


__all__ = [
    "App",
    "main",
    "PACKET_FORMATS",
    "CAPTURE_FORMATS",
    "Interfaces",
    "Server",
    "Relay",
    "Packet",
    "Capture",
]
