"""The root command and the run around it; imports `duho`, so only `main` reaches it."""

from __future__ import annotations

import os
import sys
import typing as _ty

import duho
from duho import AUTO, Cli, DefaultsFormatter

from . import _settings
from ._capture import Capture
from ._common import _Configured, _Failed
from ._interfaces import Interfaces
from ._packet import Packet
from ._relay import Relay
from ._replay import Replay
from ._server import Server


class App(Cli):
    """pydhcp CLI Interface"""

    # duho names the program after the class, so every usage line and every
    # error read "App" -- a name that appears nowhere the user installed,
    # typed, or could look up.
    _parsername_ = "pydhcp"
    _version_ = AUTO
    _logger_name_ = "pydhcp"
    _config_loader_ = staticmethod(_settings.load_layer)
    _help_formatter_ = DefaultsFormatter
    _subcommands_ = [Interfaces, Server, Relay, Packet, Capture, Replay]


def _quiet_stdout() -> None:
    """Point stdout at the null device, so the flush at exit cannot fail again."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def run(args: "_ty.List[str]") -> int:
    """Parse `args` and run the command they name; `main`'s body."""
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
