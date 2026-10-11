"""The root command and the run around it; imports `duho`, so only `main` reaches it."""

from __future__ import annotations

import os
import sys
import typing as _ty

import duho
from duho import AUTO, Cli, ConfigArgs, DefaultsFormatter

from .. import _extras
from .._config import BACKENDS
from . import _settings
from ._common import _Configured, _Failed
from ._interfaces import Interfaces
from ._packet import Packet
from ._relay import Relay
from ._server import Server

#: The commands that need the `pktcap` extra.
_CAPTURE_COMMANDS = ("capture", "replay")


def _commands() -> "_ty.List[_ty.Type[_ty.Any]]":
    """Every command this installation has: the capture ones only with pktcap."""
    found: "_ty.List[_ty.Type[_ty.Any]]" = [Interfaces, Server, Relay, Packet]
    if _extras.has_pktcap():
        from ._capture import Capture
        from ._replay import Replay

        found += [Capture, Replay]
    return found


class App(ConfigArgs, Cli):  # type: ignore[misc]
    """pydhcp CLI Interface"""

    # duho names the program after the class, so every usage line and every
    # error read "App" -- a name that appears nowhere the user installed,
    # typed, or could look up.
    _parsername_ = "pydhcp"
    _version_ = AUTO
    _logger_name_ = "pydhcp"
    _config_env_ = _settings.CONFIG_ENV
    _config_backends_ = BACKENDS
    _config_loader_ = staticmethod(_settings.load_layer)
    _help_formatter_ = DefaultsFormatter
    _subcommands_ = _commands()


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
        if args and args[0] in _CAPTURE_COMMANDS and not _extras.has_pktcap():
            print(f"pydhcp: error: {_extras.PKTCAP_NEEDED}", file=sys.stderr)
            return 1
        sections = _settings.sections_of(
            command
            for command in App._subcommands_ or ()
            if issubclass(command, _Configured)
        )
        run_, token = _settings.begin(args, sections)
        try:
            _settings.check_renamed_variables(run_.command)
            status = duho.main(App, args)
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
    except (OSError, ImportError, NotImplementedError, _Failed) as error:
        if show_traceback:
            raise
        print(f"pydhcp: error: {error}", file=sys.stderr)
        return 1
    return 0 if status is None else int(status)
