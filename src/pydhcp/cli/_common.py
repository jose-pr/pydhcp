"""What every subcommand shares: the format lists, the base classes and the output."""

from __future__ import annotations

import contextlib as _contextlib
import errno as _errno
import pathlib
import sys as _sys
import typing as _ty

from duho import Cmd, LoggingArgs, Meta

from .._config import CONFIG_FORMATS
from ._settings import CONFIG_ENV, CONFIG_FORMAT_ENV

PACKET_FORMATS = ("json", "yaml", "toml", "ini", "summary")


CAPTURE_FORMATS = ("json", "yaml", "toml", "ini")


@_contextlib.contextmanager
def _arguments() -> "_ty.Iterator[None]":
    """Build a role from the command's arguments.

    A value of the wrong type can only come from a configuration file, and the
    constructor's `TypeError` for it is a wrong invocation like a `ValueError`.
    """
    try:
        yield
    except TypeError as error:
        raise ValueError(str(error)) from None


class _Failed(Exception):
    """A run that did not succeed: `main` prints it as one line and returns 1.

    A wrong invocation is a `ValueError` instead and returns 2.
    """


def write_line(text: str) -> None:
    """One result line on stdout, flushed; `BrokenPipeError` if nobody reads it.

    A closed pipe is `BrokenPipeError` on POSIX and `OSError(EINVAL)` on Windows.
    """
    try:
        _sys.stdout.write(text if text.endswith("\n") else text + "\n")
        _sys.stdout.flush()
    except OSError as error:
        if isinstance(error, BrokenPipeError) or error.errno in (
            _errno.EPIPE,
            _errno.EINVAL,
        ):
            raise BrokenPipeError(_errno.EPIPE, "stdout is closed") from None
        raise


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


class _Configured(_Command):
    """A command whose settings can also come from a configuration file.

    The file is explicit: `--config` or `PYDHCP_CONFIG`. A daemon does not pick
    up a file nobody named, so there is no default location.
    """

    config: _ty.Annotated[_ty.Optional[pathlib.Path], Meta(env=CONFIG_ENV)] = None
    "Configuration file (JSON, YAML, TOML or INI) with a section named for this command; '-' reads standard input and needs --config-format. Default: none"
    ("--config",)

    config_format: _ty.Annotated[
        _ty.Optional[str], Meta(choices=CONFIG_FORMATS, env=CONFIG_FORMAT_ENV)
    ] = None
    "Format of the configuration file. Default: from the file's extension"
    ("--config-format",)
