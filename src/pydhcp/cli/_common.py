"""What every subcommand shares: the format lists, the base classes and the output."""

from __future__ import annotations

import contextlib as _contextlib
import errno as _errno
import pathlib
import sys as _sys
import typing as _ty

import pktcap as _pktcap
from duho import Cmd, LoggingArgs, Meta

from .._config import CONFIG_FORMATS
from ._settings import CONFIG_ENV, CONFIG_FORMAT_ENV, listen_value

PACKET_FORMATS = ("json", "yaml", "toml", "ini", "summary")


#: What `capture --format` writes: the capture files and the record formats of pktcap.
CAPTURE_FORMATS = _pktcap.OUTPUT_FORMATS


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


def closed_stdout(error: OSError) -> "_ty.Optional[BrokenPipeError]":
    """`BrokenPipeError` when `error` says nobody reads stdout any more, else `None`.

    A closed pipe is `BrokenPipeError` on POSIX and `OSError(EINVAL)` on Windows.
    """
    if isinstance(error, BrokenPipeError) or error.errno in (
        _errno.EPIPE,
        _errno.EINVAL,
    ):
        return BrokenPipeError(_errno.EPIPE, "stdout is closed")
    return None


def write_line(text: str) -> None:
    """One result line on stdout, flushed; `BrokenPipeError` if nobody reads it."""
    try:
        _sys.stdout.write(text if text.endswith("\n") else text + "\n")
        _sys.stdout.flush()
    except OSError as error:
        closed = closed_stdout(error)
        if closed is not None:
            raise closed from None
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


class _Listening(_Configured):
    """A command that listens: `server`, `relay` and `capture`.

    It declares `--listen` and `--per-interface` once. Each subclass gets the
    variables `PYDHCP_<COMMAND>_LISTEN` and `PYDHCP_<COMMAND>_PER_INTERFACE`, named
    for its `_parsername_` when the class is built.
    """

    listen: _ty.Annotated[_ty.Optional[str], Meta(type=listen_value)] = None
    "Listen address/port spec, for example '*', '127.0.0.1:6767,127.0.0.1:6768' or an interface ('eth1', 'eth1:67', 'aa-bb-cc-dd-ee-ff'). Default: every address, port 67"
    ("--listen", "-l")

    per_interface: _ty.Annotated[bool, Meta()] = False
    "Bind one socket per interface address instead of the wildcard; on Linux such sockets hear no broadcast"
    ("--per-interface",)

    def __init_subclass__(cls, **kwargs: _ty.Any) -> None:
        super().__init_subclass__(**kwargs)
        command = str(getattr(cls, "_parsername_", "")).upper()
        cls.__annotations__ = {
            **cls.__dict__.get("__annotations__", {}),
            "listen": _ty.Annotated[
                _ty.Optional[str],
                Meta(env=f"PYDHCP_{command}_LISTEN", type=listen_value),
            ],
            "per_interface": _ty.Annotated[
                bool, Meta(env=f"PYDHCP_{command}_PER_INTERFACE")
            ],
        }

    def _serve(self, role: _ty.Any) -> None:
        """Run `role` until it ends or is interrupted; Ctrl-C is a clean end."""
        try:
            with role:
                role.serve_forever()
        except KeyboardInterrupt:
            self._logger_.info("Stopped listening due to Ctrl-C")
