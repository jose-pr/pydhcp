"""The `pydhcp` command line.

`main` is here and imports nothing the command needs until it is called. `App`
and the six command classes are in the modules beside it (`_app`, `_interfaces`,
`_server`, `_relay`, `_packet`, `_capture`, `_replay`), which import `duho`:
the names load on first use, and without the `cli` extra that use is an
`ImportError` naming the extra. What the commands share is in `_common` and where
the settings come from in `_settings`.
"""

from __future__ import annotations

import importlib as _importlib
import logging as _logging
import sys
import typing as _ty

from .._extras import missing as _missing

if _ty.TYPE_CHECKING:
    from ._app import App as App
    from ._capture import Capture as Capture
    from ._interfaces import Interfaces as Interfaces
    from ._packet import Packet as Packet
    from ._relay import Relay as Relay
    from ._replay import Replay as Replay
    from ._server import Server as Server

#: The command line's logger, a child of the package logger `pydhcp`: the
#: `-v` and `--loglevel pydhcp:DEBUG` options configure the parent.
LOGGER = _logging.getLogger(__name__)

#: Which module holds each name that needs `duho`.
_MODULES = {
    "App": "_app",
    "Interfaces": "_interfaces",
    "Server": "_server",
    "Relay": "_relay",
    "Packet": "_packet",
    "Capture": "_capture",
    "Replay": "_replay",
}


_NEEDS_CLI = _missing("the command line", "cli")


def _has_duho() -> bool:
    """Whether `duho`, which the `cli` extra installs, can be imported.

    A failure inside `duho` or one of its own dependencies is not "absent".
    """
    try:
        import duho  # noqa: F401
    except ModuleNotFoundError as error:
        if error.name != "duho":
            raise
        return False
    return True


def __getattr__(name: str) -> _ty.Any:
    module = _MODULES.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    if not _has_duho():
        raise ImportError(_NEEDS_CLI)
    value = getattr(_importlib.import_module(f".{module}", __name__), name)
    globals()[name] = value
    return value


def main(argv: "_ty.Optional[_ty.Sequence[str]]" = None) -> int:
    """Run the command line and return its exit status; it never exits itself.

    `argv` is the arguments after the program name (default `sys.argv[1:]`).
    Status 0 is success, 1 a run that failed (an address in use, a file that
    cannot be written, a hook that failed), 2 a wrong invocation (a bad
    option, a malformed `--listen`, a configuration file that cannot be used).
    The parser's own exits (`--help`, `--version`, a usage error) are returned
    as their status. An error is one line on stderr, `pydhcp: error: ...`;
    `PYDHCP_TRACEBACK=1` raises it with its traceback instead. Without the `cli`
    extra the one line names it and the status is 1.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if not _has_duho():
        print(f"pydhcp: error: {_NEEDS_CLI}", file=sys.stderr)
        return 1
    from ._app import run

    return run(args)


__all__ = [
    "App",
    "main",
    "Interfaces",
    "Server",
    "Relay",
    "Packet",
    "Capture",
    "Replay",
]
