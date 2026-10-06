"""Where the command's settings come from, beyond its arguments.

The order is argument, environment variable, configuration file, field default,
and duho applies it to every declared field of every command. This module reads
the two things duho cannot know before it parses: which configuration file to
load, and whether `PYDHCP_TRACEBACK` asks for tracebacks. Every environment
variable the command reads is named here or on a field as `Meta(env=...)`.
"""

from __future__ import annotations

import contextvars as _contextvars
import dataclasses as _dataclasses
import os as _os
import pathlib as _pathlib
import typing as _ty

from .._config import STDIN_NAME, check_sections, load_config

#: The variable that names the configuration file (`--config` beats it).
CONFIG_ENV = "PYDHCP_CONFIG"
#: The variable that names a configuration file's format (`--config-format`).
CONFIG_FORMAT_ENV = "PYDHCP_CONFIG_FORMAT"
#: The variable that asks for a traceback on an error.
TRACEBACK_ENV = "PYDHCP_TRACEBACK"

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")

#: The configuration keys that are not settings of a command.
_NOT_SETTINGS = frozenset(
    {"config", "config_format", "verbose", "quiet", "loglevel", "loglevels"}
)


def traceback_requested(environ: "_ty.Mapping[str, str]" = _os.environ) -> bool:
    """Whether `PYDHCP_TRACEBACK` is on: `1`, `true`, `yes`, `on`, in any case.

    Unset or empty is off, as are `0`, `false`, `no` and `off`; any other text
    is a `ValueError` naming the variable.
    """
    raw = environ.get(TRACEBACK_ENV, "").strip().lower()
    if raw in _TRUE:
        return True
    if raw == "" or raw in _FALSE:
        return False
    raise ValueError(
        f"{TRACEBACK_ENV} must be one of {', '.join(_TRUE + _FALSE)}, got {raw!r}"
    )


class Listen:
    """A `listen` value from a configuration file that is not text.

    A file can hold a pair, a list of pairs or a null host, which duho's
    layering would refuse for a text field; the wrapper carries it to the
    command, which hands the value to the listener's own grammar.
    """

    __slots__ = ("value",)

    def __init__(self, value: _ty.Any) -> None:
        self.value = value


def listen_value(raw: _ty.Any) -> _ty.Any:
    """The value of a `listen` field: text as given, a file's structure as read."""
    return raw.value if isinstance(raw, Listen) else str(raw)


@_dataclasses.dataclass
class _Run:
    """What one `main` call knows before duho parses."""

    command: _ty.Optional[str] = None
    config: _ty.Optional[str] = None
    config_format: _ty.Optional[str] = None
    #: Each command's name mapped to the keys its section accepts.
    sections: "_ty.Mapping[str, _ty.Collection[str]]" = _dataclasses.field(
        default_factory=dict
    )


_RUN: "_contextvars.ContextVar[_ty.Optional[_Run]]" = _contextvars.ContextVar(
    "pydhcp_cli_run", default=None
)


def _prescan(argv: _ty.Sequence[str]) -> _Run:
    """The command and the configuration options of `argv`, spelled out in full.

    The configuration file has to be read before duho parses, so its path comes
    from here. The root takes no option of its own, so the command is the first
    word when that is not an option.
    """
    run = _Run()
    if argv and not argv[0].startswith("-"):
        run.command = argv[0]
    wanted = {"--config": "config", "--config-format": "config_format"}
    index = 0
    while index < len(argv):
        token = argv[index]
        index += 1
        if token == "--":
            break
        name, equals, value = token.partition("=")
        if name not in wanted:
            continue
        if not equals:
            if index >= len(argv):
                break
            value = argv[index]
            index += 1
        setattr(run, wanted[name], value)
    environ = _os.environ
    if run.config is None:
        run.config = environ.get(CONFIG_ENV) or None
    if run.config_format is None:
        run.config_format = environ.get(CONFIG_FORMAT_ENV) or None
    return run


def begin(
    argv: _ty.Sequence[str], sections: "_ty.Mapping[str, _ty.Collection[str]]"
) -> "tuple[_Run, _contextvars.Token[_ty.Optional[_Run]]]":
    """Read what `argv` says about the configuration; `end` undoes it."""
    run = _prescan(argv)
    run.sections = sections
    return run, _RUN.set(run)


def end(token: "_contextvars.Token[_ty.Optional[_Run]]") -> None:
    _RUN.reset(token)


def config_path() -> _ty.Optional[_pathlib.Path]:
    """The configuration file this run names, or `None`."""
    run = _RUN.get()
    return None if run is None or run.config is None else _pathlib.Path(run.config)


def load_layer(path: _pathlib.Path) -> _ty.Dict[str, _ty.Any]:
    """duho's `_config_loader_`: the file as sections, checked against the commands."""
    run = _RUN.get()
    if run is None:  # pragma: no cover - duho only calls this inside `main`
        raise RuntimeError("the configuration is read inside main()")
    name = _os.fspath(path)
    table = load_config(name, run.config_format)
    shown = STDIN_NAME if name == "-" else name
    check_sections(table, run.sections, shown, running=run.command)
    for body in table.values():
        if "listen" in body and not isinstance(body["listen"], str):
            body["listen"] = Listen(body["listen"])
    return table


def sections_of(
    commands: "_ty.Iterable[_ty.Any]",
) -> "dict[str, frozenset[str]]":
    """Each command's name mapped to the keys its configuration section accepts."""
    return {
        str(command._parsername_): frozenset(
            builder.name
            for builder in command._getargs_()
            if builder.name not in _NOT_SETTINGS
        )
        for command in commands
    }
