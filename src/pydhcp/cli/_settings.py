"""Where the command's settings come from, beyond its arguments.

The order is argument, environment variable, configuration file, field default,
and duho applies it to every declared field of every command. The file is the
root's `--config` or `PYDHCP_CONFIG`; this module is the loader duho calls for
it, and reads the two things duho cannot know before it parses: which command
runs, so that a file may be refused for naming another, and whether
`PYDHCP_TRACEBACK` asks for tracebacks. Every environment variable the command
reads is named here or on a field as `Meta(env=...)`.
"""

from __future__ import annotations

import contextvars as _contextvars
import dataclasses as _dataclasses
import os as _os
import pathlib as _pathlib
import typing as _ty

from .._config import check_sections, load_config

#: The variable that names the configuration file (`--config` beats it).
CONFIG_ENV = "PYDHCP_CONFIG"
#: The variable that asks for a traceback on an error.
TRACEBACK_ENV = "PYDHCP_TRACEBACK"

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")

#: The configuration keys that are not settings of a command.
_NOT_SETTINGS = frozenset({"config", "verbose", "quiet", "loglevel", "loglevels"})


#: The variables a command reads under another name than it read before, by command.
#: A value in one is refused with the name to use: it would otherwise change nothing.
_RENAMED_VARIABLES: "_ty.Mapping[str, _ty.Mapping[str, str]]" = {
    "capture": {
        "PYDHCP_CAPTURE_RECORD_FORMAT": "PYDHCP_CAPTURE_FORMAT",
        "PYDHCP_CAPTURE_PER_CAPTURE": "PYDHCP_CAPTURE_PER_RECORD",
    },
    "replay": {"PYDHCP_REPLAY_SERVER": "PYDHCP_REPLAY_TO"},
}


#: The variables no command reads any more, with what to do instead.
_REMOVED_VARIABLES: "_ty.Mapping[str, str]" = {
    "PYDHCP_CONFIG_FORMAT": "the ending of the file's name says its format "
    "(.json, .toml, .yaml, .yml, .ini or .cfg)",
}


def check_renamed_variables(
    command: _ty.Optional[str], environ: "_ty.Mapping[str, str]" = _os.environ
) -> None:
    """`ValueError` naming what to do when `command` finds a variable it does not read."""
    for old, instead in _REMOVED_VARIABLES.items():
        if environ.get(old):
            raise ValueError(f"{old} is not read: {instead}")
    for old, new in _RENAMED_VARIABLES.get(command or "", {}).items():
        if environ.get(old):
            raise ValueError(f"{old} is not read: the variable is {new}")


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
    #: Each command's name mapped to the keys its section accepts.
    sections: "_ty.Mapping[str, _ty.Collection[str]]" = _dataclasses.field(
        default_factory=dict
    )


_RUN: "_contextvars.ContextVar[_ty.Optional[_Run]]" = _contextvars.ContextVar(
    "pydhcp_cli_run", default=None
)

_FILE_FIRST = (
    "--config goes before the command name and names a file: "
    "pydhcp --config FILE COMMAND"
)
_NOT_STDIN = (
    "--config - is not read: standard input is not a settings file, name a file"
)


def _prescan(argv: _ty.Sequence[str]) -> _Run:
    """The command `argv` names, and the refusal of a spelling that names no option.

    The loader duho calls is given a path and nothing else, so the command is found
    here: the first word that is not an option or the file `--config` names. The
    root takes no other option with a value. `--config` after the command name,
    `--config-format` and `--config -` (standard input) are refused with the line to
    use, where the parser would only say the option is unknown.
    """
    run = _Run()
    index = 0
    while index < len(argv):
        token = argv[index]
        index += 1
        if token == "--":
            break
        name = token.partition("=")[0]
        if name == "--config-format":
            raise ValueError(
                "--config-format is not an option: the ending of the file's name "
                "says its format (.json, .toml, .yaml, .yml, .ini or .cfg)"
            )
        if run.command is not None:
            if name == "--config":
                raise ValueError(_FILE_FIRST)
            continue
        if name == "-c" or (len(name) > 2 and "--config".startswith(name)):
            value = token.partition("=")[2] if "=" in token else None
            if value is None:
                value = argv[index] if index < len(argv) else None
                index += 1
            if value == "-":
                raise ValueError(_NOT_STDIN)
            continue
        if not token.startswith("-"):
            run.command = token
    return run


def begin(
    argv: _ty.Sequence[str], sections: "_ty.Mapping[str, _ty.Collection[str]]"
) -> "tuple[_Run, _contextvars.Token[_ty.Optional[_Run]]]":
    """Read what `argv` says about the command; `end` undoes it."""
    run = _prescan(argv)
    run.sections = sections
    return run, _RUN.set(run)


def end(token: "_contextvars.Token[_ty.Optional[_Run]]") -> None:
    _RUN.reset(token)


def load_layer(path: _pathlib.Path) -> _ty.Dict[str, _ty.Any]:
    """duho's `_config_loader_`: the file as sections, checked against the commands."""
    run = _RUN.get()
    if run is None:  # pragma: no cover - duho only calls this inside `main`
        raise RuntimeError("the configuration is read inside main()")
    name = _os.fspath(path)
    table = load_config(name)
    check_sections(table, run.sections, name, running=run.command)
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
