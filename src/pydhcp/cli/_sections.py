"""What the settings file may name: the sections and keys the commands have."""

from __future__ import annotations

import typing as _ty

from ..exceptions import DHCPConfigError

#: The configuration keys that are not settings of a command.
_NOT_SETTINGS = frozenset({"config", "verbose", "quiet", "loglevel", "loglevels"})

#: A bound on a name taken from a file, in characters.
_NAME_LIMIT = 80


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


def _plain(text: str) -> str:
    """A name from a file as one bounded line."""
    line = " ".join(text.split())
    return line if len(line) <= _NAME_LIMIT else line[: _NAME_LIMIT - 3] + "..."


def check_file(
    command: _ty.Any,
    table: "_ty.Mapping[str, _ty.Any]",
    unknown: _ty.Sequence[str],
    commands: "_ty.Iterable[_ty.Any]",
) -> None:
    """`DHCPConfigError` for a settings file that names what the program lacks.

    `command` is the parsed command, `table` the file as the loader read it and
    `unknown` the dotted keys duho found that nothing applies. A top-level key that
    is no command's name, a section of another command, a section that is no
    mapping, and a key the running command does not accept (the logging options
    and `config` are the root's, not a section's) are refused by name. The
    messages hold names, never a value.
    """
    sections = sections_of(commands)
    running = str(command._parsername_)
    for name, body in table.items():
        if name not in sections:
            raise DHCPConfigError(
                f"unknown section {_plain(str(name))!r}; "
                f"expected one of {', '.join(sections)}"
            )
        if name != running:
            raise DHCPConfigError(
                f"section {name!r} belongs to another command, and this is {running!r}"
            )
        if not isinstance(body, dict):
            raise DHCPConfigError(
                f"section {name!r} must be a mapping, not {type(body).__name__}"
            )
    own = table.get(running, {})
    refused = [key for key in own if key in _NOT_SETTINGS]
    refused += [
        key.partition(".")[2] for key in unknown if key.startswith(f"{running}.")
    ]
    if refused:
        accepted = ", ".join(sorted(sections[running])) or "none"
        raise DHCPConfigError(
            f"unknown key {_plain(str(refused[0]))!r} in section {running!r}; "
            f"it accepts {accepted}"
        )
