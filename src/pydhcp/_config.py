from __future__ import annotations

import configparser as _configparser
import json as _json
import os as _os
import pathlib as _pathlib
import re as _re
import sys as _sys
import typing as _ty

from . import _extras
from .exceptions import DHCPConfigError

#: The configuration formats, by name.
CONFIG_FORMATS = ("json", "yaml", "toml", "ini")

_SUFFIXES = {
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "ini",
}

#: What `load_config` calls standard input in an error.
STDIN_NAME = "<stdin>"


#: A bound on the problem text taken from a parser, in characters.
_PROBLEM_LIMIT = 80

_TOML_POSITION = _re.compile(r"\s*\(at (?:line (\d+), column (\d+)|end of document)\)")


def _plain(text: str) -> str:
    """A parser's own problem text as one bounded line."""
    line = " ".join(text.split())
    return line if len(line) <= _PROBLEM_LIMIT else line[: _PROBLEM_LIMIT - 3] + "..."


def _format_of(path: str, explicit: _ty.Optional[str]) -> str:
    """The format named by `explicit`, else by the file name's suffix."""
    if explicit is not None:
        name = explicit.lower()
        if name not in CONFIG_FORMATS:
            raise DHCPConfigError(
                f"unsupported configuration format {explicit!r}; "
                f"use one of {', '.join(CONFIG_FORMATS)}",
                path,
            )
        return name
    suffix = _pathlib.PurePath(path).suffix.lower()
    if suffix in _SUFFIXES:
        return _SUFFIXES[suffix]
    raise DHCPConfigError(
        f"cannot tell the configuration format from the file name"
        f"{' extension ' + repr(suffix) if suffix else ''}; use a name ending "
        f"{', '.join(_SUFFIXES)} or name the format",
        path,
    )


def _parse_json(text: str, path: str) -> _ty.Any:
    try:
        return _json.loads(text)
    except _json.JSONDecodeError as error:
        raise DHCPConfigError(
            _plain(error.msg), path, error.lineno, error.colno
        ) from None
    except RecursionError:
        raise DHCPConfigError("nested too deeply", path) from None


def _parse_yaml(text: str, path: str) -> _ty.Any:
    try:
        yaml = _extras.yaml_module()
    except ImportError as error:
        raise DHCPConfigError(str(error), path) from None
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        problem = getattr(error, "problem", None)
        raise DHCPConfigError(
            _plain(problem) if problem else "not valid YAML",
            path,
            None if mark is None else mark.line + 1,
            None if mark is None else mark.column + 1,
        ) from None
    except RecursionError:
        raise DHCPConfigError("nested too deeply", path) from None
    except (ValueError, TypeError, OverflowError):
        raise DHCPConfigError("a value that is not valid YAML", path) from None


def _parse_toml(text: str, path: str) -> _ty.Any:
    try:
        reader = _extras.toml_reader()
    except ImportError as error:
        raise DHCPConfigError(str(error), path) from None
    try:
        return reader.loads(text)
    except reader.TOMLDecodeError as error:
        message = str(error)
        found = _TOML_POSITION.search(message)
        line = getattr(error, "lineno", None)
        column = getattr(error, "colno", None)
        if line is None and found is not None and found.group(1) is not None:
            line, column = int(found.group(1)), int(found.group(2))
        problem = getattr(error, "msg", None) or _TOML_POSITION.sub("", message)
        raise DHCPConfigError(_plain(problem), path, line, column) from None
    except RecursionError:
        raise DHCPConfigError("nested too deeply", path) from None


def _parse_ini(text: str, path: str) -> _ty.Any:
    # No interpolation: a `%` in a value (a Windows path, a URL) is text.
    parser = _configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text, source=path)
    except _configparser.MissingSectionHeaderError as error:
        raise DHCPConfigError(
            "no section header before the first key", path, error.lineno
        ) from None
    except _configparser.ParsingError as error:
        errors = getattr(error, "errors", None) or []
        line = errors[0][0] if errors else None
        raise DHCPConfigError("not a key and value", path, line) from None
    except _configparser.DuplicateSectionError as error:
        raise DHCPConfigError(
            f"section [{_plain(error.section)}] is defined twice", path, error.lineno
        ) from None
    except _configparser.DuplicateOptionError as error:
        raise DHCPConfigError(
            f"key {_plain(error.option)!r} is defined twice in "
            f"[{_plain(error.section)}]",
            path,
            error.lineno,
        ) from None
    except _configparser.Error:
        raise DHCPConfigError("not valid INI", path) from None
    return {name: dict(parser.items(name)) for name in parser.sections()}


_PARSERS: "dict[str, _ty.Callable[[str, str], _ty.Any]]" = {
    "json": _parse_json,
    "yaml": _parse_yaml,
    "toml": _parse_toml,
    "ini": _parse_ini,
}


def load_config(
    source: "_ty.Union[str, _os.PathLike[str]]", format: _ty.Optional[str] = None
) -> _ty.Dict[str, _ty.Any]:
    """Read one configuration file into a mapping of sections.

    `source` is a path, or `-` for standard input, which has no file name and
    so needs `format`. The format is `format` (`json`, `yaml`, `toml` or `ini`,
    any case) or else the file name's suffix; any other suffix is refused.
    The text is UTF-8, with or without a byte-order mark. An empty YAML
    document is an empty mapping.

    A file that cannot be read raises the `OSError`. A document that does not
    parse, whose top level is not a mapping, or whose format cannot be told
    raises `DHCPConfigError` with the path and position and no text from the
    document. A YAML file needs the `yaml` extra, and a TOML file Python 3.11+
    or the `toml` extra: without it the `DHCPConfigError` names the extra.
    """
    if _os.fspath(source) == "-":
        path = STDIN_NAME
        if format is None:
            raise DHCPConfigError(
                "reading the configuration from standard input needs a format "
                f"({', '.join(CONFIG_FORMATS)})",
                path,
            )
        name = _format_of(path, format)
        data = _sys.stdin.buffer.read()
    else:
        path = _os.fspath(source)
        name = _format_of(path, format)
        data = _pathlib.Path(path).read_bytes()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise DHCPConfigError(
            f"not valid UTF-8 (byte offset {error.start})", path
        ) from None
    parsed = _PARSERS[name](text, path)
    if parsed is None and name == "yaml":
        return {}
    if not isinstance(parsed, dict):
        raise DHCPConfigError(
            f"the top level must be a mapping, not {type(parsed).__name__}", path
        )
    return _ty.cast(_ty.Dict[str, _ty.Any], parsed)


def check_sections(
    table: _ty.Mapping[str, _ty.Any],
    sections: _ty.Mapping[str, _ty.Collection[str]],
    path: str,
    *,
    running: _ty.Optional[str] = None,
) -> None:
    """Refuse a configuration table that names what the program does not have.

    `sections` maps each section to the keys it accepts. A top-level key that is
    not a section, a section that is not a mapping, a key the section does not
    accept, and, when `running` names the command being run, a section of any
    other command are `DHCPConfigError`s naming the key, so a misspelled section
    never looks like it worked.
    """
    for name, body in table.items():
        if name not in sections:
            raise DHCPConfigError(
                f"unknown section {_plain(str(name))!r}; "
                f"expected one of {', '.join(sections)}",
                path,
            )
        if running is not None and name != running:
            raise DHCPConfigError(
                f"section {name!r} belongs to another command, and this is "
                f"{running!r}",
                path,
            )
        if not isinstance(body, dict):
            raise DHCPConfigError(
                f"section {name!r} must be a mapping, not {type(body).__name__}", path
            )
        for key in body:
            if key not in sections[name]:
                accepted = ", ".join(sorted(sections[name])) or "none"
                raise DHCPConfigError(
                    f"unknown key {_plain(str(key))!r} in section {name!r}; "
                    f"it accepts {accepted}",
                    path,
                )
