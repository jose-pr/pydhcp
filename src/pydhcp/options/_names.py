"""Reading an option's name: the one rule every caller that takes a name follows."""

from __future__ import annotations

import re as _re
import typing as _ty

#: `option-67`, `option_67`, `OPTION67`: the number spelled as a name.
_OPTION_NUMBER = _re.compile(r"option[-_ ]?([0-9]+)", _re.IGNORECASE)


def resolve_code(codemap: _ty.Any, name: _ty.Any) -> int:
    """The option code `name` names in the code enum `codemap`.

    `name` is an `int` (an option code member included), or text: digits, `option-<n>`
    (`-`, `_`, a space or nothing between, any case), or a member name of `codemap` --
    exactly, or in any case with `-` and `_` alike (`bootfile-name` is
    `BOOTFILE_NAME`). An alias member resolves to its code. The code is not
    range-checked here: storing it is what checks it.

    Raises:
        TypeError: `name` is neither text nor an integer.
        ValueError: text that is none of the above.
    """
    if isinstance(name, bool) or not isinstance(name, (int, str)):
        raise TypeError(f"an option is named by text or a number, not {name!r}")
    if isinstance(name, int):
        return int(name)
    text = name.strip()
    if text.isdigit():
        return int(text)
    numbered = _OPTION_NUMBER.fullmatch(text)
    if numbered is not None:
        return int(numbered.group(1))
    for key in (text, text.upper().replace("-", "_")):
        member = _member(codemap, key)
        if member is not None:
            return int(member)
    raise ValueError(
        f"unknown option {name!r}: it is neither a name in "
        f"{getattr(codemap, '__name__', codemap)}, a number nor option-<n>"
    )


def _member(codemap: _ty.Any, key: str) -> _ty.Any:
    members = getattr(codemap, "__members__", None)
    if members is not None:
        return members.get(key)
    try:
        return codemap[key]
    except (KeyError, TypeError):
        return None
