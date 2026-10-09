"""What a value means in a DHCP filter key: the conversions behind `_plugin`.

The grammar (`key=value` or `key!=value` clauses joined by `and`) and the compiling are
pktcap's. Each converter raises `ValueError` for a value no message could match, so a
mistyped filter fails when it is compiled instead of reporting nothing.
"""

from __future__ import annotations

import enum as _enum
import re as _re
import typing as _ty


from ..options._codecs._base import is_codec
from ..options._codecs._message_type import DHCPMessageType
from ..options._codes import DHCPOptionCode
from ..packet._enums import DHCPOpcode

_NUMBER_RE = _re.compile(r"[0-9]+|0[xX][0-9a-fA-F]+")
_UNNAMED_TYPE_RE = _re.compile(r"TYPE_([0-9]+)", _re.IGNORECASE)
# Hex digits in groups, joined by one `:`, `-` or `.` each: `01:AA`, `68-F7`, `68f7.d8e5`.
_HEX_RE = _re.compile(r"[0-9a-fA-F]+(?:[:.-][0-9a-fA-F]+)*")
_HEX_SEPARATOR_RE = _re.compile(r"[:.-]")

#: The name of a message type with no option 53 to name it.
_NO_TYPE = "UNKNOWN"
#: The widest a hardware address (`hlen`) and a client identifier (one option) get, in octets.
_MAX_CHADDR_OCTETS = 16
_MAX_CLIENT_ID_OCTETS = 255


def _number(key: str, text: str, low: int, high: int) -> int:
    try:
        number = int(text, 0)
    except ValueError:
        raise ValueError(
            f"Capture filter {key}= expects an integer, got {text!r}"
        ) from None
    if not low <= number <= high:
        raise ValueError(f"Capture filter {key}= expects {low} to {high}, got {text!r}")
    return number


def _named_number(key: str, text: str, names: "_ty.Mapping[str, int]") -> int:
    """A member's name in any letter case, or a number, which need not be a member."""
    if _NUMBER_RE.fullmatch(text):
        number = int(text, 16 if text[1:2] in ("x", "X") else 10)
        return _number(key, str(number), 0, 255)
    if text.upper() in names:
        return names[text.upper()]
    raise ValueError(
        f"Capture filter {key}= does not know {text!r}. It is one of: "
        + ", ".join(names)
        + ", or a number from 0 to 255"
    )


def _names(enumeration: "_ty.Type[_enum.IntEnum]") -> "dict[str, int]":
    return {name: int(member) for name, member in enumeration.__members__.items()}


# Each `*_matcher` converts a clause's values, raising `ValueError` for one no message
# could match, and returns a test of the value the clause reads. This module's filter
# and the pktcap plugin both build on them, so the two cannot read a value differently.


def op_matcher(key: str, values: "_ty.Tuple[str, ...]") -> "_ty.Callable[[int], bool]":
    """A test of an opcode's number."""
    names = _names(DHCPOpcode)
    wanted = tuple(_named_number(key, value, names) for value in values)
    return lambda number: number in wanted


def msg_type_matcher(
    key: str, values: "_ty.Tuple[str, ...]"
) -> "_ty.Callable[[_ty.Optional[int]], bool]":
    """A test of option 53's number, `None` for a message with no such option."""
    names = _names(DHCPMessageType)
    wanted: "list[int]" = []
    untyped = False
    for value in values:
        unnamed = _UNNAMED_TYPE_RE.fullmatch(value)
        if value.upper() == _NO_TYPE:
            untyped = True
        elif unnamed:
            wanted.append(_number(key, unnamed.group(1), 0, 255))
        else:
            wanted.append(_named_number(key, value, names))

    def matches(kind: _ty.Optional[int]) -> bool:
        return untyped if kind is None else kind in wanted

    return matches


def xid_matcher(key: str, values: "_ty.Tuple[str, ...]") -> "_ty.Callable[[int], bool]":
    """A test of a transaction id."""
    wanted = tuple(_number(key, value, 0, 0xFFFFFFFF) for value in values)
    return lambda xid: xid in wanted


def _hex(key: str, values: "_ty.Tuple[str, ...]", most: int) -> "_ty.Tuple[str, ...]":
    digits = []
    for value in values:
        if not _HEX_RE.fullmatch(value):
            raise ValueError(
                f"Capture filter {key}= expects hexadecimal digits, optionally "
                f"separated by ':', '-' or '.', got {value!r}"
            )
        text = _HEX_SEPARATOR_RE.sub("", value).lower()
        if len(text) % 2 or len(text) > 2 * most:
            raise ValueError(
                f"Capture filter {key}= expects whole octets, at most {most}, "
                f"got {value!r}"
            )
        digits.append(text)
    return tuple(digits)


def client_id_matcher(
    key: str, values: "_ty.Tuple[str, ...]"
) -> "_ty.Callable[[str], bool]":
    """A test of a client identifier's text: hex digits with any separators, or `UNKNOWN`."""
    # `get_client_id()` always gives colon-separated hex, and `pydhcp interfaces`
    # prints hardware addresses upper-case with hyphens: both spellings select.
    wanted = _hex(key, values, _MAX_CLIENT_ID_OCTETS)
    return lambda text: _HEX_SEPARATOR_RE.sub("", text).lower() in wanted


def chaddr_matcher(
    key: str, values: "_ty.Tuple[str, ...]"
) -> "_ty.Callable[[str], bool]":
    """A test of a hardware address's text: hex digits with any separators."""
    # `chaddr` is raw octets with `hlen` up to 16, so it is compared as digits
    # and not parsed as a six-octet address.
    wanted = _hex(key, values, _MAX_CHADDR_OCTETS)
    return lambda text: _HEX_SEPARATOR_RE.sub("", text).lower() in wanted


def option_selector(
    key: str, value: str
) -> "_ty.Tuple[_ty.Union[int, DHCPOptionCode], str]":
    """The option `option.NAME` or `option.NUMBER` names and the text it must have, whole.

    A value of an option can hold a comma (a list), so it is never split.
    """
    option = key[len("option.") :]
    code: "_ty.Union[int, DHCPOptionCode]"
    if _re.fullmatch(r"[0-9]+", option):
        code = int(option)
        if not 1 <= code <= 254:
            raise ValueError(
                f"Capture filter {key}= names no option: a code is 1 to 254"
            )
    else:
        try:
            code = DHCPOptionCode[option]
        except KeyError:
            raise ValueError(f"Unsupported DHCP option filter key: {key!r}") from None
    return code, value


def option_value_text(value: _ty.Any) -> _ty.Optional[str]:
    """A decoded option value as the text a clause compares: an enum's name, else its JSON form."""
    if value is None:
        return None
    if isinstance(value, _enum.Enum):
        return value.name
    if is_codec(value):
        return str(value.to_json())
    return str(value)
