"""What each key of a capture filter means for a captured DHCP message.

The grammar (`key=value` or `key!=value` clauses joined by `and`) is pktcap's.
A clause is built when the filter is compiled and a value that no packet could
ever match is refused there, so a mistyped filter fails at start-up instead of
reporting nothing.
"""

from __future__ import annotations

import enum as _enum
import ipaddress as _ipaddress
import re as _re
import typing as _ty

import pktcap as _pktcap

from ..options._codecs._base import is_codec
from ..options._codecs._message_type import DHCPMessageType
from ..options._codes import DHCPOptionCode
from ..packet._enums import DHCPOpcode
from ..packet._message import DHCPMessage
from ._events import CaptureEvent, CapturePredicate

#: The keys a clause may name, besides `option.NAME` and `option.NUMBER`.
FILTER_KEYS: _ty.Final = (
    "op",
    "msg_type",
    "xid",
    "client_id",
    "chaddr",
    "src",
    "src_port",
    "dst",
    "dst_port",
    "interface",
)

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


def compile_capture_filter(text: _ty.Optional[str]) -> CapturePredicate:
    """The predicate for a filter expression; `None` or blank accepts every event.

    `pktcap.CaptureFilterError` (a `ValueError`) for a malformed expression, an
    unknown key, or a value no packet could match.
    """
    return _pktcap.compile_capture_filter(text, _build)


def _build(clause: _pktcap.FilterClause) -> CapturePredicate:
    key = clause.key
    if key.startswith("option.") and len(key) > len("option."):
        return _option(key, clause.value)
    builder = _CLAUSES.get(key)
    if builder is None:
        raise ValueError(
            f"Unsupported capture filter key: {key!r}. The keys are "
            + ", ".join((*FILTER_KEYS, "option.NAME", "option.NUMBER"))
        )
    values = clause.values
    if not values:
        raise ValueError(f"Capture filter {key}= expects a value")
    return builder(key, values)


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


def _op(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    names = _names(DHCPOpcode)
    wanted = tuple(_named_number(key, value, names) for value in values)
    return lambda event: int(event.message.op) in wanted


def _msg_type(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
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

    def matches(event: CaptureEvent) -> bool:
        kind = event.message.message_type
        return untyped if kind is None else int(kind) in wanted

    return matches


def _xid(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    wanted = tuple(_number(key, value, 0, 0xFFFFFFFF) for value in values)
    return lambda event: event.message.xid in wanted


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


def _client_id(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    # `get_client_id()` always gives colon-separated hex, and `pydhcp interfaces`
    # prints hardware addresses upper-case with hyphens: both spellings select.
    wanted = _hex(key, values, _MAX_CLIENT_ID_OCTETS)
    return lambda event: _HEX_SEPARATOR_RE.sub("", event.client_id).lower() in wanted


def _chaddr(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    # `chaddr` is raw octets with `hlen` up to 16, so it is compared as digits
    # and not parsed as a six-octet address.
    wanted = _hex(key, values, _MAX_CHADDR_OCTETS)
    return lambda event: event.message.chaddr.hex() in wanted


def _addresses(
    key: str, values: "_ty.Tuple[str, ...]"
) -> "_ty.Tuple[_ipaddress.IPv4Address, ...]":
    found = []
    for value in values:
        try:
            found.append(_ipaddress.IPv4Address(value))
        except ValueError:
            raise ValueError(
                f"Capture filter {key}= expects an IPv4 address, got {value!r}"
            ) from None
    return tuple(found)


def _src(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    wanted = _addresses(key, values)
    return lambda event: event.source.ip in wanted


def _dst(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    wanted = _addresses(key, values)
    return lambda event: event.destination.ip in wanted


def _src_port(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    wanted = tuple(_number(key, value, 0, 65535) for value in values)
    return lambda event: event.source.port in wanted


def _dst_port(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    wanted = tuple(_number(key, value, 0, 65535) for value in values)
    return lambda event: event.destination.port in wanted


def _interface(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    # An adapter that does not exist yet may appear while the capture runs, so a
    # name cannot be refused here.
    # An event read from a capture file heard nothing on a local interface.
    return lambda event: (
        event.context is not None and event.context.interface.name in values
    )


_CLAUSES: (
    "_ty.Dict[str, _ty.Callable[[str, _ty.Tuple[str, ...]], CapturePredicate]]"
) = {
    "op": _op,
    "msg_type": _msg_type,
    "xid": _xid,
    "client_id": _client_id,
    "chaddr": _chaddr,
    "src": _src,
    "src_port": _src_port,
    "dst": _dst,
    "dst_port": _dst_port,
    "interface": _interface,
}


def _option(key: str, value: str) -> CapturePredicate:
    """`option.NAME=text` or `option.NUMBER=text`: the option's text, whole.

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
    return lambda event: _option_text(event.message, code) == value


def _option_text(
    message: DHCPMessage, code: "_ty.Union[int, DHCPOptionCode]"
) -> _ty.Optional[str]:
    value = message.options.get(code)
    if value is None:
        return None
    if isinstance(value, _enum.Enum):
        return value.name
    if is_codec(value):
        return str(value.to_json())
    return str(value)
