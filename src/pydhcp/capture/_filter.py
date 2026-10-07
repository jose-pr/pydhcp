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

    An expression is `key=value` or `key!=value` clauses joined by `and` (any
    letter case, a space on both sides; there is no `or`, and it may not end in
    `and`); `!=` selects what the clause does not. The keys are `op`, `msg_type`,
    `xid`, `client_id`, `chaddr`, `src`, `src_port`, `dst`, `dst_port`,
    `interface` and `option.NAME_OR_CODE`, which compares the option's decoded
    value (an enum's name, else its text) as one text, so a comma in it is part
    of it. For every other key a comma means any of:
    `msg_type=DHCPDISCOVER,DHCPREQUEST`.

    `op` and `msg_type` take a member's name in any letter case or a number from
    0 to 255, named or not; `msg_type` also takes `UNKNOWN` (a message with no
    option 53) and `TYPE_<n>` (an unnamed type). `xid` is an integer in any base up
    to 32 bits, the ports are 0 to 65535, `src` and `dst` are IPv4 addresses and
    `interface` is an adapter name, compared as written. `client_id` and `chaddr`
    are whole octets in hexadecimal with `:`, `-` or `.` between groups, compared
    without them, so `00:11:22:33:44:55` and `001122334455` are one filter.

    Raises `pktcap.CaptureFilterError` (a `ValueError`) naming the clause for a
    malformed expression, an unknown key or name, a number out of range, hex that
    is not octets, an `option.` code outside 1 to 254, or any other value no
    packet could match: a typo is one start-up error, not a capture that reports
    nothing.
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


# Each `*_matcher` converts a clause's values, raising `ValueError` for one no message
# could match, and returns a test of the value the clause reads. This module's filter
# and the pktcap plugin both build on them, so the two cannot read a value differently.


def op_matcher(key: str, values: "_ty.Tuple[str, ...]") -> "_ty.Callable[[int], bool]":
    """A test of an opcode's number."""
    names = _names(DHCPOpcode)
    wanted = tuple(_named_number(key, value, names) for value in values)
    return lambda number: number in wanted


def _op(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    matches = op_matcher(key, values)
    return lambda event: matches(int(event.message.op))


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


def _msg_type(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    matches = msg_type_matcher(key, values)

    def of_event(event: CaptureEvent) -> bool:
        kind = event.message.message_type
        return matches(None if kind is None else int(kind))

    return of_event


def xid_matcher(key: str, values: "_ty.Tuple[str, ...]") -> "_ty.Callable[[int], bool]":
    """A test of a transaction id."""
    wanted = tuple(_number(key, value, 0, 0xFFFFFFFF) for value in values)
    return lambda xid: xid in wanted


def _xid(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    matches = xid_matcher(key, values)
    return lambda event: matches(event.message.xid)


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


def _client_id(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    matches = client_id_matcher(key, values)
    return lambda event: matches(event.client_id)


def chaddr_matcher(
    key: str, values: "_ty.Tuple[str, ...]"
) -> "_ty.Callable[[str], bool]":
    """A test of a hardware address's text: hex digits with any separators."""
    # `chaddr` is raw octets with `hlen` up to 16, so it is compared as digits
    # and not parsed as a six-octet address.
    wanted = _hex(key, values, _MAX_CHADDR_OCTETS)
    return lambda text: _HEX_SEPARATOR_RE.sub("", text).lower() in wanted


def _chaddr(key: str, values: "_ty.Tuple[str, ...]") -> CapturePredicate:
    matches = chaddr_matcher(key, values)
    return lambda event: matches(event.message.chaddr.hex())


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


def _option(key: str, value: str) -> CapturePredicate:
    code, wanted = option_selector(key, value)
    return lambda event: _option_text(event.message, code) == wanted


def _option_text(
    message: DHCPMessage, code: "_ty.Union[int, DHCPOptionCode]"
) -> _ty.Optional[str]:
    return option_value_text(message.options.get(code))


def option_value_text(value: _ty.Any) -> _ty.Optional[str]:
    """A decoded option value as the text a clause compares: an enum's name, else its JSON form."""
    if value is None:
        return None
    if isinstance(value, _enum.Enum):
        return value.name
    if is_codec(value):
        return str(value.to_json())
    return str(value)
