"""What a capture records and how a filter chooses: events, filters and filename patterns."""

from __future__ import annotations

import ipaddress as _ipaddress
import dataclasses as _data
import datetime as _dt
import enum as _enum_base
import re as _re
import string as _string
import typing as _ty

from .. import _network as _net
from ..listener._receive import DHCPRequestContext
from ..options._codes import DHCPOptionCode
from ..exceptions import NoClientIdentityError
from ..packet._message import DHCPMessage
from ..options._codecs._base import is_codec

#: The placeholders `CaptureEvent.format_filename` fills in, and so the only
#: ones a `--output-mode per-capture` filename pattern may name.
FILENAME_FIELDS: _ty.Final = ("client_id", "timestamp", "msg_type", "xid", "format")

#: The subset of those that differs between two packets of one capture. A
#: pattern naming none of them resolves to the same filename for packets that
#: agree on the rest, and each record then overwrites the last.
UNIQUE_FILENAME_FIELDS: _ty.Final = frozenset({"timestamp", "xid"})

_SAFE_FILENAME_RE = _re.compile(r"[^A-Za-z0-9_.-]+")
_AND_SEPARATOR_RE = _re.compile(r"\s+and\s+", _re.IGNORECASE)
_OR_TOKEN_RE = _re.compile(r"(?:^|\s)or(?:\s|$)", _re.IGNORECASE)
_HEX_SEPARATOR_RE = _re.compile(r"[:.-]")


@_data.dataclass(frozen=True)
class CaptureEvent:
    message: DHCPMessage
    context: DHCPRequestContext
    captured_at: _dt.datetime

    @property
    def source(self) -> _net.SocketAddress:
        return self.context.client

    @property
    def destination(self) -> _net.SocketAddress:
        local_ip = self.context.local_ip or _ty.cast(
            _ipaddress.IPv4Address, self.context.interface.ip
        )
        # The port the packet was received on. Hardcoding 0 here made the
        # documented `dst_port=` filter key unable to match anything, while
        # still passing validation -- so a filter using it silently dropped
        # every packet.
        port = 0
        socket = getattr(self.context.transport, "socket", None)
        if socket is not None:
            try:
                port = int(socket.getsockname()[1])
            except Exception:  # pragma: no cover - closed or unusual socket
                port = 0
        return _net.SocketAddress(local_ip, port)

    @property
    def message_type(self) -> str:
        value = self.message.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
        if value is None:
            return "UNKNOWN"
        return value.name if hasattr(value, "name") else str(value)

    @property
    def client_id(self) -> str:
        try:
            return self.message.get_client_id()
        except NoClientIdentityError:
            # A capture reports what arrived; a client with no identity is
            # exactly the sort of packet someone runs a capture to look at.
            return "UNKNOWN"

    @property
    def xid(self) -> str:
        return f"{self.message.xid:08X}"

    def format_filename(self, pattern: str, format: str) -> str:
        values = {
            "client_id": _sanitize_filename_value(self.client_id),
            "timestamp": _sanitize_filename_value(
                self.captured_at.strftime("%Y%m%dT%H%M%S.%fZ")
            ),
            "msg_type": _sanitize_filename_value(self.message_type),
            "xid": _sanitize_filename_value(self.xid),
            "format": _sanitize_filename_value(format),
        }
        return pattern.format(**values)


CapturePredicate = _ty.Callable[[CaptureEvent], bool]
#: What `packet_filter` accepts: a filter expression, or the predicate itself.
PacketFilterLike = _ty.Union[str, CapturePredicate]
CaptureHook = _ty.Callable[[CaptureEvent], None]
CaptureSink = _ty.Callable[[CaptureEvent], None]


def validate_filename_pattern(pattern: str) -> frozenset[str]:
    """Check a per-capture filename pattern; return the fields it names.

    Raises `ValueError` for a malformed pattern or one naming a placeholder
    `format_filename` cannot fill. This belongs at startup because
    `format_filename` is only ever called from the receive handler, where a
    `KeyError` lands inside the listener's per-packet `except` -- so
    `--output "cap_{mac}.json"` started cleanly, recorded nothing, and logged
    the same traceback once per packet on the segment instead of once.

    Format specs are allowed (`{client_id:>12}`): `string.Formatter().parse`
    hands back the field name separately from its spec. Anything else that is
    not a bare field name -- `{}`, `{0}`, `{xid.real}` -- is rejected, because
    `format_filename` formats against a plain dict of the five values and
    nothing else resolves against it.
    """

    def fields_of(text: str) -> "_ty.Iterator[str]":
        try:
            parsed = list(_string.Formatter().parse(text))
        except ValueError as error:
            raise ValueError(
                f"Invalid capture filename pattern {pattern!r}: {error}"
            ) from None
        for _literal, field, spec, _conversion in parsed:
            if field is not None:
                yield field
            # `str.format` resolves one level of nesting inside a spec, e.g.
            # `{xid:{format}}`, and those names have to be real too.
            if spec:
                yield from fields_of(spec)

    used: set[str] = set()
    for field in fields_of(pattern):
        if field not in FILENAME_FIELDS:
            named = "{}" if not field else "{" + field + "}"
            raise ValueError(
                f"Invalid capture filename pattern {pattern!r}: {named} is not a "
                f"capture field. Available: "
                + ", ".join("{" + name + "}" for name in FILENAME_FIELDS)
            )
        used.add(field)
    return frozenset(used)


def compile_capture_filter(text: _ty.Optional[str]) -> CapturePredicate:
    if text is None or not text.strip():
        return lambda event: True

    checks: list[CapturePredicate] = []
    # Both the `and` split and the `or` rejection are case-insensitive. Measured
    # with the case-sensitive versions: `src=192.0.2.55 AND msg_type=DHCPDISCOVER`
    # compiled into one clause whose value was the whole remainder, and
    # `msg_type=DHCPDISCOVER OR msg_type=DHCPOFFER` compiled too (the lowercase
    # `or` correctly raised). Both then matched every packet away and exited 0 --
    # indistinguishable from "no traffic", which is the exact conclusion someone
    # runs a capture to reach.
    for part in _AND_SEPARATOR_RE.split(text.strip()):
        if not part or "=" not in part:
            raise ValueError(f"Unsupported capture filter expression: {part!r}")
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            raise ValueError(f"Unsupported capture filter expression: {part!r}")
        if key.lower() == "or" or _OR_TOKEN_RE.search(part):
            raise ValueError("Capture filters support 'and' only")
        checks.append(_compile_clause(key, value))

    def predicate(event: CaptureEvent) -> bool:
        return all(check(event) for check in checks)

    return predicate


def _sanitize_filename_value(value: str) -> str:
    return _SAFE_FILENAME_RE.sub("_", value).strip("._") or "unknown"


def _compile_clause(key: str, value: str) -> CapturePredicate:
    """Build the per-packet test for one `key=value` clause.

    The value is converted here, not inside the returned predicate. Converting
    per packet meant `xid=zz` compiled cleanly and then raised `ValueError` from
    inside the listener's per-packet handler for every packet on the segment --
    a log flood where one startup error belonged.
    """
    if key == "op":
        return lambda event: event.message.op.name == value
    if key == "msg_type":
        return lambda event: event.message_type == value
    if key == "xid":
        xid = _filter_int(key, value, base=0)
        return lambda event: event.message.xid == xid
    if key == "client_id":
        # `DHCPMessage.get_client_id()` always returns colon-separated hex, so
        # stripping separators cannot corrupt a free-form identifier -- while
        # `pydhcp interfaces` prints hardware addresses uppercase-hyphenated
        # (`MACAddress.__str__`, e.g. 68-F7-D8-E5-1E-83), which was the one form
        # the colon-only comparison rejected. Pasting from that command matched
        # nothing.
        wanted_id = _hex_digits(value)
        return lambda event: _hex_digits(event.client_id) == wanted_id
    if key == "chaddr":
        # Same normalization. `chaddr` is raw bytes with `hlen` up to 16, so it
        # is compared as hex digits rather than parsed as a 6-byte MAC.
        wanted_chaddr = _hex_digits(value)
        return lambda event: event.message.chaddr.hex() == wanted_chaddr
    if key == "src":
        src_ip = _filter_ip(key, value)
        return lambda event: event.source.ip == src_ip
    if key == "src_port":
        src_port = _filter_int(key, value)
        return lambda event: event.source.port == src_port
    if key == "dst":
        dst_ip = _filter_ip(key, value)
        return lambda event: event.destination.ip == dst_ip
    if key == "dst_port":
        dst_port = _filter_int(key, value)
        return lambda event: event.destination.port == dst_port
    if key == "interface":
        return lambda event: event.context.interface.name == value
    if key.startswith("option.") and len(key) > len("option."):
        option_key = key[len("option.") :]
        if not option_key.isdigit():
            try:
                DHCPOptionCode[option_key]
            except KeyError:
                raise ValueError(
                    f"Unsupported DHCP option filter key: {key!r}"
                ) from None
        return lambda event: _option_value(event.message, option_key) == value
    raise ValueError(f"Unsupported capture filter key: {key!r}")


def _hex_digits(value: str) -> str:
    return _HEX_SEPARATOR_RE.sub("", value).lower()


def _filter_int(key: str, value: str, base: int = 10) -> int:
    try:
        return int(value, base)
    except ValueError:
        raise ValueError(
            f"Capture filter {key}= expects an integer, got {value!r}"
        ) from None


def _filter_ip(key: str, value: str) -> _ipaddress.IPv4Address:
    try:
        return _ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError(
            f"Capture filter {key}= expects an IPv4 address, got {value!r}"
        ) from None


def _option_value(message: DHCPMessage, key: str) -> _ty.Optional[str]:
    raw_code: int | DHCPOptionCode
    if key.isdigit():
        raw_code = int(key)
    else:
        raw_code = DHCPOptionCode[key]
    value = message.options.get(raw_code)
    if value is None:
        return None
    if isinstance(value, _enum_base.Enum):
        return value.name
    if is_codec(value):
        return str(value.to_json())
    return str(value)
