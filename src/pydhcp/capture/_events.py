"""What a capture records: events, the text of a record, and filename patterns."""

from __future__ import annotations

import ipaddress as _ipaddress
import dataclasses as _data
import datetime as _dt
import hashlib as _hashlib
import json as _json
import re as _re
import string as _string
import typing as _ty

from .. import _network as _net
from ..listener._receive import DHCPRequestContext
from ..exceptions import NoClientIdentityError
from ..packet._message import DHCPMessage

#: The placeholders `CaptureEvent.format_filename` fills in, and so the only
#: ones a `--output-mode per-capture` filename pattern may name.
FILENAME_FIELDS: _ty.Final = ("client_id", "timestamp", "msg_type", "xid", "format")

#: The subset of those that differs between two packets of one capture. A
#: pattern naming none of them resolves to the same filename for packets that
#: agree on the rest, and each record then overwrites the last.
UNIQUE_FILENAME_FIELDS: _ty.Final = frozenset({"timestamp", "xid"})

_SAFE_FILENAME_RE = _re.compile(r"[^A-Za-z0-9_.-]+")


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
        # Where the datagram was sent: a broadcast for a client with no
        # address, not the address of the interface that heard it. Without
        # packet info (a socket bound to one address) the destination is the
        # address this host answers from.
        address = (
            self.context.destination
            or self.context.local_ip
            or _ty.cast(_ipaddress.IPv4Address, self.context.interface.ip)
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
        return _net.SocketAddress(address, port)

    @property
    def message_type(self) -> str:
        value = self.message.message_type
        if value is None:
            return "UNKNOWN"
        return value.label()

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


def serialize_event(event: CaptureEvent, packet_format: str) -> str:
    """One captured message in `packet_format`: what a record file holds and what
    a command hook reads on standard input.

    `json` is one compact line ending in a newline; `yaml`, `toml` and `ini` are
    `DHCPMessage.to_text`.
    """
    if packet_format == "json":
        return _json.dumps(event.message.to_mapping()) + "\n"
    return event.message.to_text(packet_format)


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


#: The longest a value interpolated into a filename may be, in characters. A
#: client identifier is up to 255 octets, which renders as 765 characters, and
#: no filesystem takes a path component that long.
MAX_FILENAME_VALUE = 64


def _sanitize_filename_value(value: str) -> str:
    """`value` as one safe path component of at most `MAX_FILENAME_VALUE` characters.

    A longer value is cut and ends in a hash of the whole, so two long values
    that agree at the start still name two files.
    """
    cleaned = _SAFE_FILENAME_RE.sub("_", value).strip("._") or "unknown"
    if len(cleaned) <= MAX_FILENAME_VALUE:
        return cleaned
    digest = _hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return f"{cleaned[: MAX_FILENAME_VALUE - 9].rstrip('._')}-{digest}"
