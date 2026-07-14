from __future__ import annotations

import dataclasses as _data
import datetime as _dt
import enum as _enum_base
import re as _re
import typing as _ty

from . import network as _net
from .packet import enums as _enum
from .listener import DhcpListener, ListenSpec, RequestContext
from .log import LOGGER
from .options import DhcpOptionCode
from .packet.message import DhcpMessage
from .options import DhcpOptionType

CapturePredicate = _ty.Callable[["CaptureEvent"], bool]
CaptureHook = _ty.Callable[["CaptureEvent"], None]
CaptureSink = _ty.Callable[["CaptureEvent"], None]

_SAFE_FILENAME_RE = _re.compile(r"[^A-Za-z0-9_.-]+")


@_data.dataclass(frozen=True)
class CaptureEvent:
    message: DhcpMessage
    context: RequestContext
    captured_at: _dt.datetime

    @property
    def source(self) -> _net.SocketAddress:
        return self.context.client

    @property
    def destination(self) -> _net.SocketAddress:
        local_ip = self.context.local_ip or _ty.cast(_net.IPv4, self.context.interface.ip)
        return _net.SocketAddress(local_ip, 0)

    @property
    def message_type(self) -> str:
        value = self.message.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
        if value is None:
            return "UNKNOWN"
        return value.name if hasattr(value, "name") else str(value)

    @property
    def client_id(self) -> str:
        return self.message.client_id()

    @property
    def xid(self) -> str:
        return f"{self.message.xid:08X}"

    def format_filename(self, pattern: str, format: str) -> str:
        values = {
            "client_id": _sanitize_filename_value(self.client_id),
            "timestamp": _sanitize_filename_value(self.captured_at.strftime("%Y%m%dT%H%M%S.%fZ")),
            "msg_type": _sanitize_filename_value(self.message_type),
            "xid": _sanitize_filename_value(self.xid),
            "format": _sanitize_filename_value(format),
        }
        return pattern.format(**values)


def compile_capture_filter(text: str | None) -> CapturePredicate:
    if text is None or not text.strip():
        return lambda event: True

    checks: list[tuple[str, str]] = []
    for part in _re.split(r"\s+and\s+", text.strip()):
        if not part or "=" not in part:
            raise ValueError(f"Unsupported capture filter expression: {part!r}")
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            raise ValueError(f"Unsupported capture filter expression: {part!r}")
        if key == "or" or " or " in part:
            raise ValueError("Capture filters support 'and' only")
        _validate_filter_key(key)
        checks.append((key, value))

    def predicate(event: CaptureEvent) -> bool:
        return all(_match_filter(event, key, value) for key, value in checks)

    return predicate


class DhcpCapture(DhcpListener):
    def __init__(
        self,
        listen: ListenSpec = None,
        packet_filter: str | CapturePredicate | None = None,
        sink: CaptureSink | None = None,
        hook: CaptureHook | None = None,
        hook_fail_fast: bool = False,
        select_timeout: float | None = None,
        max_packet_size: int | None = None,
        per_interface: bool | None = None,
    ) -> None:
        super().__init__(
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self.packet_filter = (
            compile_capture_filter(packet_filter)
            if isinstance(packet_filter, str) or packet_filter is None
            else packet_filter
        )
        self.sink = sink
        self.hook = hook
        self.hook_fail_fast = hook_fail_fast
        self.accepted_count = 0

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        event = CaptureEvent(
            message=msg,
            context=context,
            captured_at=_dt.datetime.now(tz=_dt.timezone.utc),
        )
        if not self.packet_filter(event):
            return
        self.accepted_count += 1
        if self.sink is not None:
            self.sink(event)
        if self.hook is not None:
            try:
                self.hook(event)
            except Exception:
                LOGGER.exception("Capture hook failed")
                if self.hook_fail_fast:
                    raise


def _sanitize_filename_value(value: str) -> str:
    return _SAFE_FILENAME_RE.sub("_", value).strip("._") or "unknown"


def _validate_filter_key(key: str) -> None:
    if key in {
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
    }:
        return
    if key.startswith("option.") and len(key) > len("option."):
        option_key = key[len("option.") :]
        if not option_key.isdigit():
            try:
                DhcpOptionCode[option_key]
            except KeyError:
                raise ValueError(f"Unsupported DHCP option filter key: {key!r}") from None
        return
    raise ValueError(f"Unsupported capture filter key: {key!r}")


def _match_filter(event: CaptureEvent, key: str, value: str) -> bool:
    if key == "op":
        return event.message.op.name == value
    if key == "msg_type":
        return event.message_type == value
    if key == "xid":
        return event.message.xid == int(value, 0)
    if key == "client_id":
        return event.client_id == value.upper()
    if key == "chaddr":
        return event.message.chaddr.hex(":").upper() == value.upper()
    if key == "src":
        return str(event.source.ip) == value
    if key == "src_port":
        return event.source.port == int(value)
    if key == "dst":
        return str(event.destination.ip) == value
    if key == "dst_port":
        return event.destination.port == int(value)
    if key == "interface":
        return event.context.interface.name == value
    if key.startswith("option."):
        option_value = _option_value(event.message, key[len("option.") :])
        return option_value == value
    raise ValueError(f"Unsupported capture filter key: {key!r}")


def _option_value(message: DhcpMessage, key: str) -> str | None:
    raw_code: int | DhcpOptionCode
    if key.isdigit():
        raw_code = int(key)
    else:
        raw_code = DhcpOptionCode[key]
    value = message.options.get(raw_code)
    if value is None:
        return None
    if isinstance(value, _enum_base.Enum):
        return value.name
    if isinstance(value, DhcpOptionType):
        return str(value.__json__())
    return str(value)
