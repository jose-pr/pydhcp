from __future__ import annotations

import dataclasses as _data
import datetime as _dt
import enum as _enum_base
import re as _re
import typing as _ty

from . import network as _net
from .listener import DhcpListener, ListenSpec, RequestContext
from .log import LOGGER
from .options import DhcpOptionCode
from .packet.message import DhcpMessage, NoClientIdentity
from .options import DhcpOptionType

CapturePredicate = _ty.Callable[["CaptureEvent"], bool]
CaptureHook = _ty.Callable[["CaptureEvent"], None]
CaptureSink = _ty.Callable[["CaptureEvent"], None]

_SAFE_FILENAME_RE = _re.compile(r"[^A-Za-z0-9_.-]+")
_AND_SEPARATOR_RE = _re.compile(r"\s+and\s+", _re.IGNORECASE)
_OR_TOKEN_RE = _re.compile(r"(?:^|\s)or(?:\s|$)", _re.IGNORECASE)
_HEX_SEPARATOR_RE = _re.compile(r"[:.-]")


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
        local_ip = self.context.local_ip or _ty.cast(
            _net.IPv4, self.context.interface.ip
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
        value = self.message.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
        if value is None:
            return "UNKNOWN"
        return value.name if hasattr(value, "name") else str(value)

    @property
    def client_id(self) -> str:
        try:
            return self.message.client_id()
        except NoClientIdentity:
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


def compile_capture_filter(text: str | None) -> CapturePredicate:
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
        #: The hook failure that stopped the capture, if `hook_fail_fast` is set.
        #: Lets a caller distinguish "stopped because the hook failed" from
        #: "stopped because it was asked to", which an exception swallowed by the
        #: listener loop could not.
        self.hook_error: _ty.Optional[BaseException] = None
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
            except Exception as exc:
                LOGGER.exception("Capture hook failed")
                if self.hook_fail_fast:
                    # Re-raising alone achieved nothing: handle() runs inside the
                    # listener's per-packet try, which logs and carries on, so
                    # capture kept running and still exited 0. Record the failure
                    # and stop the loop, so a caller can tell that it ended
                    # because of the hook rather than because it was asked to.
                    self.hook_error = exc
                    self.stop()
                    raise


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
        # `DhcpMessage.client_id()` always returns colon-separated hex, so
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
                DhcpOptionCode[option_key]
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


def _filter_ip(key: str, value: str) -> _net.IPv4:
    try:
        return _net.IPv4(value)
    except ValueError:
        raise ValueError(
            f"Capture filter {key}= expects an IPv4 address, got {value!r}"
        ) from None


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
