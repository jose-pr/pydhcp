"""What a capture records: events, the text of a record, and filename patterns."""

from __future__ import annotations

import ipaddress as _ipaddress
import dataclasses as _data
import datetime as _dt
import json as _json
import typing as _ty

from .. import _network as _net
from ..listener._receive import DHCPRequestContext
from ..exceptions import NoClientIdentityError
from ..packet._message import DHCPMessage


def message_type_text(message: DHCPMessage) -> str:
    """The name of the message's type, `UNKNOWN` when it has no option 53."""
    value = message.message_type
    return "UNKNOWN" if value is None else value.label()


def client_id_text(message: DHCPMessage) -> str:
    """The client identifier as colon-separated upper-case hex, `UNKNOWN` when there is none to give."""
    try:
        return message.get_client_id()
    except NoClientIdentityError:
        # A capture reports what arrived; a client with no identity is
        # exactly the sort of packet someone runs a capture to look at.
        return "UNKNOWN"


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
    def payload(self) -> _ty.Optional[bytes]:
        """The datagram as it arrived, or `None` when the context holds none."""
        return self.context.payload

    @property
    def message_type(self) -> str:
        return message_type_text(self.message)

    @property
    def client_id(self) -> str:
        return client_id_text(self.message)

    @property
    def xid(self) -> str:
        return f"{self.message.xid:08X}"


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
