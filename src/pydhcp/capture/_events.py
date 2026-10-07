"""What a capture records: events, the text of a record, and filename patterns."""

from __future__ import annotations

import ipaddress as _ipaddress
import dataclasses as _data
import datetime as _dt
import json as _json
import typing as _ty

import pktcap as _pktcap

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
    """One DHCP message a capture heard, or read from a capture file.

    A live event has a `context` (the receiving interface, the transport) and no
    `datagram`. An event read from a file has `datagram` (who sent what to whom,
    when) and no `context`, so nothing that names a local interface answers for it.
    """

    message: DHCPMessage
    context: _ty.Optional[DHCPRequestContext]
    captured_at: _dt.datetime
    datagram: _ty.Optional[_pktcap.CapturedDatagram] = None

    @property
    def source(self) -> _net.SocketAddress:
        """The client's address and port: where the datagram came from."""
        if self.context is None:
            return self._from_datagram(0)
        return self.context.client

    def _from_datagram(self, which: int) -> _net.SocketAddress:
        if self.datagram is None:
            raise ValueError("an event with no context holds no datagram either")
        host, port = (self.datagram.source, self.datagram.destination)[which]
        return _net.SocketAddress(host, port)

    @property
    def destination(self) -> _net.SocketAddress:
        """Where the datagram was sent: the port it arrived on, at a broadcast address for a client with no address."""
        if self.context is None:
            return self._from_datagram(1)
        # Where the datagram was sent: a broadcast for a client with no
        # address, not the address of the interface that heard it. Without
        # packet info (a socket bound to one address) the destination is the
        # address this host answers from.
        address = (
            self.context.destination
            or self.context.local_ip
            or _ty.cast(_ipaddress.IPv4Address, self.context.interface.ip)
        )
        # The port the packet was received on: the `dst_port=` filter key
        # compares against it, so a constant would pass validation and match
        # nothing.
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
        """The datagram as it arrived, or `None` when there is none to give."""
        if self.context is None:
            return None if self.datagram is None else self.datagram.payload
        return self.context.payload

    @property
    def message_type(self) -> str:
        """The message type's name (`DHCPDISCOVER`), `UNKNOWN` when there is no option 53."""
        return message_type_text(self.message)

    @property
    def client_id(self) -> str:
        """The client identifier as colon-separated upper-case hex, `UNKNOWN` when there is none."""
        return client_id_text(self.message)

    @property
    def xid(self) -> str:
        """The transaction id as eight upper-case hexadecimal digits."""
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
