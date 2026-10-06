"""DHCP messages out of a capture file, and a capture file sent again."""

from __future__ import annotations

import datetime as _dt
import os as _os
import typing as _ty

import pktcap as _pktcap

from .. import _network as _net
from ..packet._message import DHCPMessage
from ..packet._enums import DHCPPort
from ._dissector import DHCP_PORTS, DHCPLayer, dissect_dhcp
from ._events import CaptureEvent, PacketFilterLike
from ._filter import compile_capture_filter

_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)

CaptureFile = _ty.Union[str, "_os.PathLike[str]", _ty.BinaryIO]


def capture_dissector(
    ports: _ty.Iterable[int] = DHCP_PORTS,
) -> _pktcap.FrameDissector:
    """A frame dissector that reads DHCP on `ports`, over a copy of pktcap's registry.

    The process-wide registry is not changed, and whatever else is registered there
    is read as well. Its `stats` say what could not be read.
    """
    registry = _pktcap.default_registry().copy()
    for port in ports:
        registry.register("udp", port, dissect_dhcp, replace=True)
    return _pktcap.FrameDissector(registry)


def unread_note(name: str, frames: _pktcap.FrameDissector) -> str:
    """One line saying what a read of `name` could not read, or `""` when it all was.

    Counts the frames that held a message that did not decode or a layer nothing
    could read (`malformed`), a dissector that failed (`failed`) and those of a
    link type nothing dissects (`unsupported`, with their `LINKTYPE_` numbers).
    """
    stats = frames.stats
    parts = []
    if stats.malformed:
        parts.append(f"{stats.malformed} cut short or damaged")
    if stats.failed:
        parts.append(f"{stats.failed} that a dissector failed on")
    if stats.unsupported:
        kinds = ", ".join(str(n) for n in sorted(frames.unsupported_linktypes))
        parts.append(f"{stats.unsupported} of a link type nothing here reads ({kinds})")
    if not parts:
        return ""
    return f"pydhcp: {name}: of {stats.frames} frames, " + "; ".join(parts)


def _heard_at(seconds: float) -> _dt.datetime:
    """The capture's time as an aware UTC time; the epoch when it is not a time."""
    try:
        return _EPOCH + _dt.timedelta(seconds=seconds)
    except (OverflowError, ValueError):
        return _EPOCH


def read_capture(
    source: CaptureFile,
    *,
    packet_filter: _ty.Optional[PacketFilterLike] = None,
    ports: _ty.Iterable[int] = DHCP_PORTS,
    dissector: _ty.Optional[_pktcap.FrameDissector] = None,
) -> _ty.Iterator[CaptureEvent]:
    """The DHCP messages of a pcap or pcapng capture, as events, in file order.

    `source` is a path or a binary stream (`pktcap.read_frames`). An event is made
    for each UDP datagram to or from one of `ports` (67 and 68) that the DHCP
    dissector read and that passes `packet_filter` (text or a predicate, as for
    `DHCPCapture`). It has no `context`: `datagram` holds the addresses and the
    octets, `captured_at` is the datagram's time (the epoch when the file's time is
    not one), and the `interface` filter key fails its clause. Datagrams between
    IPv6 addresses are not DHCP for IPv4 and are passed over.

    Frames that hold no readable message are not an error: with the default
    `dissector` they are counted in its `stats`, so pass your own
    `FrameDissector` (`capture_dissector()`) to read them afterwards. A `dissector`
    given must have `dissect_dhcp` registered on `ports`. Arguments are checked at
    the call; the file is read, and a damaged capture raises
    `pktcap.CaptureFormatError` after the events before the damage, while iterating.
    """
    wanted = frozenset(ports)
    test = (
        compile_capture_filter(packet_filter)
        if isinstance(packet_filter, str) or packet_filter is None
        else packet_filter
    )
    frames = dissector if dissector is not None else capture_dissector(wanted)
    return _events(source, wanted, test, frames)


def _events(
    source: CaptureFile,
    ports: "_ty.FrozenSet[int]",
    test: _ty.Callable[[CaptureEvent], bool],
    frames: _pktcap.FrameDissector,
) -> _ty.Iterator[CaptureEvent]:
    for frame in _pktcap.read_dissected(source, dissector=frames):
        datagram = frame.datagram()
        if datagram is None or frame.layer(DHCPLayer) is None:
            continue
        if not ports & {datagram.source[1], datagram.destination[1]}:
            continue
        try:
            # The layer holds the message as a mapping; the octets give it back
            # exactly, whatever the sender left out or added.
            message = DHCPMessage.decode(datagram.payload)
            _net.SocketAddress(*datagram.source)
            _net.SocketAddress(*datagram.destination)
        except ValueError:
            continue
        event = CaptureEvent(message, None, _heard_at(datagram.time), datagram)
        if test(event):
            yield event


def replay_capture(
    source: _ty.Union[CaptureFile, _ty.Iterable[_pktcap.CapturedDatagram]],
    server: _ty.Any,
    port: int = int(DHCPPort.SERVER),
    *,
    endpoint: _ty.Any = None,
    speed: _ty.Optional[float] = 1.0,
    max_delay: float = 5.0,
    limit: _ty.Optional[int] = None,
) -> _pktcap.ReplayResult:
    """Send again the datagrams a capture shows going to port 67, to `server`.

    `source` is a pcap or pcapng capture (a path or a binary stream) or an iterable
    of `pktcap.CapturedDatagram`. Each datagram sent to UDP port 67 is sent as its
    payload, in order and with the recorded waits, to `server` at `port`
    (`pktcap.replay_to`): **the addresses in the capture are never sent to**, and a
    datagram to port 68 (a server's reply) is not sent at all. `endpoint` is a
    `netimps.UDPEndpoint` the caller made, to send from a chosen port or interface
    or to a broadcast address. `speed`, `max_delay` and `limit` are pktcap's:
    `speed=None` removes the waits, and `limit` ends the replay after that many
    datagrams. Returns
    `pktcap.ReplayResult(sent, partial)`. `OSError` when `server` does not resolve
    or a send fails.
    """
    datagrams: _ty.Iterable[_pktcap.CapturedDatagram] = (
        _pktcap.read_datagrams(source)  # type: ignore[arg-type]
        if isinstance(source, (str, _os.PathLike)) or hasattr(source, "read")
        else source
    )
    requests = (d for d in datagrams if d.destination[1] == int(DHCPPort.SERVER))
    return _pktcap.replay_to(
        requests,
        server,
        port,
        endpoint=endpoint,
        speed=speed,
        max_delay=max_delay,
        limit=limit,
    )
