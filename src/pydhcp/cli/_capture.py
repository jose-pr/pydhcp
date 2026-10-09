"""`pydhcp capture`: pktcap's capture command, listening on the DHCP ports."""

from __future__ import annotations

import pathlib
import sys
import typing as _ty

import netimps as _netimps
import pktcap as _pktcap
import pktcap.cli as _cli
from duho import Meta

from .. import _network as _net
from ..capture._dissector import DHCP_PORTS, DHCPLayer, dissect_dhcp
from ..capture._source import bound_endpoints
from ._common import _Listening, closed_stdout
from ._packets import _DHCPPackets

_NOT_LINUX = (
    "live capture needs Linux (AF_PACKET); pipe a capture tool's output in "
    "instead: tcpdump -w - | pydhcp capture --read -"
)


class Capture(_Listening, _DHCPPackets, _cli.Capture):
    """Capture DHCP messages from UDP sockets (no privilege), an interface (Linux) or a capture file"""

    _parsername_ = "capture"
    # Not a tool: it does not return until it is stopped, and starts a program per message.
    _mcp_ = False
    _filter_ = "proto=dhcp"
    _fields_ = ("client_id", "msg_type", "xid")
    _default_port_ = DHCP_PORTS
    # A hook is code: it comes from the option, the variable and the settings file the
    # user named, and from nowhere else.
    _hook_from_ = ("argument", "environment", "file")
    _listen_excludes_ = "source"

    listen: _ty.Optional[str] = None  # type: ignore[assignment]
    "Listen address/port spec, for example '*', '127.0.0.1:6767,127.0.0.1:6768' or an interface ('eth1', 'eth1:67', 'aa-bb-cc-dd-ee-ff'). Default: every address, ports 67 and 68. Excludes --interface and --read"
    ("--listen", "-l")

    interface: _ty.Annotated[
        _ty.Optional[str],
        Meta(conflicts="source", env="PYDHCP_CAPTURE_INTERFACE"),
    ] = None
    "Capture the frames of this interface instead of listening on sockets (Linux, needs CAP_NET_RAW), by name, address or MAC. Excludes --listen and --read"
    ("--interface",)

    read: _ty.Annotated[
        _ty.Optional[pathlib.Path],
        Meta(conflicts="source", env="PYDHCP_CAPTURE_READ"),
    ] = None
    "Read the DHCP messages of this pcap or pcapng capture file ('-' is standard input) instead of listening, through the same filter, output and hook. Excludes --listen and --interface"
    ("--read",)

    filter: _ty.Annotated[
        _ty.Optional[str], Meta(metavar="EXPRESSION", env="PYDHCP_CAPTURE_FILTER")
    ] = None
    "Keep only what matches key=value clauses joined by 'and': src, dst, host, sport, dport, port, proto, linktype, LAYER.FIELD and the DHCP keys op, msg_type, xid, client_id, chaddr and option.NAME, for example 'msg_type=DHCPDISCOVER and xid=0x1a2b'. Default: every DHCP message"
    ("--filter", "-f")

    _dissected: _ty.Optional[_pktcap.FrameDissector] = None

    def _names(self, frame: _pktcap.DissectedFrame) -> _ty.Mapping[str, object]:
        layer = frame.layer(DHCPLayer)
        assert layer is not None  # the filter keeps only frames that have one
        return {
            "client_id": layer.client_id,
            "msg_type": layer.message_type,
            "xid": f"{layer.xid:08X}",
        }

    def _frames(
        self, dissector: _pktcap.FrameDissector
    ) -> _ty.Iterator[_pktcap.DissectedFrame]:
        if self.read is not None:
            return self._file(dissector)
        if self.interface is None:
            if self.listen is None:
                self.listen = "*"
        elif not _pktcap.has_live_capture():
            raise _pktcap.LiveCaptureError(_NOT_LINUX)
        self._dissected = dissector
        return super()._frames(dissector)

    def _file(
        self, dissector: _pktcap.FrameDissector
    ) -> _ty.Iterator[_pktcap.DissectedFrame]:
        name = str(self.read)
        source = sys.stdin.buffer if name == "-" else name
        try:
            yield from _pktcap.read_dissected(source, dissector=dissector)
        except _pktcap.CaptureFormatError as error:
            raise ValueError(f"{name}: {error}") from None

    def _endpoints(self) -> _ty.Tuple[_netimps.UDPEndpoint, ...]:
        endpoints = bound_endpoints(self.listen, self.per_interface)
        for endpoint in endpoints:
            self._logger_.info(
                "Bound: %s", _net.SocketAddress.from_socket(endpoint.socket)
            )
            if self._dissected is not None:
                # DHCP is read on the port a socket is bound to, whichever it is.
                port = int(endpoint.socket.getsockname()[1])
                self._dissected.registry.register(
                    "udp", port, dissect_dhcp, replace=True
                )
        return endpoints

    def __call__(self) -> _ty.Optional[int]:
        try:
            return super().__call__()
        except OSError as error:
            closed = closed_stdout(error) if self.output == "-" else None
            if closed is not None:
                raise closed from None
            raise
