"""`pydhcp replay`: send the requests of a capture file again, to a server you name."""

from __future__ import annotations

import pathlib
import sys
import typing as _ty

import pktcap as _pktcap
from duho import Meta

from ..capture._offline import replay_capture
from ._common import _Command, write_line
from ._relay import _parse_server_address


class Replay(_Command):
    """Send the DHCP requests of a capture file again"""

    _parsername_ = "replay"
    # Not a tool: it puts datagrams on a network.
    _mcp_ = False

    input: _ty.Annotated[pathlib.Path, Meta(env="PYDHCP_REPLAY_INPUT")] = pathlib.Path(
        "-"
    )
    "The pcap or pcapng capture file, or '-' for standard input"
    ("--input", "-i")

    server: _ty.Annotated[
        _ty.Optional[str], Meta(env="PYDHCP_REPLAY_SERVER", required=True)
    ] = None
    "The server to send to, HOST or HOST:PORT (port 67 by default). The addresses in the capture are never sent to. Required"
    ("--server", "-s")

    speed: _ty.Annotated[float, Meta(env="PYDHCP_REPLAY_SPEED")] = 1.0
    "How fast to replay: 1 keeps the recorded waits, 2 halves each"
    ("--speed",)

    no_delay: _ty.Annotated[bool, Meta(env="PYDHCP_REPLAY_NO_DELAY")] = False
    "Send with no wait between datagrams (a replay sends no faster than the capture did unless asked)"
    ("--no-delay",)

    max_delay: _ty.Annotated[float, Meta(env="PYDHCP_REPLAY_MAX_DELAY")] = 5.0
    "The longest single wait, in seconds"
    ("--max-delay",)

    limit: _ty.Annotated[_ty.Optional[int], Meta(env="PYDHCP_REPLAY_LIMIT")] = None
    "Stop after this many datagrams. Default: all of them"
    ("--limit",)

    def __call__(self) -> None:
        host, port = _parse_server_address(self.server or "")
        name = str(self.input)
        source = sys.stdin.buffer if name == "-" else name
        try:
            result = replay_capture(
                source,
                host,
                port,
                speed=None if self.no_delay else self.speed,
                max_delay=self.max_delay,
                limit=self.limit,
            )
        except _pktcap.CaptureFormatError as error:
            raise ValueError(f"{name}: {error}") from None
        write_line(
            f"{result.sent} datagrams sent, {result.partial} partial passed over"
        )
