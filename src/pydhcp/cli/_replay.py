"""`pydhcp replay`: pktcap's replay command, sending to the DHCP server port."""

from __future__ import annotations

import typing as _ty

import pktcap.cli as _cli

from ._common import _Configured, closed_stdout
from ._packets import _DHCPPackets


class Replay(_Configured, _DHCPPackets, _cli.Replay):
    """Send the DHCP requests of a capture file again, to the server --to names"""

    _parsername_ = "replay"
    # Not a tool: it puts datagrams on a network.
    _mcp_ = False
    _filter_ = "dport=67"
    _default_port_ = 67
    _env_prefix_ = "PYDHCP_REPLAY_"

    def _report(self, result: _ty.Any) -> _ty.Optional[int]:
        try:
            return super()._report(result)
        except OSError as error:
            closed = closed_stdout(error)
            if closed is not None:
                raise closed from None
            raise
