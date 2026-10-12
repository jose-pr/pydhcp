"""What `capture` and `replay` share: the DHCP plugin.

Imports `pktcap.cli`, so only the two commands that need the `pktcap` extra reach it.
"""

from __future__ import annotations

import pktcap.cli as _cli


class _DHCPPackets(_cli.Loading):
    """The options of a command that reads DHCP from pktcap's frames.

    `pydhcp.capture` is always loaded as a plugin, so the DHCP layer and its filter keys
    are there.
    """

    _plugins_ = ("pydhcp.capture",)
