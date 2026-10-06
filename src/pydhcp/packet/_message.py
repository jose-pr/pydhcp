"""The DHCP wire message.

`DHCPMessage` is defined in layers -- fields, decode, encode, mapping, display --
each in a private module of `pydhcp.packet`; import it from here.
"""

from __future__ import annotations

from ._display import _MessageDisplay


class DHCPMessage(_MessageDisplay):
    """A DHCPv4 message (RFC 2131 s2): the fixed BOOTP header, then options.

    The fields, `decode`/`encode`, `to_mapping`/`from_mapping`, `client_id` and
    the display helpers are inherited from the layers in `pydhcp.packet`; the
    dataclass `__init__`, `__repr__` and `__eq__` are the base layer's, and
    report this class.
    """


__all__ = ["DHCPMessage"]
