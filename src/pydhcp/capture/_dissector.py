"""DHCP as a pktcap layer: the dissector, its record and the call that registers it."""

from __future__ import annotations

import typing as _ty

import pktcap as _pktcap

from ..packet._message import DHCPMessage
from ._events import client_id_text, message_type_text

#: The ports a DHCP message is sent to: a client sends to the server's, a server or
#: relay replies to the client's, so between them they see every message.
DHCP_PORTS: _ty.Final = (67, 68)


class DHCPLayer(_ty.NamedTuple):
    """The DHCP message a datagram carries, as plain values.

    `op` is the opcode's name (`BOOTREQUEST`), `xid` the transaction id as a number,
    `message_type` the name of option 53 (`DHCPDISCOVER`, `UNKNOWN` without one),
    `client_id` the client identifier as colon-separated upper-case hex (option 61,
    else the hardware type and address; `UNKNOWN` when there is neither) and `message` the whole message as
    `DHCPMessage.to_mapping()`. A mapping is not hashable, so neither is the layer.
    """

    op: str
    xid: int
    message_type: str
    client_id: str
    message: _ty.Dict[str, _ty.Any]


def dissect_dhcp(data: bytes) -> _pktcap.Dissected:
    """Read the DHCP message `data` holds: its `DHCPLayer`, and no payload after it.

    Raises `pktcap.DissectError` (a `ValueError`) for octets that are not a message;
    its text is fixed and quotes none of them. Keeps the contract
    `pktcap.check_dissector` checks.
    """
    try:
        message = DHCPMessage.decode(data)
    except ValueError:
        raise _pktcap.DissectError("not a DHCP message") from None
    layer = DHCPLayer(
        message.op.name or str(int(message.op)),
        message.xid,
        message_type_text(message),
        client_id_text(message),
        message.to_mapping(),
    )
    return _pktcap.Dissected(layer, b"")


def register_dhcp_dissector(
    registry: _ty.Optional[_pktcap.DissectorRegistry] = None,
) -> None:
    """Have `registry` (default: pktcap's process-wide one) dissect UDP ports 67 and 68.

    Nothing registers on import. `ValueError`, with nothing registered by this call,
    when a port already has a dissector (pktcap's rule).
    """
    target = registry if registry is not None else _pktcap.default_registry()
    done: "_ty.List[int]" = []
    try:
        for port in DHCP_PORTS:
            target.register("udp", port, dissect_dhcp)
            done.append(port)
    except ValueError:
        for port in done:
            target.unregister("udp", port)
        raise
