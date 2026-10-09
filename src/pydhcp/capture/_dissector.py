"""DHCP as a pktcap layer: the dissector, its record and the call that registers it."""

from __future__ import annotations

import typing as _ty

from .. import _extras


from ..exceptions import NoClientIdentityError
from ..packet._message import DHCPMessage

if _ty.TYPE_CHECKING:
    import pktcap as _pktcap
else:
    _pktcap = _extras.lazy_pktcap

#: The ports a DHCP message is sent to: a client sends to the server's, a server or
#: relay replies to the client's, so between them they see every message.
DHCP_PORTS: _ty.Final = (67, 68)


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

    def summary(self) -> str:
        """One line for a person: the type, the transaction id, the client, and
        `yiaddr` and `giaddr` when they are not zero.

        `DHCPOFFER xid=1A52B52E client=01:02:00:00:99:00:02 yiaddr=10.99.0.100`.
        This is the text pktcap's `text` format shows for a frame whose innermost
        layer is this one.
        """
        parts = [f"{self.message_type} xid={self.xid:08X} client={self.client_id}"]
        for key in ("yiaddr", "giaddr"):
            value = self.message.get(key)
            if value and value != "0.0.0.0":
                parts.append(f"{key}={value}")
        return " ".join(parts)


def dissect_dhcp(data: bytes) -> "_pktcap.Dissected":
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
    registry: "_ty.Optional[_pktcap.DissectorRegistry]" = None,
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


def capture_dissector(
    ports: _ty.Iterable[int] = DHCP_PORTS,
) -> "_pktcap.FrameDissector":
    """A frame dissector that reads DHCP on `ports`, over a copy of pktcap's registry.

    The registry also declares :class:`DHCPLayer` and its filter keys (`msg_type`,
    `xid`, `client_id`, `chaddr`, `op`, `option.NAME`), so `proto=dhcp` and
    `msg_type=DHCPOFFER` compile against `dissector.registry`. The process-wide
    registry is not changed, and whatever else is registered there is read as well.
    Its `stats` say what could not be read.
    """
    from ._plugin import declare_dhcp_layer

    registry = _pktcap.default_registry().copy()
    declare_dhcp_layer(registry, replace=True)
    for port in ports:
        registry.register("udp", port, dissect_dhcp, replace=True)
    return _pktcap.FrameDissector(registry)
