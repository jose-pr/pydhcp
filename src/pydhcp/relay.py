from __future__ import annotations

import logging as _logging
import typing as _ty

from .packet.message import DhcpMessage
from .listener import DhcpListener as _Base, ListenSpec, RequestContext
from . import network as _net
from .packet import enums as _enum
from .options import DhcpOptionCode
from .options import type as _type
from .log import LOGGER

ServerAddress = _ty.Union[_net.IPv4, str, tuple[_ty.Union[_net.IPv4, str], int]]


def _normalize_server_address(address: ServerAddress) -> tuple[_net.IPv4, int]:
    if isinstance(address, tuple):
        ip, port = address
        return _net.IPv4(ip), int(port)
    return _net.IPv4(address), int(_enum.DhcpPort.SERVER)


class DhcpRelay(_Base):
    """RFC 1542 / RFC 2131 4.1 / RFC 3046 DHCP relay agent.

    Forwards client broadcasts (received on port 67, same as a server) to one or
    more configured upstream DHCP servers, stamping `giaddr` and incrementing
    `hops`. Forwards server replies (unicast back to this relay) on to the
    client, applying the same destination rules a server uses on its own
    client-facing side (broadcast flag, else `yiaddr`/`ciaddr`).
    """

    DEFAULT_PORTS = (_enum.DhcpPort.SERVER,)

    def __init__(
        self,
        listen: ListenSpec = None,
        server_addresses: _ty.Sequence[ServerAddress] = (),
        max_hops: int = 16,
        insert_relay_agent_info: bool = False,
        circuit_id: _ty.Optional[bytes] = None,
        remote_id: _ty.Optional[bytes] = None,
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        per_interface: bool | None = None,
    ) -> None:
        if not server_addresses:
            raise ValueError("DhcpRelay requires at least one server address")
        super().__init__(
            listen=listen,
            select_timeout=select_timeout,
            max_packet_size=max_packet_size,
            per_interface=per_interface,
        )
        self.server_addresses = [_normalize_server_address(a) for a in server_addresses]
        self.max_hops = max_hops
        self.insert_relay_agent_info = insert_relay_agent_info
        self.circuit_id = circuit_id
        self.remote_id = remote_id
        self._pending_clients: dict[int, _net.SocketAddress] = {}

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        if msg.op == _enum.OpCode.BOOTREQUEST:
            self._forward_to_servers(msg, context)
        elif msg.op == _enum.OpCode.BOOTREPLY:
            self._forward_to_client(msg, context)
        else:
            LOGGER.warning(f"[XID={msg.xid:08x}] Received message with unknown op {msg.op}, ignoring.")

    def _forward_to_servers(self, msg: DhcpMessage, context: RequestContext) -> None:
        forwarded = DhcpMessage(**msg.__dict__.copy())
        forwarded.hops = msg.hops + 1
        if forwarded.hops > self.max_hops:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Dropping request from {context.client}: hop count {forwarded.hops} exceeds max_hops={self.max_hops}"
            )
            self.metrics.packets_dropped_hop_limit += 1
            return

        if forwarded.giaddr == _net.WILDCARD_IPv4:
            forwarded.giaddr = _ty.cast(_net.IPv4, context.interface.ip)

        self._pending_clients[msg.xid] = context.client
        self._insert_relay_agent_info(forwarded)

        data = forwarded.encode()
        for server_ip, server_port in self.server_addresses:
            forwarded.log(context.interface.ip, _net.SocketAddress(server_ip, server_port), _logging.INFO)
            context.transport.send(data, server_ip, server_port, msg.chaddr)
            self.metrics.packets_sent += 1

    def _insert_relay_agent_info(self, msg: DhcpMessage) -> None:
        if not self.insert_relay_agent_info:
            return
        if DhcpOptionCode.RELAY_AGENT_INFORMATION in msg.options:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Request already carries RELAY_AGENT_INFORMATION, passing through unmodified."
            )
            return
        suboptions: list[tuple[int, bytes]] = []
        if self.circuit_id is not None:
            suboptions.append((1, self.circuit_id))
        if self.remote_id is not None:
            suboptions.append((2, self.remote_id))
        if suboptions:
            msg.options[DhcpOptionCode.RELAY_AGENT_INFORMATION] = _type.RelayAgentInformation(suboptions)

    def _forward_to_client(self, msg: DhcpMessage, context: RequestContext) -> None:
        original_client = self._pending_clients.pop(msg.xid, None)
        client_port = original_client.port if original_client is not None else int(_enum.DhcpPort.CLIENT)

        dest: _net.IPv4
        if msg.flags is _enum.Flags.BROADCAST:
            dest = _net.IPv4("255.255.255.255")
        elif msg.ciaddr != _net.WILDCARD_IPv4:
            dest = msg.ciaddr
        elif msg.yiaddr != _net.WILDCARD_IPv4:
            dest = msg.yiaddr
        else:
            dest = _net.IPv4("255.255.255.255")

        data = msg.encode()
        msg.log(context.interface.ip, _net.SocketAddress(dest, client_port), _logging.INFO)
        context.transport.send(data, dest, client_port, msg.chaddr)
        self.metrics.packets_sent += 1
