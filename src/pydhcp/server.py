import socket as _socket
from .message import DhcpMessage
from .listener import DhcpListener as _Base, RequestContext
from . import enum as _enum, constants as _const, netutils as _net
from .options import DhcpOptions
from . import optiontype as _type
from .log import LOGGER
from .metrics import METRICS
import logging as _logging
import datetime as _dt
import typing as _ty
from math import inf as _inf

from .lease import DhcpLease, LeaseBackend

class DhcpServer(_Base):
    DEFAULT_PORTS = (_enum.DhcpPort.SERVER,)

    def __init__(
        self,
        listen: _ty.Optional[_ty.Union[_ty.List[_ty.Union[_ty.Tuple[_net.IPv4, int], _net.IPv4, str]], str]] = None,
        select_timeout: _ty.Optional[float] = None,
        max_packet_size: _ty.Optional[int] = None,
        lease_backend: _ty.Optional[LeaseBackend] = None,
    ) -> None:
        super().__init__(listen=listen, select_timeout=select_timeout, max_packet_size=max_packet_size)
        from .lease import InMemoryLeaseBackend
        self.lease_backend = lease_backend or InMemoryLeaseBackend()

    def acquire_lease(self, client_id: str, server_id: _net.IPv4, msg: DhcpMessage) -> _ty.Optional[DhcpLease]:
        _server = next(_net.host_ip_interfaces(lambda interface: interface.ip == server_id), None)
        if _server is None:
            return None

        existing = self.lease_backend.lookup(client_id)
        if existing:
            requested_ttl = msg.options.get(_enum.DhcpOptionCode.IP_ADDRESS_LEASE_TIME, decode=_type.U32)
            ttl = int(requested_ttl) if requested_ttl is not None else 3600
            renewed = self.lease_backend.renew(client_id, ttl)
            if renewed:
                METRICS.leases_renewed += 1
                return renewed
            return existing

        requested_ip = msg.options.get(
            _enum.DhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
        )
        requested_ttl = msg.options.get(_enum.DhcpOptionCode.IP_ADDRESS_LEASE_TIME, decode=_type.U32)
        ttl = int(requested_ttl) if requested_ttl is not None else 3600

        ip: _ty.Optional[_net.IPv4] = None
        if requested_ip:
            ip = requested_ip
        elif msg.ciaddr != _net.WILDCARD_IPv4:
            ip = msg.ciaddr

        if ip is None:
            return None

        options = DhcpOptions()
        options[_enum.DhcpOptionCode.SUBNET_MASK] = _server.network.netmask
        options[_enum.DhcpOptionCode.BROADCAST_ADDRESS] = _server.network.broadcast_address
        options[_enum.DhcpOptionCode.ROUTER] = [server_id]
        options[_enum.DhcpOptionCode.DNS] = [server_id]

        LOGGER.debug(f"[XID={msg.xid:08x}] Allocating {ip} for {client_id}")
        lease = self.lease_backend.allocate(client_id, ip, ttl, options)
        if lease is not None:
            METRICS.leases_allocated += 1
        return lease

    def release_lease(self, client_id: str, server_id: _net.IPv4, msg: DhcpMessage) -> None:
        if self.lease_backend.release(client_id):
            METRICS.leases_released += 1

    def handle(
        self,
        msg: DhcpMessage,
        context: RequestContext,
    ) -> None:
        if msg.op != _enum.OpCode.BOOTREQUEST:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Received a reply msg from {context.client} ignoring it."
            )
            return
        client_id = msg.client_id()
        msg_ty = msg.options.get(_enum.DhcpOptionCode.DHCP_MESSAGE_TYPE)
        msg_ty_name = msg_ty.name if (msg_ty is not None and hasattr(msg_ty, "name")) else str(msg_ty)
        LOGGER.debug(f"[XID={msg.xid:08x}] Received {msg_ty_name} from {context.client.ip}")
        server_id: _ty.Optional[_net.IPv4] = msg.options.get(
            _enum.DhcpOptionCode.SERVER_IDENTIFIER, decode=_type.IPv4Address
        )
        msg_ty = msg.options.get(_enum.DhcpOptionCode.DHCP_MESSAGE_TYPE)
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)

        if server_id is not None and server_id != actual_server_id:
            if msg_ty is _enum.DhcpMessageType.DHCPREQUEST:
                self.release_lease(client_id, server_id, msg)
            else:
                LOGGER.warning(
                    f"[XID={msg.xid:08x}] Received a message for {server_id} by {context.client}|{client_id} at {actual_server_id} ignoring"
                )
            return

        if msg_ty is _enum.DhcpMessageType.DHCPDISCOVER:
            self.handle_discover(msg, context)
        elif msg_ty is _enum.DhcpMessageType.DHCPREQUEST:
            self.handle_request(msg, context)
        elif msg_ty is _enum.DhcpMessageType.DHCPDECLINE:
            self.handle_decline(msg, context)
        elif msg_ty is _enum.DhcpMessageType.DHCPRELEASE:
            self.handle_release(msg, context)
        elif msg_ty is _enum.DhcpMessageType.DHCPINFORM:
            self.handle_inform(msg, context)
        else:
            LOGGER.warning(
                f"[XID={msg.xid:08x}] Received a DHCP Message with message type: {msg_ty} from: {context.client}|{client_id} at: {actual_server_id}, which we don't handle"
            )

    def handle_discover(self, msg: DhcpMessage, context: RequestContext) -> None:
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.info(f"[XID={msg.xid:08x}] DHCPDISCOVER from {context.client}|{client_id}")
        lease = self.acquire_lease(client_id, actual_server_id, msg)
        if not lease:
            LOGGER.info(
                f"[XID={msg.xid:08x}] No lease available for {context.client}|{client_id} at {actual_server_id} ignoring"
            )
            return
        resp = self._create_response(msg, lease, actual_server_id, _enum.DhcpMessageType.DHCPOFFER)
        self._filter_and_send(msg, resp, context, _enum.DhcpMessageType.DHCPOFFER)

    def handle_request(self, msg: DhcpMessage, context: RequestContext) -> None:
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.info(f"[XID={msg.xid:08x}] DHCPREQUEST from {context.client}|{client_id}")
        lease = self.acquire_lease(client_id, actual_server_id, msg)
        if not lease:
            LOGGER.info(
                f"[XID={msg.xid:08x}] No lease available for {context.client}|{client_id} at {actual_server_id} ignoring"
            )
            return
        ip_req: _ty.Optional[_net.IPv4] = msg.options.get(
            _enum.DhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
        )
        if not ip_req:
            ip_req = msg.ciaddr
        if ip_req == lease.ip:
            resp_ty = _enum.DhcpMessageType.DHCPACK
        else:
            resp_ty = _enum.DhcpMessageType.DHCPNAK
        resp = self._create_response(msg, lease, actual_server_id, resp_ty)
        self._filter_and_send(msg, resp, context, resp_ty)

    def handle_decline(self, msg: DhcpMessage, context: RequestContext) -> None:
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.warning(f"[XID={msg.xid:08x}] DHCPDECLINE from {context.client}|{client_id}")
        self.release_lease(client_id, actual_server_id, msg)

    def handle_release(self, msg: DhcpMessage, context: RequestContext) -> None:
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.info(f"[XID={msg.xid:08x}] DHCPRELEASE from {context.client}|{client_id}")
        self.release_lease(client_id, actual_server_id, msg)

    def handle_inform(self, msg: DhcpMessage, context: RequestContext) -> None:
        client_id = msg.client_id()
        actual_server_id = _ty.cast(_net.IPv4, context.interface.ip)
        LOGGER.info(f"[XID={msg.xid:08x}] DHCPINFORM from {context.client}|{client_id}")
        lease = self.acquire_lease(client_id, actual_server_id, msg)
        if not lease:
            LOGGER.info(
                f"[XID={msg.xid:08x}] No lease available for {context.client}|{client_id} at {actual_server_id} ignoring"
            )
            return
        resp = self._create_response(msg, lease, actual_server_id, _enum.DhcpMessageType.DHCPACK)
        if _enum.DhcpOptionCode.IP_ADDRESS_LEASE_TIME in resp.options:
            del resp.options[_enum.DhcpOptionCode.IP_ADDRESS_LEASE_TIME]
        resp.yiaddr = _net.WILDCARD_IPv4
        self._filter_and_send(msg, resp, context, _enum.DhcpMessageType.DHCPACK)

    def _create_response(
        self,
        msg: DhcpMessage,
        lease: DhcpLease,
        actual_server_id: _net.IPv4,
        resp_ty: _enum.DhcpMessageType,
    ) -> DhcpMessage:
        resp = DhcpMessage(**msg.__dict__.copy())
        resp.options = lease.options
        resp.op = _enum.OpCode.BOOTREPLY
        resp.hops = 0
        resp.secs = _dt.timedelta(seconds=0)
        if lease.ip:
            if lease.expires is None or lease.expires == _inf or not isinstance(lease.expires, _dt.datetime):
                expires = _const.INIFINITE_LEASE_TIME
            else:
                expires = int((lease.expires - _dt.datetime.now()).total_seconds())
                expires = min(expires, _const.INIFINITE_LEASE_TIME)
            if expires > 0:
                resp.options[_enum.DhcpOptionCode.IP_ADDRESS_LEASE_TIME] = expires
                resp.yiaddr = lease.ip
        resp.options[_enum.DhcpOptionCode.SERVER_IDENTIFIER] = actual_server_id
        resp.options[_enum.DhcpOptionCode.DHCP_MESSAGE_TYPE] = resp_ty
        return resp

    def _filter_and_send(
        self,
        msg: DhcpMessage,
        resp: DhcpMessage,
        context: RequestContext,
        resp_ty: _enum.DhcpMessageType,
    ) -> None:
        requests_params_raw = msg.options.get(
            _enum.DhcpOptionCode.PARAMETER_REQUEST_LIST,
            decode=_type.DhcpOptionCodes[_enum.DhcpOptionCode],
        )
        requests_params: _ty.List[_enum.DhcpOptionCode] = []
        if requests_params_raw:
            requests_params = [
                *requests_params_raw,
                _enum.DhcpOptionCode.IP_ADDRESS_LEASE_TIME,
                _enum.DhcpOptionCode.SERVER_IDENTIFIER,
            ]
        if resp_ty is _enum.DhcpMessageType.DHCPNAK:
            requests_params = [
                _enum.DhcpOptionCode.DHCP_MESSAGE,
                _enum.DhcpOptionCode.CLIENT_IDENTIFIER,
                _enum.DhcpOptionCode.VENDOR_CLASS_IDENTIFIER,
                _enum.DhcpOptionCode.SERVER_IDENTIFIER,
            ]
            resp.options[_enum.DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray.fromhex(
                msg.client_id().replace(":", "")
            )
        if requests_params:
            def _paramfilter(opt: tuple[int, bytearray]) -> bool:
                return opt[0] in requests_params
            resp.options._options = _ty.OrderedDict(
                filter(_paramfilter, resp.options.items(decoded=False))
            )
        resp.options[_enum.DhcpOptionCode.DHCP_MESSAGE_TYPE] = resp_ty

        max_size_opt = msg.options.get(
            _enum.DhcpOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE,
            default=_const.DHCP_MIN_LEGAL_PACKET_SIZE,
            decode=_type.U16,
        )
        max_size = int(max_size_opt) if max_size_opt is not None else _const.DHCP_MIN_LEGAL_PACKET_SIZE
        data = resp.encode(max_size)

        dest: _net.IPv4
        dest_port: int = context.client.port
        
        if msg.giaddr != _net.WILDCARD_IPv4:
            dest = msg.giaddr
            dest_port = 67 if context.client.port == 68 else context.client.port
        elif msg.ciaddr != _net.WILDCARD_IPv4:
            dest = msg.ciaddr
        elif msg.flags is _enum.Flags.BROADCAST:
            dest = _net.IPv4("255.255.255.255")
        else:
            if resp.yiaddr != _net.WILDCARD_IPv4:
                dest = resp.yiaddr
            else:
                dest = _net.IPv4("255.255.255.255")

        resp.log(context.interface.ip, _net.SocketAddress(dest, dest_port), _logging.INFO)
        if __debug__:
            _check = DhcpMessage.decode(memoryview(data))
            _check.log(
                context.interface.ip, _net.SocketAddress(dest, dest_port), _logging.DEBUG
            )
        context.transport.send(data, dest, dest_port, context.client_mac)
        METRICS.packets_sent += 1


from .listener import AsyncDhcpListener as _AsyncBase


class AsyncDhcpServer(_AsyncBase, DhcpServer):  # type: ignore[misc]
    DEFAULT_PORTS = (_enum.DhcpPort.SERVER,)

    def __init__(
        self,
        listen: _ty.Optional[_ty.Union[_ty.List[_ty.Union[_ty.Tuple[_net.IPv4, int], _net.IPv4, str]], str]] = None,
        max_packet_size: _ty.Optional[int] = None,
        lease_backend: _ty.Optional[LeaseBackend] = None,
    ) -> None:
        _AsyncBase.__init__(self, listen=listen, max_packet_size=max_packet_size)
        from .lease import InMemoryLeaseBackend
        self.lease_backend = lease_backend or InMemoryLeaseBackend()

    def handle(self, msg: DhcpMessage, context: RequestContext) -> None:
        DhcpServer.handle(self, msg, context)


