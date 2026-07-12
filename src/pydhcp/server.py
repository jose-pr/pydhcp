import socket as _socket
from .message import DhcpMessage
from .listener import DhcpListener as _Base
from . import enum as _enum, contants as _const, netutils as _net
from .options import DhcpOptions
from . import optiontype as _type
from .log import LOGGER
import logging as _logging
import datetime as _dt
import typing as _ty
from math import inf as _inf


class DhcpLease(_ty.NamedTuple):
    ip: _ty.Optional[_net.IPv4]
    expires: _ty.Union[_dt.datetime, float]
    options: DhcpOptions


class DhcpServer(_Base):
    DEFAULT_PORTS = (_enum.DhcpPort.SERVER,)

    def acquire_lease(self, client_id: str, server_id: _net.IPv4, msg: DhcpMessage) -> _ty.Optional[DhcpLease]:
        _server = next(_net.host_ip_interfaces(lambda interface: interface.ip == server_id), None)
        if _server is None:
            return None
        requested_ip = msg.options.get(
            _enum.DhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
        )
        expires = _dt.datetime.now() + _dt.timedelta(0, 3600)
        options = DhcpOptions()
        
        ip: _ty.Optional[_net.IPv4] = None
        if requested_ip:
            ip = requested_ip
        elif msg.ciaddr != _net.WILDCARD_IPv4:
            ip = msg.ciaddr
            
        options[_enum.DhcpOptionCode.SUBNET_MASK] = _server.network.netmask

        options[
            _enum.DhcpOptionCode.BROADCAST_ADDRESS
        ] = _server.network.broadcast_address

        return DhcpLease(ip, expires, options)

    def release_lease(self, client_id: str, server_id: _net.IPv4, msg: DhcpMessage) -> None:
        ...

    def handle(
        self,
        msg: DhcpMessage,
        session: _net.SocketSession,
    ) -> None:
        server = session.server
        if msg.op != _enum.OpCode.BOOTREQUEST:
            LOGGER.warning(
                f"Receive a reply msg from {session.client} on {server} ignoring it."
            )
            return
        client_id = msg.client_id()
        server_id: _ty.Optional[_net.IPv4] = msg.options.get(
            _enum.DhcpOptionCode.SERVER_IDENTIFIER, decode=_type.IPv4Address
        )
        msg_ty = msg.options.get(_enum.DhcpOptionCode.DHCP_MESSAGE_TYPE)
        if server_id is not None and server_id != server.ip:
            if msg_ty is _enum.DhcpMessageType.DHCPREQUEST:
                self.release_lease(client_id, server_id, msg)
            else:
                LOGGER.warning(
                    f"Receive a message for {server_id} by {session.client}|{client_id} at {server} ignoring"
                )
            return
        actual_server_id = server.ip
        lease = self.acquire_lease(client_id, actual_server_id, msg)
        if not lease:
            LOGGER.info(
                f"No lease avaliable for {session.client}|{client_id} at {server} ignoring"
            )
            return
        resp = DhcpMessage(**msg.__dict__.copy())
        resp.options = lease.options
        resp.op = _enum.OpCode.BOOTREPLY
        resp.hops = 0
        resp.secs = _dt.timedelta(seconds=0)
        if lease.ip:
            if lease.expires is None or lease.expires == _inf or not isinstance(lease.expires, _dt.datetime):
                expires = _const.INIFINITE_LEASE_TIME
            else:
                expires = min(
                    (lease.expires - _dt.datetime.now()).seconds,
                    _const.INIFINITE_LEASE_TIME,
                )
            if expires <= 0:
                LOGGER.info(
                    f"No lease avaliable for {session.client}|{client_id} at {server} ignoring"
                )
                return
            resp.options[_enum.DhcpOptionCode.IP_ADDRESS_LEASE_TIME] = expires
            resp.yiaddr = lease.ip
        resp.options[_enum.DhcpOptionCode.SERVER_IDENTIFIER] = actual_server_id
        resp_ty = None
        match msg_ty:
            case _enum.DhcpMessageType.DHCPDISCOVER:
                resp_ty = _enum.DhcpMessageType.DHCPOFFER
            case _enum.DhcpMessageType.DHCPREQUEST:
                ip_req: _ty.Optional[_net.IPv4] = msg.options.get(
                    _enum.DhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
                )
                if not ip_req:
                    ip_req = msg.ciaddr
                if ip_req == lease.ip:
                    resp_ty = _enum.DhcpMessageType.DHCPACK
                else:
                    resp_ty = _enum.DhcpMessageType.DHCPNAK
            case _enum.DhcpMessageType.DHCPDECLINE:
                self.release_lease(client_id, actual_server_id, msg)
                return
            case _enum.DhcpMessageType.DHCPRELEASE:
                self.release_lease(client_id, actual_server_id, msg)
                return
            case _enum.DhcpMessageType.DHCPINFORM:
                del resp.options[_enum.DhcpOptionCode.IP_ADDRESS_LEASE_TIME]
                resp.yiaddr = _net.WILDCARD_IPv4
                resp_ty = _enum.DhcpMessageType.DHCPACK

            case other:
                LOGGER.warning(
                    f"Receive a DHCP Message with message type: {other} from: {session.client}|{client_id} at: {server}, which we dont handle"
                )
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
                client_id.replace(":", "")
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

        if msg.giaddr != _net.WILDCARD_IPv4:
            dest: _net.IPv4 = msg.giaddr
        elif msg.ciaddr != _net.WILDCARD_IPv4 and msg.flags is _enum.Flags.UNICAST:
            dest = msg.ciaddr
        else:
            # We should be sending unicast to mac if BROADCAST not set but socket wont allow setting the mac
            # Protocol allows sending to broadcast as an option
            dest = _net.IPv4("255.255.255.255")
        resp.log(server.ip, _net.SocketAddress(dest, session.client.port), _logging.INFO)
        if __debug__:
            _check = DhcpMessage.decode(memoryview(data))
            _check.log(
                server.ip, _net.SocketAddress(dest, session.client.port), _logging.DEBUG
            )
        session.respond(data, dest)

