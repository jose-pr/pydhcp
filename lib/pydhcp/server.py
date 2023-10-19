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
    ip: _net.IPv4
    expires: _dt.datetime
    options: DhcpOptions


class DhcpServer(_Base):
    DEFAULT_PORTS = (_enum.DhcpPort.SERVER,)

    def acquire_lease(self, client_id: str, server_id: _net.IPv4, msg: DhcpMessage):
        _server = next(_net.host_ip_interfaces(lambda int: int.ip == server_id), None)
        requested_ip = msg.options.get(
            _enum.IanaDhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
        )
        expires = _dt.datetime.now() + _dt.timedelta(0, 3600)
        options = DhcpOptions()
        if requested_ip:
            ip = requested_ip
        elif msg.ciaddr != _net.WILDCARD_IPv4:
            ip = msg.ciaddr
        else:
            ip = None
        options[_enum.IanaDhcpOptionCode.SUBNET_MASK] = _server.network.netmask

        options[
            _enum.IanaDhcpOptionCode.BROADCAST_ADDRESS
        ] = _server.network.broadcast_address

        return DhcpLease(ip, expires, options)

    def release_lease(self, client_id: str, server_id: _net.IPv4, msg: DhcpMessage):
        ...

    def handle(
        self,
        msg: DhcpMessage,
        client: _net.Address,
        server: _net.Address,
        socket: _socket.socket,
    ):
        if msg.op != _enum.OpCode.BOOTREQUEST:
            LOGGER.warning(
                f"Receive a reply msg from {client} on {server} ignoring it."
            )
            return
        client_id = msg.client_id()
        server_id = msg.options.get(
            _enum.IanaDhcpOptionCode.SERVER_IDENTIFIER, decode=_type.IPv4Address
        )
        msg_ty = msg.options.get(_enum.IanaDhcpOptionCode.DHCP_MESSAGE_TYPE)
        if server_id and server_id != server:
            if msg_ty is _enum.DhcpMessageType.DHCPREQUEST:
                self.release_lease(client_id, server_id, msg)
            else:
                LOGGER.warning(
                    f"Receive a message for {server_id} by {client}|{client_id} at {server} ignoring"
                )
            return
        server_id = server.ip
        lease = self.acquire_lease(client_id, server_id, msg)
        if not lease:
            LOGGER.info(
                f"No lease avaliable for {client}|{client_id} at {server} ignoring"
            )
            return
        resp = DhcpMessage(**msg.__dict__.copy())
        resp.options = lease.options
        resp.op = _enum.OpCode.BOOTREPLY
        resp.hops = 0
        resp.secs = _dt.timedelta(seconds=0)
        if lease.ip:
            if lease.expires is None or lease.expires is _inf:
                expires = _const.INIFINITE_LEASE_TIME
            else:
                expires = min(
                    (lease.expires - _dt.datetime.now()).seconds,
                    _const.INIFINITE_LEASE_TIME,
                )
            if expires <= 0:
                LOGGER.info(
                    f"No lease avaliable for {client}|{client_id} at {server} ignoring"
                )
                return
            resp.options[_enum.IanaDhcpOptionCode.IP_ADDRESS_LEASE_TIME] = expires
            resp.yiaddr = lease.ip
        resp.options[_enum.IanaDhcpOptionCode.SERVER_IDENTIFIER] = server_id
        resp_ty = None
        match msg_ty:
            case _enum.DhcpMessageType.DHCPDISCOVER:
                resp_ty = _enum.DhcpMessageType.DHCPOFFER
            case _enum.DhcpMessageType.DHCPREQUEST:
                ip = msg.options.get(
                    _enum.IanaDhcpOptionCode.REQUESTED_IP, decode=_type.IPv4Address
                )
                if not ip:
                    ip = msg.ciaddr
                if ip == lease.ip:
                    resp_ty = _enum.DhcpMessageType.DHCPACK
                else:
                    resp_ty = _enum.DhcpMessageType.DHCPNAK
            case _enum.DhcpMessageType.DHCPDECLINE:
                self.release_lease(client_id, server_id, msg)
                return
            case _enum.DhcpMessageType.DHCPRELEASE:
                self.release_lease(client_id, server_id, msg)
                return
            case _enum.DhcpMessageType.DHCPINFORM:
                del resp.options[_enum.IanaDhcpOptionCode.IP_ADDRESS_LEASE_TIME]
                resp.yiaddr = _net.WILDCARD_IPv4
                resp_ty = _enum.DhcpMessageType.DHCPACK

            case other:
                LOGGER.warning(
                    f"Receive a DHCP Message with message type: {other} from: {client}|{client_id} at: {server}, which we dont handle"
                )
        requests_params = msg.options.get(
            _enum.IanaDhcpOptionCode.PARAMETER_REQUEST_LIST,
            decode=_type.DhcpOptionCodes[_enum.IanaDhcpOptionCode],
        )
        if requests_params:
            requests_params = [
                *requests_params,
                _enum.IanaDhcpOptionCode.IP_ADDRESS_LEASE_TIME,
                _enum.IanaDhcpOptionCode.SERVER_IDENTIFIER,
            ]
        if resp_ty is _enum.DhcpMessageType.DHCPNAK:
            requests_params = [
                _enum.IanaDhcpOptionCode.DHCP_MESSAGE,
                _enum.IanaDhcpOptionCode.CLIENT_IDENTIFIER,
                _enum.IanaDhcpOptionCode.VENDOR_CLASS_IDENTIFIER,
                _enum.IanaDhcpOptionCode.SERVER_IDENTIFIER,
            ]
            resp[_enum.IanaDhcpOptionCode.CLIENT_IDENTIFIER] = bytearray.fromhex(
                client_id.replace(":", "")
            )
        if requests_params:

            def _paramfilter(opt: tuple[int, bytes]):
                return opt[0] in requests_params

            resp.options._options = _ty.OrderedDict(
                filter(_paramfilter, resp.options.items(decoded=False))
            )
        resp.options[_enum.IanaDhcpOptionCode.DHCP_MESSAGE_TYPE] = resp_ty

        data = resp.encode(
            msg.options.get(
                _enum.IanaDhcpOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE,
                _const.DHCP_MIN_LEGAL_PACKET_SIZE,
            )
        )

        if msg.giaddr != _net.WILDCARD_IPv4:
            dest = msg.giaddr
        elif msg.ciaddr != _net.WILDCARD_IPv4 and msg.flags is _enum.Flags.UNICAST:
            dest = msg.ciaddr
        else:
            # We should be sending unicast to mac if BROADCAST not set but socket wont allow setting the mac
            # Protocol allows sending to broadcast as an option
            dest = _net.IPv4("255.255.255.255")
        resp.log(server, _net.Address(dest, client.port), _logging.INFO)
        if __debug__:
            _check = DhcpMessage.decode(memoryview(data))
            _check.log(server, _net.Address(dest, client.port), _logging.DEBUG)
        socket.sendto(data, (str(dest), client.port))
