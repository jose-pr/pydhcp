import socket as _socket
from .message import DhcpMessage
from .netutils import Address, IPAddress
from . import netutils
from .listener import DhcpListener
from .iana import (
    DHCP_MIN_LEGAL_PACKET_SIZE,
    DHCP_SERVER_PORT,
    DhcpOptionCode,
    DhcpMessageType,
    OpCode,
    INIFINITE_LEASE_TIME,
    DhcpOptionCodesDhcpOptionType
)
from .options import (
    IPv4DhcpOptionType,
    DhcpOptions,
    IPsv4DhcpOptionType,
    U32DhcpOptionType,
)
from socket import socket as _socket
from .log import LOGGER
import logging as _logging
import datetime
import typing as _ty
from math import inf as _inf


class DhcpLease(_ty.NamedTuple):
    ip: IPAddress
    expires: datetime.datetime
    options: DhcpOptions


class DhcpServer(DhcpListener):
    DEFAULT_PORTS = (DHCP_SERVER_PORT,)

    def acquire_lease(self, client_id: str, server_id: str, msg: DhcpMessage):
        _server = netutils.get_ipinterface(server_id)
        requested_ip = msg.options.get(DhcpOptionCode.REQUESTED_IP)
        expires = datetime.datetime.now() + datetime.timedelta(0, 3600)
        options = DhcpOptions()
        ty = msg.options[DhcpOptionCode.DHCP_MESSAGE_TYPE]
        if ty is DhcpMessageType.DHCPINFORM and msg.ciaddr:
            ip = msg.ciaddr
        elif requested_ip:
            ip = requested_ip.ip
        else:
            ip = None
        requested = msg.options.get(DhcpOptionCode.PARAMETER_REQUEST_LIST, decode=DhcpOptionCodesDhcpOptionType)
        if requested:
            requested = requested.options
        if not requested or DhcpOptionCode.SUBNET_MASK in requested:
            options[DhcpOptionCode.SUBNET_MASK] = IPv4DhcpOptionType(
                _server.network.netmask
            )
        if not requested or DhcpOptionCode.SUBNET_MASK in requested:
            options[DhcpOptionCode.BROADCAST_ADDRESS] = IPv4DhcpOptionType(
                _server.network.broadcast_address
            )
        return DhcpLease(ip, expires, options)

    def release_lease(self, client_id: str, server_id: str, msg: DhcpMessage):
        ...

    def handle(
        self, msg: DhcpMessage, client: Address, server: Address, socket: _socket
    ):
        if msg.op != OpCode.BOOTREQUEST:
            LOGGER.warning(
                f"Receive a reply msg from {client} on {server} ignoring it."
            )
            return
        client_id = msg.client_id()
        server_id = msg.options.get(
            DhcpOptionCode.SERVER_IDENTIFIER, decode=IPv4DhcpOptionType
        )
        msg_ty = msg.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
        if server_id and server_id != server.ip:
            if msg_ty is DhcpMessageType.DHCPREQUEST:
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
        resp.op = OpCode.BOOTREPLY
        resp.hops = 0
        resp.secs = datetime.timedelta(seconds=0)
        if lease.ip:
            if lease.expires is None or lease.expires is _inf:
                expires = INIFINITE_LEASE_TIME
            else:
                expires = min(
                    (lease.expires - datetime.datetime.now()).seconds,
                    INIFINITE_LEASE_TIME,
                )
            if expires <= 0:
                LOGGER.info(
                    f"No lease avaliable for {client}|{client_id} at {server} ignoring"
                )
                return
            resp.options[DhcpOptionCode.IP_ADDRESS_LEASE_TIME] = U32DhcpOptionType(
                expires
            )
            resp.yiaddr = lease.ip
        resp.options[DhcpOptionCode.SERVER_IDENTIFIER] = IPv4DhcpOptionType(server_id)
        match msg_ty:
            case DhcpMessageType.DHCPDISCOVER:
                resp.options[
                    DhcpOptionCode.DHCP_MESSAGE_TYPE
                ] = DhcpMessageType.DHCPOFFER
            case DhcpMessageType.DHCPREQUEST:
                if (
                    msg.options.get(DhcpOptionCode.REQUESTED_IP).ip == lease.ip
                ):  # MUST BE SET TO YIADDR/LEASE_IP
                    resp.options[
                        DhcpOptionCode.DHCP_MESSAGE_TYPE
                    ] = DhcpMessageType.DHCPACK
                else:
                    resp.options[
                        DhcpOptionCode.DHCP_MESSAGE_TYPE
                    ] = DhcpMessageType.DHCPNAK
            case DhcpMessageType.DHCPDECLINE:
                ...
            case DhcpMessageType.DHCPRELEASE:
                ...
            case DhcpMessageType.DHCPINFORM:
                del resp.options[DhcpOptionCode.IP_ADDRESS_LEASE_TIME]
                resp.yiaddr = netutils.ALL_IPS
            case other:
                LOGGER.warning(
                    f"Receive a DHCP Message with message type: {other} from: {client}|{client_id} at: {server}, which we dont handle"
                )
        data = resp.encode(msg.options.get(DhcpOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE, DHCP_MIN_LEGAL_PACKET_SIZE))
        resp.log(server, client, _logging.INFO)
        if msg.giaddr != netutils.ALL_IPS:
            dest = msg.giaddr
        elif msg.ciaddr != netutils.ALL_IPS:
            dest = msg.ciaddr
        else:
            # We should be sending unicast to mac if BROADCAST not set but socket wont allow setting the mac
            # Protocol allows sending to broadcast as an option
            dest = IPAddress("255.255.255.255")
        socket.sendto(data, (str(dest), client.port))
