import socket as _socket
from .message import DhcpMessage
from .netutils import Address, IPAddress
from . import netutils
from .listener import DhcpListener
from .iana import DHCP_SERVER_PORT, DhcpOptionCode, DhcpMessageType, OpCode
from .options import IPv4DhcpOptionType, DhcpOptions, IPsv4DhcpOptionType
from socket import socket as _socket
from .log import LOGGER
import datetime
import typing as _ty

class DhcpLease(_ty.NamedTuple):
    ip: IPAddress
    expires: datetime.datetime
    options: DhcpOptions

class DhcpServer(DhcpListener):
    DEFAULT_PORTS = (DHCP_SERVER_PORT,)

    def find_lease(self, client_id:str, server_id:str, msg:DhcpMessage):
        _server =  netutils.get_ipinterface(server_id)
        requested_ip = msg.options.get(DhcpOptionCode.REQUESTED_IP)
        expires = datetime.datetime.now() + datetime.timedelta(0,3600)
        options = DhcpOptions()
        if requested_ip:
            ip = requested_ip.ip
        else:
            ip = None

        options[DhcpOptionCode.SUBNET_MASK] = IPv4DhcpOptionType(_server.network.netmask)
        options[DhcpOptionCode.BROADCAST_ADDRESS] = IPv4DhcpOptionType(_server.network.broadcast_address)
        return  DhcpLease(ip,expires,options)

    def handle(
        self, msg: DhcpMessage, client: Address, server: Address, socket: _socket
    ):
        if msg.op != OpCode.BOOTREQUEST:
            LOGGER.warning(f"Receive a reply msg from {client} on {server} ignoring it.")
            return
        client_id = msg.client_id()
        server_id = msg.options.get(DhcpOptionCode.SERVER_IDENTIFIER, decode=IPv4DhcpOptionType)
        if server_id and server_id != server.ip:
            LOGGER.warning(f"Receive a message for {server_id} by {client}|{client_id} at {server} ignoring")
            return
        server_id = server.ip
        lease = self.find_lease(client_id, server_id, msg)
        if not lease:
            LOGGER.info(f"No lease avaliable for {client}|{client_id} at {server} ignoring")
        match msg.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE):
            case DhcpMessageType.DHCPDISCOVER:
                ...
            case DhcpMessageType.DHCPREQUEST:
                ...
            case DhcpMessageType.DHCPDECLINE:
                ...
            case DhcpMessageType.DHCPRELEASE:
                ...
            case DhcpMessageType.DHCPINFORM:
                ...
            case other:
                LOGGER.warning(
                    f"Receive a DHCP Message with message type: {other} from: {client}|{client_id} at: {server}, which we dont handle"
                )
