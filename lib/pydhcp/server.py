import socket as _socket
from .message import DhcpMessage
from .netutils import Address, IPAddress
from .listener import DhcpListener
from .iana import DHCP_SERVER_PORT, DhcpOptionCode, DhcpMessageType, OpCode
from .options import IPv4DhcpOptionType, DhcpOptions
from socket import socket as _socket
from .log import LOGGER
import typing as _ty

class DhcpLease(_ty.NamedTuple):
    ip: IPAddress
    options: DhcpOptions

class DhcpServer(DhcpListener):
    DEFAULT_PORTS = (DHCP_SERVER_PORT,)

    def find_lease(self, client_id:str, server_id:str, msg:DhcpMessage):
        return None

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
