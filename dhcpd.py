import logging, sys

from lib.pydhcp.message import DhcpMessage

LOGGER = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
LOGGER.addHandler(handler)

from lib.pydhcp import DhcpServer, log
from lib.pydhcp.server import DhcpLease, Address, DhcpOptionCode, DhcpOptions, IPAddress
from ipaddress import IPv4Network, IPv4Interface
from lib.pydhcp.options import IPv4DhcpOptionType, IPsv4DhcpOptionType
from lib.pydhcp.iana import DhcpOptionCodesDhcpOptionType
from lib.pydhcp import netutils

log.LOGGER.setLevel(logging.DEBUG)


class DhcpServer(DhcpServer):
    offset = 60

    def acquire_lease(self, client_id: str, server_id: str, msg: DhcpMessage):
        ip, expires, options = super().acquire_lease(client_id, server_id, msg)
        _server = netutils.get_ipinterface(server_id)

        if client_id.endswith("CC:7C") and not ip:
            ip = _server.network.network_address + self.offset

        requested = msg.options.get(DhcpOptionCode.PARAMETER_REQUEST_LIST, decode=DhcpOptionCodesDhcpOptionType)
        if requested:
            requested = requested.options
        if not requested or DhcpOptionCode.ROUTER in requested:
            options[DhcpOptionCode.ROUTER] = IPv4DhcpOptionType(
                _server.network.network_address + 1
            )
        if not requested or DhcpOptionCode.DNS in requested:
            options[DhcpOptionCode.DNS] = IPsv4DhcpOptionType(
                _server.network.network_address + 1, '8.8.8.8'
            )
            options.append((DhcpOptionCode.DNS, "1.1.1.1"))
        if ip is None:
            return
        return DhcpLease(ip, expires, options)


dhcpd = DhcpServer()
dhcpd.start()
dhcpd.wait()
pass
