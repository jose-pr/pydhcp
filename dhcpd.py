import logging, sys

from lib.pydhcp.message import DhcpMessage

LOGGER = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
LOGGER.addHandler(handler)

from lib.pydhcp import DhcpServer, log
from lib.pydhcp.server import DhcpLease, DhcpOptionCode
from lib.pydhcp import netutils, optiontype

log.LOGGER.setLevel(logging.DEBUG)


class DhcpServer(DhcpServer):
    offset = 60

    def acquire_lease(self, client_id: str, server_id: str, msg: DhcpMessage):
        ip, expires, options = super().acquire_lease(client_id, server_id, msg)
        _server = netutils.get_ipinterface(server_id)
        if not ip:
            if client_id.endswith("CC:7C"):
                ip = _server.network.network_address + self.offset
            elif client_id.endswith("C0:DE"):
                ip = _server.network.network_address + self.offset + 1
        options[DhcpOptionCode.ROUTER] = optiontype.List[optiontype.IPv4Address](
            _server.network.network_address + 1
        )
        options[DhcpOptionCode.DNS] = optiontype.List[optiontype.IPv4Address](
            _server.network.network_address + 1, "8.8.8.8"
        )
        options.append((DhcpOptionCode.DNS, "1.1.1.1"))
        if ip is None:
            return
        return DhcpLease(ip, expires, options)


dhcpd = DhcpServer()
dhcpd.start()
dhcpd.wait()
pass
