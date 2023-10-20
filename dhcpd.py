import logging, sys
import pathlib

_LIB = pathlib.Path(__file__).parent / "lib"
sys.path.insert(0, _LIB.as_posix())
from lib.pydhcp.message import DhcpMessage

LOGGER = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
LOGGER.addHandler(handler)

from pydhcp import DhcpServer, log
from pydhcp.server import DhcpLease
from pydhcp import netutils, optiontype
from pydhcp.enum import DhcpOptionCode

log.LOGGER.setLevel(logging.DEBUG)


class DhcpServer(DhcpServer):
    offset = 60

    def acquire_lease(self, client_id: str, server_id: netutils.IPv4, msg: DhcpMessage):
        ip, expires, options = super().acquire_lease(client_id, server_id, msg)
        _server = next(netutils.host_ip_interfaces(lambda ip: ip.ip == server_id), None)
        if not ip:
            if client_id.endswith("CC:7C"):
                ip = _server.network.network_address + self.offset
            elif client_id.endswith("C0:DF"):
                ip = _server.network.network_address + self.offset + 1
        options[DhcpOptionCode.ROUTER] = _server.network.network_address + 1
        options[DhcpOptionCode.DNS] = [
            _server.network.network_address + 1,
            "8.8.8.8",
            "1.1.1.1",
        ]
        if ip is None:
            return
        return DhcpLease(ip, expires, options)


dhcpd = DhcpServer()
dhcpd.listen()
# dhcpd.wait()
pass
