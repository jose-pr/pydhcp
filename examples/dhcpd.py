from __future__ import annotations

import datetime as dt
import logging
import sys

from pydhcp import DhcpOptions, DhcpServer, log, netutils
from pydhcp.options import DhcpOptionCode
from pydhcp.packet.message import DhcpMessage
from pydhcp.server import DhcpLease


LOGGER = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
LOGGER.addHandler(handler)
log.LOGGER.setLevel(logging.DEBUG)


class ExampleDhcpServer(DhcpServer):
    offset = 60

    def acquire_lease(
        self,
        client_id: str,
        server_id: netutils.IPv4,
        msg: DhcpMessage,
    ) -> DhcpLease | None:
        lease = super().acquire_lease(client_id, server_id, msg)
        if lease is not None:
            return lease

        server_interface = next(
            netutils.host_ip_interfaces(lambda interface: interface.ip == server_id),
            None,
        )
        if server_interface is None:
            return None

        ip = None
        if client_id.endswith("CC:7C"):
            ip = server_interface.network.network_address + self.offset
        elif client_id.endswith("C0:DF"):
            ip = server_interface.network.network_address + self.offset + 1
        if ip is None:
            return None

        options = DhcpOptions()
        options[DhcpOptionCode.ROUTER] = server_interface.network.network_address + 1
        options[DhcpOptionCode.DNS] = [
            server_interface.network.network_address + 1,
            "8.8.8.8",
            "1.1.1.1",
        ]
        return DhcpLease(ip, dt.datetime.now() + dt.timedelta(hours=1), options)


if __name__ == "__main__":
    dhcpd = ExampleDhcpServer()
    dhcpd.listen()
