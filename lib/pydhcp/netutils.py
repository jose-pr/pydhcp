
import typing as _ty
import ipaddress as _ip
import ifaddr as _if


IPAddress = _ip.IPv4Address

ALL_IPS = IPAddress("0.0.0.0")


class MACAddress(int):
    ...


class _Address(_ty.NamedTuple):
    ip: IPAddress
    port: int


class Address(_Address):
    def __new__(cls, ip, port):
        return super(Address, cls).__new__(cls, IPAddress(ip), int(port))

    def compat(self):
        return (str(self.ip), self.port)

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"

    def __repr__(self) -> str:
        return f"Address(ip={self.ip}, port={self.port})"


_APIPA = _ip.ip_network("169.254.0.0/16")

def all_ipv4_addresses():
    address = []
    for adapter in _if.get_adapters():
        for ip in adapter.ips:
            if ip.is_IPv4:
                ip = _ip.IPv4Address(ip.ip)
                if ip not in _APIPA:
                    address.append(ip)
    return address