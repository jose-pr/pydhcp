import typing as _ty
import ipaddress as _ip
import ifaddr as _if


IPv4 = _ip.IPv4Address
IPv6 = _ip.IPv4Address
IP = IPv4 | IPv6

WILDCARD_IPv4 = IPv4("0.0.0.0")


class MACAddress(int):
    ...


class _Address(_ty.NamedTuple):
    ip: IPv4
    port: int


class Address(_Address):
    def __new__(cls, ip, port):
        return super(Address, cls).__new__(cls, IPv4(ip), int(port))

    def compat(self):
        return (str(self.ip), self.port)

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"

    def __repr__(self) -> str:
        return f"Address(ip={self.ip}, port={self.port})"


APIPA = _ip.ip_network("169.254.0.0/16")


def host_ip_interfaces(filter:_ty.Callable[[_ip.IPv4Interface|_ip.IPv6Interface], bool]|bool=True):
    if filter is True:
        filter = lambda ip: ip.ip not in APIPA
    for adapter in _if.get_adapters():
        for ip_ in adapter.ips:
            ip = ip_.ip
            if ip_.is_IPv6:
                ip = f"{ip[0]}%{ip[2]}"
            interface = _ip.ip_interface((ip, ip_.network_prefix))
            if not filter or filter(interface):
                yield interface