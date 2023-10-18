from .._options import *
from ..optiontype import *
from .options import DhcpOptionCode
from .hardwaretype import HardwareAddressType

class ClientIdentifierOptionType(Bytes):
    @classmethod
    def __dhcp_decode__(cls, option: bytearray) -> "Self":
        if len(option) < 2:
            raise ValueError(option)
        return super().decode(option)
    def __repr__(self) -> str:
            ty = self[0]
            addr =  self[1:]
            try:
                ty = HardwareAddressType(ty).name
            except:
                ...
            maybe = f"{ty}({addr.hex(':')})"

            return f'{maybe}|{self.hex(':').upper()}'  

class DhcpOptionCodesDhcpOptionType(DhcpOptionType):
    options:list[DhcpOptionCode|int]
    @classmethod
    def decode(cls, option: bytearray):
        self = cls()
        self.options = []
        for o in option:
            try:
                o = DhcpOptionCode(o)
            except:
                ...
            self.options.append(o)
        return self
    
    def encode(self) -> bytearray:
        data = bytearray([int(o) for o in self.options])
        return data

    def __repr__(self) -> str:
        return str(self.options)[1:-1].replace(', ','\n')
    
    def __str__(self) -> str:
        return str(self.options)
    

DhcpOptionCode.BROADCAST_ADDRESS.register_type(IPv4Address)
DhcpOptionCode.CLIENT_IDENTIFIER.register_type(ClientIdentifierOptionType)
DhcpOptionCode.DNS.register_type(List[IPv4Address])
DhcpOptionCode.DOMAIN_NAME.register_type(String)
DhcpOptionCode.DOMAIN_SEARCH.register_type(DomainList)
DhcpOptionCode.HOSTNAME.register_type(String)
DhcpOptionCode.IP_ADDRESS_LEASE_TIME.register_type(U32)
DhcpOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE.register_type(U16)
DhcpOptionCode.PARAMETER_REQUEST_LIST.register_type(DhcpOptionCodesDhcpOptionType)
DhcpOptionCode.REQUESTED_IP.register_type(IPv4Address)
DhcpOptionCode.ROUTER.register_type(List[IPv4Address])
DhcpOptionCode.SERVER_IDENTIFIER.register_type(IPv4Address)
DhcpOptionCode.SUBNET_MASK.register_type(IPv4Address)
DhcpOptionCode.VENDOR_CLASS_IDENTIFIER.register_type(String)
_REGISTERED = True
