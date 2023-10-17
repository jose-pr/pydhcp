from .._options import *
from .options import DhcpOptionCode
from .hardwaretype import HardwareAddressType

class ClientIdentifierOptionType(GenericDhcpOptionType):
    @classmethod
    def decode(cls, option: bytearray) -> "Self":
        if len(option) < 2:
            raise ValueError(option)
        return super().decode(option)
    def __repr__(self) -> str:
            ty = self.data[0]
            addr =  self.data[1:]
            try:
                ty = HardwareAddressType(ty).name
            except:
                ...
            maybe = f"{ty}({addr.hex(':')})"

            return f'{maybe}|{self.data.hex(':').upper()}'  

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
    

DhcpOptionCode.BROADCAST_ADDRESS.register_type(IPv4DhcpOptionType)
DhcpOptionCode.CLIENT_IDENTIFIER.register_type(ClientIdentifierOptionType)
DhcpOptionCode.DNS.register_type(IPsv4DhcpOptionType)
DhcpOptionCode.DOMAIN_NAME.register_type(StringDhcpOptionType)
DhcpOptionCode.DOMAIN_SEARCH.register_type(DomainListDhcpOptionType)
DhcpOptionCode.HOSTNAME.register_type(StringDhcpOptionType)
DhcpOptionCode.IP_ADDRESS_LEASE_TIME.register_type(U32DhcpOptionType)
DhcpOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE.register_type(U16DhcpOptionType)
DhcpOptionCode.PARAMETER_REQUEST_LIST.register_type(DhcpOptionCodesDhcpOptionType)
DhcpOptionCode.REQUESTED_IP.register_type(IPv4DhcpOptionType)
DhcpOptionCode.ROUTER.register_type(IPsv4DhcpOptionType)
DhcpOptionCode.SERVER_IDENTIFIER.register_type(IPv4DhcpOptionType)
DhcpOptionCode.SUBNET_MASK.register_type(IPv4DhcpOptionType)
DhcpOptionCode.VENDOR_CLASS_IDENTIFIER.register_type(StringDhcpOptionType)
_REGISTERED = True