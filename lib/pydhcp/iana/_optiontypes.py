from .._options import *
from ..optiontype import *
from .options import DhcpOptionCode
from .hardwaretype import HardwareAddressType

class ClientIdentifier(Bytes):
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        if len(option) < 2:
            raise ValueError(option)
        return super()._dhcp_read(option)
    
    def __repr__(self) -> str:
            ty = self[0]
            addr =  self[1:]
            try:
                ty = HardwareAddressType(ty).name
            except:
                ...
            maybe = f"{ty}({addr.hex(':').upper()})"

            return f'{maybe}|{self}'  
    
    def __str__(self) -> str:
        return self.__repr__()

class DhcpOptionCodes(DhcpOptionType, list[DhcpOptionCode|int]):
    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple["Self", int]:
        self = cls()
        for o in option:
            try:
                o = DhcpOptionCode(o)
            except:
                ...
            self.append(o)
        return self, len(option)
    
    def _dhcp_write(self, data:bytearray):
        data.extend(self)
        return len(self)
   

DhcpOptionCode.BROADCAST_ADDRESS.register_type(IPv4Address)
DhcpOptionCode.CLIENT_IDENTIFIER.register_type(ClientIdentifier)
DhcpOptionCode.DNS.register_type(List[IPv4Address])
DhcpOptionCode.DOMAIN_NAME.register_type(String)
DhcpOptionCode.DOMAIN_SEARCH.register_type(DomainList)
DhcpOptionCode.HOSTNAME.register_type(String)
DhcpOptionCode.IP_ADDRESS_LEASE_TIME.register_type(U32)
DhcpOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE.register_type(U16)
DhcpOptionCode.PARAMETER_REQUEST_LIST.register_type(DhcpOptionCodes)
DhcpOptionCode.REQUESTED_IP.register_type(IPv4Address)
DhcpOptionCode.ROUTER.register_type(List[IPv4Address])
DhcpOptionCode.SERVER_IDENTIFIER.register_type(IPv4Address)
DhcpOptionCode.SUBNET_MASK.register_type(IPv4Address)
DhcpOptionCode.VENDOR_CLASS_IDENTIFIER.register_type(String)
_REGISTERED = True
