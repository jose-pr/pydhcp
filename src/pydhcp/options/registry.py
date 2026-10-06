from __future__ import annotations

from .code import DHCPOptionCode
from ..packet.enums import DHCPMessageType
from .type import *

DHCPOptionCode.TIME_OFFSET.register_type(I32)
DHCPOptionCode.RFC868_TIMESERVER.register_type(List[IPv4Address])
DHCPOptionCode.IEN116_NAMESERVER.register_type(List[IPv4Address])
DHCPOptionCode.SWAP_SERVER.register_type(IPv4Address)
DHCPOptionCode.MERIT_DUMP_FILE.register_type(String)
DHCPOptionCode.BROADCAST_ADDRESS.register_type(IPv4Address)
DHCPOptionCode.BOOTFILE_NAME.register_type(String)
DHCPOptionCode.BOOT_FILE_SIZE.register_type(U16)
# RFC 4702 s2.1: Flags, RCODE1, RCODE2, then the name -- not a bare string,
# which silently dropped the name every Windows client sends.
DHCPOptionCode.CLIENT_FQDN.register_type(ClientFqdn)
# RFC 3442: the option carries one or more destination/router pairs, and a
# server sending it SHOULD include the default route -- so real options
# nearly always hold more than one.
DHCPOptionCode.CLASSLESS_STATIC_ROUTE.register_type(List[ClasslessRoute])
DHCPOptionCode.CLIENT_IDENTIFIER.register_type(ClientIdentifier)
DHCPOptionCode.DHCP_MESSAGE_TYPE.register_type(DHCPMessageType)
DHCPOptionCode.DHCP_MESSAGE.register_type(String)
DHCPOptionCode.DNS.register_type(List[IPv4Address])
DHCPOptionCode.DOMAIN_NAME.register_type(String)
DHCPOptionCode.DOMAIN_SEARCH.register_type(DomainList)
DHCPOptionCode.EXTENSION_FILE.register_type(String)
DHCPOptionCode.ETHERNET_ENCAPSULATION.register_type(Boolean)
DHCPOptionCode.HOSTNAME.register_type(String)
DHCPOptionCode.IP_FORWARDING.register_type(Boolean)
DHCPOptionCode.IP_TTL.register_type(U8)
DHCPOptionCode.IP_ADDRESS_LEASE_TIME.register_type(U32)
DHCPOptionCode.INTERFACE_MTU.register_type(U16)
DHCPOptionCode.LOG_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.MAX_DATAGRAM_REASSEMBLY_SIZE.register_type(U16)
DHCPOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE.register_type(U16)
DHCPOptionCode.MSFT_CLASSLESS_STATIC_ROUTE.register_type(List[ClasslessRoute])
DHCPOptionCode.MTU_TIMEOUT.register_type(U32)
DHCPOptionCode.MTU_PLATEAU.register_type(List[U16])
DHCPOptionCode.MASK_DISCOVERY.register_type(Boolean)
DHCPOptionCode.MASK_SUPPLIER.register_type(Boolean)
DHCPOptionCode.NON_LOCAL_SOURCE_ROUTING.register_type(Boolean)
# RFC 4280 s4.6: 'DNS name compression MUST NOT be used.' The compressed
# DomainList emitted a 0xC0 pointer into a payload whose RFC forbids one.
DHCPOptionCode.BCMCS_DOMAIN_NAME_LIST.register_type(UncompressedDomainList)
DHCPOptionCode.BCMCS_IPV4_ADDRESS.register_type(List[IPv4Address])
DHCPOptionCode.CLIENT_LAST_TRANSACTION_TIME.register_type(U32)
# RFC 4388 s6.1: 'Len n (multiple of 4), Address 1 ... Address n'. A single
# address could not decode a DHCPLEASEACTIVE for a multi-homed client.
DHCPOptionCode.ASSOCIATED_IP.register_type(List[IPv4Address])
DHCPOptionCode.CLIENT_SYSTEM_ARCHITECTURE.register_type(List[U16])
DHCPOptionCode.PCODE.register_type(String)
DHCPOptionCode.TCODE.register_type(String)
DHCPOptionCode.IPV6_ONLY.register_type(U32)
DHCPOptionCode.NETINFO_ADDRESS.register_type(IPv4Address)
DHCPOptionCode.NETINFO_TAG.register_type(String)
DHCPOptionCode.DHCP_CAPTIVE_PORTAL.register_type(String)
DHCPOptionCode.AUTO_CONFIG.register_type(Boolean)
DHCPOptionCode.VI_VENDOR_CLASS.register_type(ViVendorClass)
DHCPOptionCode.CAPWAP_AC_V4.register_type(List[IPv4Address])
DHCPOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS.register_type(DomainList)
DHCPOptionCode.IPV4_ADDRESS_ANDSF.register_type(List[IPv4Address])
DHCPOptionCode.V4_SZTP_REDIRECT.register_type(UriList)
# RFC 8973 s5.2: an uncompressed RFC 1035 label sequence, not dotted text.
DHCPOptionCode.V4_DOTS_RI.register_type(DomainName)
DHCPOptionCode.V4_DOTS_ADDRESS.register_type(List[IPv4Address])
DHCPOptionCode.MUD_URL_V4.register_type(String)
DHCPOptionCode.TFTP_SERVER_ADDRESS.register_type(List[IPv4Address])
DHCPOptionCode.BASE_TIME.register_type(U32)
DHCPOptionCode.START_TIME_OF_STATE.register_type(U32)
DHCPOptionCode.QUERY_START_TIME.register_type(U32)
DHCPOptionCode.QUERY_END_TIME.register_type(U32)
DHCPOptionCode.DHCP_STATE.register_type(U8)
DHCPOptionCode.DATA_SOURCE.register_type(U8)
# RFC 7291 s4: one or more (List-Length, addresses) entries. A flat list read
# the length octet as address data.
DHCPOptionCode.V4_PCP_SERVER.register_type(PcpServerList)
DHCPOptionCode.CONFIGURATION_FILE.register_type(String)
DHCPOptionCode.PATH_PREFIX.register_type(String)
DHCPOptionCode.REBOOT_TIME.register_type(U32)
# RFC 5986 s3.2: an uncompressed RFC 1035 label sequence, as for 147.
DHCPOptionCode.V4_ACCESS_DOMAIN.register_type(DomainName)
DHCPOptionCode.POLICY_FILTER.register_type(PolicyFilter)
DHCPOptionCode.NIS_DOMAIN.register_type(String)
DHCPOptionCode.NIS_PLUS_DOMAIN.register_type(String)
DHCPOptionCode.NIS_PLUS_SERVERS.register_type(List[IPv4Address])
DHCPOptionCode.NIS_SERVERS.register_type(List[IPv4Address])
DHCPOptionCode.NTP_SERVERS.register_type(List[IPv4Address])
DHCPOptionCode.OPTION_OVERLOAD.register_type(OptionOverload)
DHCPOptionCode.PARAMETER_REQUEST_LIST.register_type(DHCPOptionCodes[DHCPOptionCode])
# RFC 2937 s3: a list of 16-bit name service option codes, not domain names.
DHCPOptionCode.NAME_SERVICE_SEARCH.register_type(List[U16])
DHCPOptionCode.SUBNET_SELECTION_OPTION.register_type(IPv4Address)
DHCPOptionCode.REQUESTED_IP.register_type(IPv4Address)
DHCPOptionCode.REBINDING_TIME.register_type(U32)
DHCPOptionCode.RENEWAL_TIME.register_type(U32)
DHCPOptionCode.ROOT_PATH.register_type(String)
DHCPOptionCode.ROUTER.register_type(List[IPv4Address])
DHCPOptionCode.ROUTER_DISCOVERY.register_type(Boolean)
DHCPOptionCode.ROUTER_SOLICITATION_ADDRESS.register_type(IPv4Address)
DHCPOptionCode.STATIC_ROUTE.register_type(StaticRoute)
DHCPOptionCode.SERVER_IDENTIFIER.register_type(IPv4Address)
DHCPOptionCode.SUBNET_MASK.register_type(IPv4Address)
DHCPOptionCode.TCP_DEFAULT_TTL.register_type(U8)
DHCPOptionCode.TCP_KEEPALIVE_GARBAGE.register_type(Boolean)
DHCPOptionCode.TCP_KEEPALIVE_INTERVAL.register_type(U32)
DHCPOptionCode.TFTP_SERVER.register_type(String)
# RFC 2132 s9.13: 'a string of n octets' -- not NUL-terminated. String
# truncates at the first NUL, so a binary vendor class decoded to ''.
DHCPOptionCode.VENDOR_CLASS_IDENTIFIER.register_type(OctetString)
DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION.register_type(VendorSpecificInformation)
DHCPOptionCode.WPAD.register_type(String)
DHCPOptionCode.NETBIOS_SCOPE.register_type(String)
DHCPOptionCode.NETBIOS_NODE_TYPE.register_type(U8)
DHCPOptionCode.COOKIE_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.LPR_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.IMPRESS_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.RLP_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.NBNS_SERVERS.register_type(List[IPv4Address])
DHCPOptionCode.NBDD_SERVERS.register_type(List[IPv4Address])
DHCPOptionCode.X_WINDOW_FONT_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.X_WINDOW_MANAGER.register_type(List[IPv4Address])
DHCPOptionCode.HOME_AGENT_ADDRESSES.register_type(List[IPv4Address])
DHCPOptionCode.SMTP_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.POP3_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.NNTP_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.WWW_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.FINGER_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.IRC_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.STREETTALK_SERVER.register_type(List[IPv4Address])
DHCPOptionCode.STDA_SERVER.register_type(List[IPv4Address])
# RFC 3361 s3.1: a leading encoding octet selects names (0) or addresses (1).
DHCPOptionCode.SIP_SERVERS.register_type(SipServers)
DHCPOptionCode.ARP_TIMEOUT.register_type(U32)
DHCPOptionCode.IPV4_ADDRESS_MOS.register_type(MoSIpv4AddressList)
DHCPOptionCode.IPV4_FQDN_MOS.register_type(MoSFqdnList)
DHCPOptionCode.CCC.register_type(CccOption)
# Opaque by default, like VENDOR_SPECIFIC_INFORMATION (43): iPXE and several
# PXE ROMs send option 77 unframed rather than in RFC 3004's length-prefixed
# form, and a strict codec here rejects those packets outright. Ask for the
# structured form explicitly with options.get(77, decode=UserClass).
DHCPOptionCode.USER_CLASS.register_type(Bytes)
DHCPOptionCode.RELAY_AGENT_INFORMATION.register_type(RelayAgentInformation)
DHCPOptionCode.VI_VENDOR_SPECIFIC_INFORMATION.register_type(ViVendorSpecificInformation)
DHCPOptionCode.ALL_SUBNETS_ARE_LOCAL.register_type(Boolean)
DHCPOptionCode.TRAILER_ENCAPSULATION.register_type(Boolean)
# RFC 4039 s4: "Code 80, Len 0" -- presence is the whole message.
DHCPOptionCode.RAPID_COMMIT.register_type(Flag)
# RFC 6704 s3.1.2: one octet per supported algorithm. Boolean made a
# two-algorithm payload undecodable, and False wrote the undefined 0.
DHCPOptionCode.FORCERENEW_NONCE_CAPABLE.register_type(List[U8])
# RFC 6731 s4.3 defers to RFC 3315 s8: a domain name list in DHCP 'MUST NOT
# be stored in compressed form'. RdnssSelection holds an UncompressedDomainList.
DHCPOptionCode.RDNSS_SELECTION.register_type(RdnssSelection)
# RFC 6926 s6.2.2: a status octet plus an optional UTF-8 message.
DHCPOptionCode.STATUS_CODE.register_type(StatusCode)
