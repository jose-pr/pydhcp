import pytest
from pydhcp.options import DhcpOptions
from pydhcp.enum import DhcpOptionCode, DhcpMessageType
from pydhcp.optiontype import (
    IPv4Address,
    String,
    Boolean,
    Bytes,
    U16,
    PolicyFilter,
    StaticRoute,
    UserClass,
    VendorSpecificInformation,
    RelayAgentInformation,
    ViVendorSpecificInformationRecord,
    ViVendorSpecificInformation,
    RdnssSelection,
    MoSIpv4AddressList,
    MoSFqdnList,
    MoSIpv4AddressRecord,
    MoSFqdnRecord,
)

def test_options_set_get():
    opts = DhcpOptions()
    
    # Test setting enum / DhcpOptionType
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    assert opts.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPDISCOVER
    
    # Test setting raw bytes
    opts[DhcpOptionCode.ROUTER] = b"\xc0\xa8\x01\x01" # 192.168.1.1
    # Test decoding with type
    from pydhcp.netutils import IPv4
    assert opts.get(DhcpOptionCode.ROUTER, decode=IPv4Address) == IPv4("192.168.1.1")
    
    # Test missing / default
    assert opts.get(999, default="hello") == "hello"

def test_options_partial_encode():
    opts = DhcpOptions()
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    opts[DhcpOptionCode.HOSTNAME] = "test-host"
    
    encoded = opts.encode()
    assert len(encoded) > 0
    assert encoded[-1] == 255 # END mark
    
    # Decode back
    decoded_opts = DhcpOptions()
    decoded_opts.decode(memoryview(encoded))
    assert decoded_opts.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPDISCOVER
    assert decoded_opts.get(DhcpOptionCode.HOSTNAME, decode=String) == "test-host"


def test_typed_registrations_and_aliases():
    assert DhcpOptionCode.TCP_KEEPALIVE_GARBAGE.name == "TCP_KEEPALIVE_GARBAGE"
    assert DhcpOptionCode.NNTP_SERVER.name == "NNTP_SERVER"
    assert DhcpOptionCode.RFC868_TIMESERVER.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.SWAP_SERVER.get_type() is IPv4Address
    assert DhcpOptionCode.NETBIOS_SCOPE.get_type() is String
    assert DhcpOptionCode.LOG_SERVER.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.SIP_SERVERS.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST.get_type().__name__ == "DomainList"
    assert DhcpOptionCode.BCMCS_IPV4_ADDRESS.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.ASSOCIATED_IP.get_type() is IPv4Address
    assert DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE.get_type()._args_[0].__name__ == "U16"
    assert DhcpOptionCode.IPV6_ONLY.get_type().__name__ == "U32"
    assert DhcpOptionCode.NETINFO_ADDRESS.get_type() is IPv4Address
    assert DhcpOptionCode.AUTO_CONFIG.get_type() is Boolean
    assert DhcpOptionCode.CAPWAP_AC_V4.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS.get_type().__name__ == "DomainList"
    assert DhcpOptionCode.IPV4_ADDRESS_ANDSF.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.V4_DOTS_ADDRESS.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.TFTP_SERVER_ADDRESS.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.BASE_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.START_TIME_OF_STATE.get_type().__name__ == "U32"
    assert DhcpOptionCode.QUERY_START_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.QUERY_END_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.DHCP_STATE.get_type().__name__ == "U8"
    assert DhcpOptionCode.DATA_SOURCE.get_type().__name__ == "U8"
    assert DhcpOptionCode.V4_PCP_SERVER.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.REBOOT_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.RAPID_COMMIT.get_type() is Boolean
    assert DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL.get_type() is Boolean
    assert DhcpOptionCode.TRAILER_ENCAPSULATION.get_type() is Boolean
    assert DhcpOptionCode.FORCERENEW_NONCE_CAPABLE.get_type() is Boolean
    assert DhcpOptionCode.MERIT_DUMP_FILE.get_type() is String
    assert DhcpOptionCode.ARP_TIMEOUT.get_type().__name__ == "U32"
    assert DhcpOptionCode.STATUS_CODE.get_type().__name__ == "U8"
    assert DhcpOptionCode.POLICY_FILTER.get_type() is PolicyFilter
    assert DhcpOptionCode.STATIC_ROUTE.get_type() is StaticRoute
    assert DhcpOptionCode.USER_CLASS.get_type() is UserClass
    assert DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION.get_type() is VendorSpecificInformation
    assert DhcpOptionCode.RELAY_AGENT_INFORMATION.get_type() is RelayAgentInformation
    assert DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION.get_type() is ViVendorSpecificInformation
    assert DhcpOptionCode.NAME_SERVICE_SEARCH.get_type().__name__ == "DomainList"
    assert DhcpOptionCode.SUBNET_SELECTION_OPTION.get_type() is IPv4Address
    assert DhcpOptionCode.RDNSS_SELECTION.get_type() is RdnssSelection
    assert DhcpOptionCode.IPV4_ADDRESS_MOS.get_type() is MoSIpv4AddressList
    assert DhcpOptionCode.IPV4_FQDN_MOS.get_type() is MoSFqdnList

    opts = DhcpOptions()
    opts[DhcpOptionCode.LOG_SERVER] = ["10.0.0.1", "10.0.0.2"]
    opts[DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST] = ["alpha.example", "beta.example"]
    opts[DhcpOptionCode.BCMCS_IPV4_ADDRESS] = ["10.0.0.7", "10.0.0.8"]
    opts[DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE] = [1, 2]
    opts[DhcpOptionCode.RFC868_TIMESERVER] = ["10.0.0.4"]
    opts[DhcpOptionCode.IEN116_NAMESERVER] = ["10.0.0.5"]
    opts[DhcpOptionCode.SWAP_SERVER] = "10.0.0.6"
    opts[DhcpOptionCode.SIP_SERVERS] = ["10.0.0.3"]
    opts[DhcpOptionCode.ASSOCIATED_IP] = "192.0.2.20"
    opts[DhcpOptionCode.NETINFO_ADDRESS] = "192.0.2.21"
    opts[DhcpOptionCode.CAPWAP_AC_V4] = ["192.0.2.30", "192.0.2.31"]
    opts[DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS] = ["service.example", "config.example"]
    opts[DhcpOptionCode.IPV4_ADDRESS_ANDSF] = ["192.0.2.40", "192.0.2.41"]
    opts[DhcpOptionCode.V4_DOTS_ADDRESS] = ["192.0.2.50", "192.0.2.51"]
    opts[DhcpOptionCode.TFTP_SERVER_ADDRESS] = ["192.0.2.60", "192.0.2.61"]
    opts[DhcpOptionCode.V4_PCP_SERVER] = ["192.0.2.70", "192.0.2.71"]
    opts[DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME] = 1234
    opts[DhcpOptionCode.IPV6_ONLY] = 4321
    opts[DhcpOptionCode.BASE_TIME] = 111
    opts[DhcpOptionCode.START_TIME_OF_STATE] = 222
    opts[DhcpOptionCode.QUERY_START_TIME] = 333
    opts[DhcpOptionCode.QUERY_END_TIME] = 444
    opts[DhcpOptionCode.REBOOT_TIME] = 555
    opts[DhcpOptionCode.DHCP_STATE] = 7
    opts[DhcpOptionCode.DATA_SOURCE] = 3
    opts[DhcpOptionCode.AUTO_CONFIG] = True
    opts[DhcpOptionCode.IP_FORWARDING] = 1
    opts[DhcpOptionCode.RAPID_COMMIT] = True
    opts[DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL] = False
    opts[DhcpOptionCode.TRAILER_ENCAPSULATION] = 1
    opts[DhcpOptionCode.FORCERENEW_NONCE_CAPABLE] = 1
    assert isinstance(opts.get(DhcpOptionCode.LOG_SERVER)[0], IPv4Address)
    assert opts.get(DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST) == ["alpha.example", "beta.example"]
    assert isinstance(opts.get(DhcpOptionCode.BCMCS_IPV4_ADDRESS)[0], IPv4Address)
    assert opts.get(DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE) == [U16(1), U16(2)]
    assert isinstance(opts.get(DhcpOptionCode.RFC868_TIMESERVER)[0], IPv4Address)
    assert isinstance(opts.get(DhcpOptionCode.IEN116_NAMESERVER)[0], IPv4Address)
    assert opts.get(DhcpOptionCode.SWAP_SERVER) == IPv4Address("10.0.0.6")
    assert isinstance(opts.get(DhcpOptionCode.SIP_SERVERS)[0], IPv4Address)
    assert opts.get(DhcpOptionCode.ASSOCIATED_IP) == IPv4Address("192.0.2.20")
    assert opts.get(DhcpOptionCode.NETINFO_ADDRESS) == IPv4Address("192.0.2.21")
    assert isinstance(opts.get(DhcpOptionCode.CAPWAP_AC_V4)[0], IPv4Address)
    assert opts.get(DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS) == ["service.example", "config.example"]
    assert isinstance(opts.get(DhcpOptionCode.IPV4_ADDRESS_ANDSF)[0], IPv4Address)
    assert isinstance(opts.get(DhcpOptionCode.V4_DOTS_ADDRESS)[0], IPv4Address)
    assert isinstance(opts.get(DhcpOptionCode.TFTP_SERVER_ADDRESS)[0], IPv4Address)
    assert opts.get(DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME).__class__.__name__ == "U32"
    assert opts.get(DhcpOptionCode.IPV6_ONLY).__class__.__name__ == "U32"
    assert opts.get(DhcpOptionCode.BASE_TIME).__class__.__name__ == "U32"
    assert opts.get(DhcpOptionCode.START_TIME_OF_STATE).__class__.__name__ == "U32"
    assert opts.get(DhcpOptionCode.QUERY_START_TIME).__class__.__name__ == "U32"
    assert opts.get(DhcpOptionCode.QUERY_END_TIME).__class__.__name__ == "U32"
    assert opts.get(DhcpOptionCode.REBOOT_TIME).__class__.__name__ == "U32"
    assert opts.get(DhcpOptionCode.DHCP_STATE).__class__.__name__ == "U8"
    assert opts.get(DhcpOptionCode.DATA_SOURCE).__class__.__name__ == "U8"
    assert opts.get(DhcpOptionCode.AUTO_CONFIG) == Boolean(1)
    assert opts.get(DhcpOptionCode.IP_FORWARDING) == Boolean(1)
    assert opts.get(DhcpOptionCode.RAPID_COMMIT) == Boolean(1)
    assert opts.get(DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL) == Boolean(0)
    assert opts.get(DhcpOptionCode.TRAILER_ENCAPSULATION) == Boolean(1)
    assert opts.get(DhcpOptionCode.FORCERENEW_NONCE_CAPABLE) == Boolean(1)

    opts[DhcpOptionCode.MERIT_DUMP_FILE] = "core.dump"
    assert opts.get(DhcpOptionCode.MERIT_DUMP_FILE, decode=String) == "core.dump"

    opts[DhcpOptionCode.POLICY_FILTER] = PolicyFilter([
        ("192.0.2.1", "255.255.255.0"),
    ])
    opts[DhcpOptionCode.STATIC_ROUTE] = StaticRoute([
        ("192.0.2.0", "192.0.2.1"),
    ])
    opts[DhcpOptionCode.USER_CLASS] = UserClass([b"alpha", b"\x00\xff"])
    opts[DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION] = VendorSpecificInformation(b"\x00\xff\x02vendor\x10")
    opts[DhcpOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation([(9, b"\x02")])
    opts[DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION] = ViVendorSpecificInformation([
        (32473, b"alpha"),
        ViVendorSpecificInformationRecord(65537, b"\x00\xff"),
    ])
    opts[DhcpOptionCode.NAME_SERVICE_SEARCH] = ["alpha.example", "beta.example"]
    opts[DhcpOptionCode.SUBNET_SELECTION_OPTION] = "192.0.2.64"
    opts[DhcpOptionCode.RDNSS_SELECTION] = RdnssSelection(1, "192.0.2.1", "192.0.2.2", ["example.com"])
    opts[DhcpOptionCode.IPV4_ADDRESS_MOS] = [
        MoSIpv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
        (99, b"\x01\x02"),
    ]
    opts[DhcpOptionCode.IPV4_FQDN_MOS] = [
        MoSFqdnRecord(1, ["alpha.example", "beta.example"]),
        (99, b"\x03raw"),
    ]
    assert opts.get(DhcpOptionCode.POLICY_FILTER)[0][0] == IPv4Address("192.0.2.1")
    assert opts.get(DhcpOptionCode.STATIC_ROUTE)[0][0] == IPv4Address("192.0.2.0")
    assert opts.get(DhcpOptionCode.USER_CLASS) == UserClass([b"alpha", b"\x00\xff"])
    assert opts.get(DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION) == VendorSpecificInformation(b"\x00\xff\x02vendor\x10")
    assert isinstance(opts.get(DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION), Bytes)
    assert opts.get(DhcpOptionCode.RELAY_AGENT_INFORMATION)[0].value == b"\x02"
    assert opts.get(DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION)[0].enterprise_number == 32473
    assert opts.get(DhcpOptionCode.NAME_SERVICE_SEARCH) == ["alpha.example", "beta.example"]
    assert opts.get(DhcpOptionCode.SUBNET_SELECTION_OPTION) == IPv4Address("192.0.2.64")
    assert opts.get(DhcpOptionCode.RDNSS_SELECTION) == RdnssSelection(1, "192.0.2.1", "192.0.2.2", ["example.com"])
    assert opts.get(DhcpOptionCode.V4_PCP_SERVER)[0] == IPv4Address("192.0.2.70")
    assert opts.get(DhcpOptionCode.IPV4_ADDRESS_MOS) == MoSIpv4AddressList([
        MoSIpv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
        (99, b"\x01\x02"),
    ])
    assert opts.get(DhcpOptionCode.IPV4_FQDN_MOS) == MoSFqdnList([
        MoSFqdnRecord(1, ["alpha.example", "beta.example"]),
        (99, b"\x03raw"),
    ])


def test_registered_option_code_round_trips():
    opts = DhcpOptions()
    opts[DhcpOptionCode.SIP_SERVERS] = ["192.0.2.10", "192.0.2.11"]
    opts[DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST] = ["alpha.example", "beta.example"]
    opts[DhcpOptionCode.BCMCS_IPV4_ADDRESS] = ["192.0.2.14", "192.0.2.15"]
    opts[DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE] = [1, 2]
    opts[DhcpOptionCode.RFC868_TIMESERVER] = ["192.0.2.12"]
    opts[DhcpOptionCode.SWAP_SERVER] = "192.0.2.13"
    opts[DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME] = 1234
    opts[DhcpOptionCode.ASSOCIATED_IP] = "192.0.2.20"
    opts[DhcpOptionCode.IPV6_ONLY] = 4321
    opts[DhcpOptionCode.NETINFO_ADDRESS] = "192.0.2.21"
    opts[DhcpOptionCode.AUTO_CONFIG] = True
    opts[DhcpOptionCode.CAPWAP_AC_V4] = ["192.0.2.30", "192.0.2.31"]
    opts[DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS] = ["service.example", "config.example"]
    opts[DhcpOptionCode.IPV4_ADDRESS_ANDSF] = ["192.0.2.40", "192.0.2.41"]
    opts[DhcpOptionCode.V4_DOTS_ADDRESS] = ["192.0.2.50", "192.0.2.51"]
    opts[DhcpOptionCode.TFTP_SERVER_ADDRESS] = ["192.0.2.60", "192.0.2.61"]
    opts[DhcpOptionCode.BASE_TIME] = 111
    opts[DhcpOptionCode.START_TIME_OF_STATE] = 222
    opts[DhcpOptionCode.QUERY_START_TIME] = 333
    opts[DhcpOptionCode.QUERY_END_TIME] = 444
    opts[DhcpOptionCode.DHCP_STATE] = 7
    opts[DhcpOptionCode.DATA_SOURCE] = 3
    opts[DhcpOptionCode.V4_PCP_SERVER] = ["192.0.2.70", "192.0.2.71"]
    opts[DhcpOptionCode.REBOOT_TIME] = 555
    opts[DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL] = True
    opts[DhcpOptionCode.MERIT_DUMP_FILE] = "crash.dump"
    opts[DhcpOptionCode.STATUS_CODE] = 7
    opts[DhcpOptionCode.POLICY_FILTER] = PolicyFilter([("192.0.2.1", "255.255.255.0")])
    opts[DhcpOptionCode.STATIC_ROUTE] = StaticRoute([("192.0.2.0", "192.0.2.1")])
    opts[DhcpOptionCode.USER_CLASS] = UserClass([b"alpha", b"\x00\xff"])
    opts[DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION] = VendorSpecificInformation(b"\x00\xff\x02vendor\x10")
    opts[DhcpOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation([(9, b"\x02")])
    opts[DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION] = ViVendorSpecificInformation([
        (32473, b"alpha"),
        ViVendorSpecificInformationRecord(65537, b"\x00\xff"),
    ])
    opts[DhcpOptionCode.NAME_SERVICE_SEARCH] = ["alpha.example", "beta.example"]
    opts[DhcpOptionCode.SUBNET_SELECTION_OPTION] = "192.0.2.64"
    opts[DhcpOptionCode.RDNSS_SELECTION] = RdnssSelection(1, "192.0.2.1", "192.0.2.2", ["example.com"])
    opts[DhcpOptionCode.IPV4_ADDRESS_MOS] = [
        MoSIpv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
        (99, b"\x01\x02"),
    ]
    opts[DhcpOptionCode.IPV4_FQDN_MOS] = [
        MoSFqdnRecord(1, ["alpha.example", "beta.example"]),
        (99, b"\x03raw"),
    ]

    encoded = opts.encode()
    decoded = DhcpOptions()
    decoded.decode(memoryview(encoded))

    assert decoded.get(DhcpOptionCode.SIP_SERVERS)[0] == IPv4Address("192.0.2.10")
    assert decoded.get(DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST) == ["alpha.example", "beta.example"]
    assert isinstance(decoded.get(DhcpOptionCode.BCMCS_IPV4_ADDRESS)[0], IPv4Address)
    assert decoded.get(DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE) == [U16(1), U16(2)]
    assert decoded.get(DhcpOptionCode.RFC868_TIMESERVER)[0] == IPv4Address("192.0.2.12")
    assert decoded.get(DhcpOptionCode.SWAP_SERVER) == IPv4Address("192.0.2.13")
    assert decoded.get(DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME).__class__.__name__ == "U32"
    assert decoded.get(DhcpOptionCode.ASSOCIATED_IP) == IPv4Address("192.0.2.20")
    assert decoded.get(DhcpOptionCode.IPV6_ONLY).__class__.__name__ == "U32"
    assert decoded.get(DhcpOptionCode.NETINFO_ADDRESS) == IPv4Address("192.0.2.21")
    assert decoded.get(DhcpOptionCode.AUTO_CONFIG) == Boolean(1)
    assert isinstance(decoded.get(DhcpOptionCode.CAPWAP_AC_V4)[0], IPv4Address)
    assert decoded.get(DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS) == ["service.example", "config.example"]
    assert isinstance(decoded.get(DhcpOptionCode.IPV4_ADDRESS_ANDSF)[0], IPv4Address)
    assert isinstance(decoded.get(DhcpOptionCode.V4_DOTS_ADDRESS)[0], IPv4Address)
    assert isinstance(decoded.get(DhcpOptionCode.TFTP_SERVER_ADDRESS)[0], IPv4Address)
    assert decoded.get(DhcpOptionCode.BASE_TIME).__class__.__name__ == "U32"
    assert decoded.get(DhcpOptionCode.START_TIME_OF_STATE).__class__.__name__ == "U32"
    assert decoded.get(DhcpOptionCode.QUERY_START_TIME).__class__.__name__ == "U32"
    assert decoded.get(DhcpOptionCode.QUERY_END_TIME).__class__.__name__ == "U32"
    assert decoded.get(DhcpOptionCode.DHCP_STATE).__class__.__name__ == "U8"
    assert decoded.get(DhcpOptionCode.DATA_SOURCE).__class__.__name__ == "U8"
    assert isinstance(decoded.get(DhcpOptionCode.V4_PCP_SERVER)[0], IPv4Address)
    assert decoded.get(DhcpOptionCode.REBOOT_TIME).__class__.__name__ == "U32"
    assert decoded.get(DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL) == Boolean(1)
    assert decoded.get(DhcpOptionCode.MERIT_DUMP_FILE, decode=String) == "crash.dump"
    assert decoded.get(DhcpOptionCode.STATUS_CODE) == 7
    assert decoded.get(DhcpOptionCode.POLICY_FILTER)[0][0] == IPv4Address("192.0.2.1")
    assert decoded.get(DhcpOptionCode.STATIC_ROUTE)[0][1] == IPv4Address("192.0.2.1")
    assert decoded.get(DhcpOptionCode.USER_CLASS) == UserClass([b"alpha", b"\x00\xff"])
    assert decoded.get(DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION) == VendorSpecificInformation(b"\x00\xff\x02vendor\x10")
    assert isinstance(decoded.get(DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION), Bytes)
    assert decoded.get(DhcpOptionCode.RELAY_AGENT_INFORMATION)[0].value == b"\x02"
    assert decoded.get(DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION)[0].enterprise_number == 32473
    assert decoded.get(DhcpOptionCode.NAME_SERVICE_SEARCH) == ["alpha.example", "beta.example"]
    assert decoded.get(DhcpOptionCode.SUBNET_SELECTION_OPTION) == IPv4Address("192.0.2.64")
    assert decoded.get(DhcpOptionCode.RDNSS_SELECTION) == RdnssSelection(1, "192.0.2.1", "192.0.2.2", ["example.com"])
    assert decoded.get(DhcpOptionCode.V4_PCP_SERVER)[0] == IPv4Address("192.0.2.70")
    assert decoded.get(DhcpOptionCode.IPV4_ADDRESS_MOS) == MoSIpv4AddressList([
        MoSIpv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
        (99, b"\x01\x02"),
    ])
    assert decoded.get(DhcpOptionCode.IPV4_FQDN_MOS) == MoSFqdnList([
        MoSFqdnRecord(1, ["alpha.example", "beta.example"]),
        (99, b"\x03raw"),
    ])


def test_raw_wire_decoding_for_opaque_and_enterprise_specific_options():
    vendor_payload = b"\x00\xff\x02vendor\x10"
    vi_payload = (
        (32473).to_bytes(4, "big")
        + b"\x05alpha"
        + (65537).to_bytes(4, "big")
        + b"\x02\x00\xff"
    )

    encoded = bytearray()
    encoded.extend([DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION, len(vendor_payload)])
    encoded.extend(vendor_payload)
    encoded.extend([DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION, len(vi_payload)])
    encoded.extend(vi_payload)
    encoded.append(255)

    decoded = DhcpOptions()
    decoded.decode(memoryview(encoded))

    assert decoded.get(DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION) == VendorSpecificInformation(vendor_payload)
    assert decoded.get(DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION) == ViVendorSpecificInformation([
        (32473, b"alpha"),
        ViVendorSpecificInformationRecord(65537, b"\x00\xff"),
    ])
    assert DhcpOptionCode.IPV4_ADDRESS_MOS.get_type() is MoSIpv4AddressList
    assert DhcpOptionCode.IPV4_FQDN_MOS.get_type() is MoSFqdnList


def test_raw_wire_decoding_for_new_primitive_registrations():
    encoded = bytearray()
    encoded.extend([DhcpOptionCode.ASSOCIATED_IP, 4])
    encoded.extend(IPv4Address("192.0.2.25").packed)
    encoded.extend([DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME, 4])
    encoded.extend((1234).to_bytes(4, "big"))
    encoded.extend([DhcpOptionCode.DHCP_STATE, 1, 7])
    encoded.extend([DhcpOptionCode.AUTO_CONFIG, 1, 1])
    encoded.extend([DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST, 15])
    encoded.extend(b"\x05alpha\x07example\x00")
    encoded.append(255)

    decoded = DhcpOptions()
    decoded.decode(memoryview(encoded))

    assert decoded.get(DhcpOptionCode.ASSOCIATED_IP) == IPv4Address("192.0.2.25")
    assert decoded.get(DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME).__class__.__name__ == "U32"
    assert decoded.get(DhcpOptionCode.DHCP_STATE).__class__.__name__ == "U8"
    assert decoded.get(DhcpOptionCode.AUTO_CONFIG) == Boolean(1)
    assert decoded.get(DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST) == ["alpha.example"]


def test_register_type_rejects_invalid_type():
    with pytest.raises(TypeError):
        DhcpOptionCode.LOG_SERVER.register_type(int)  # type: ignore[arg-type]
