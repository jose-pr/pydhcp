import pytest
from pydhcp.packet import DhcpMessageType
from pydhcp.options import DhcpOptions
from pydhcp.options import DhcpOptionCode
from pydhcp.options.type import (
    IPv4Address,
    SipServers,
    ClientFqdn,
    String,
    Boolean,
    Flag,
    Bytes,
    U16,
    U8,
    U32,
    PolicyFilter,
    StaticRoute,
    UserClass,
    VendorSpecificInformation,
    RelayAgentInformation,
    ViVendorSpecificInformationRecord,
    ViVendorSpecificInformation,
    ViVendorClassRecord,
    ViVendorClass,
    RdnssSelection,
    MoSIpv4AddressList,
    MoSFqdnList,
    MoSIpv4AddressRecord,
    MoSFqdnRecord,
    UriList,
    CccOption,
    CccPrimaryDhcpServerAddressSubOption,
    CccSecondaryDhcpServerAddressSubOption,
    CccProvisioningServerAddressSubOption,
    CccAsReqAsRepBackoffRetrySubOption,
    CccApReqApRepBackoffRetrySubOption,
    CccKerberosRealmNameSubOption,
    CccTicketGrantingServerUtilizationSubOption,
    CccProvisioningTimerSubOption,
    CccSecurityTicketControlSubOption,
    CccKdcServerAddressSubOption,
)


def _assert_scalar(opts, code, width: type, expected: int):
    """Assert an option decodes to exactly this width *and* this value.

    The type was the whole assertion before, spelled
    `opts.get(...).__class__.__name__ == "U32"`, so an option that decoded
    through the right codec to the wrong number passed. Both halves are needed
    and neither implies the other: `U8(7) == U32(7)` is True (they are `int`
    subclasses), so value equality alone does not pin the width -- which is why
    this checks `type(...) is`, not `isinstance`.
    """
    value = opts.get(code)
    assert type(value) is width, f"{code!r}: {type(value).__name__}"
    assert value == expected, f"{code!r}: {value!r}"
    return value


def _assert_addresses(opts, code, expected: list):
    """Assert an address-list option decodes to exactly these addresses.

    `isinstance(value[0], IPv4Address)` was the whole assertion before: the
    list's length, every entry after the first, and every address in it went
    unchecked, so a codec that stopped after one entry -- or produced the right
    count of wrong addresses -- passed. The per-element type check is kept as
    well because `IPv4Address` compares equal to a plain
    `ipaddress.IPv4Address`, so values alone would not pin the type.
    """
    value = opts.get(code)
    assert [type(item) for item in value] == [IPv4Address] * len(
        expected
    ), f"{code!r}: {[type(item).__name__ for item in value]}"
    assert list(value) == [IPv4Address(a) for a in expected], f"{code!r}: {value!r}"
    return value


def test_options_set_get():
    opts = DhcpOptions()

    # Test setting enum / DhcpOptionType
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    assert opts.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPDISCOVER

    # Test setting raw bytes
    opts[DhcpOptionCode.ROUTER] = b"\xc0\xa8\x01\x01"  # 192.168.1.1
    # Test decoding with type
    from pydhcp.network import IPv4

    assert opts.get(DhcpOptionCode.ROUTER, decode=IPv4Address) == IPv4("192.168.1.1")

    # Test missing / default
    assert opts.get(999, default="hello") == "hello"


def test_options_encode_round_trip():
    # Renamed: this calls `encode()`, so it never exercised `partial_encode`'s
    # size limit or its leftover bag -- the two things that name refers to.
    # The real one is `test_options_partial_encode_splits_and_returns_leftovers`.
    opts = DhcpOptions()
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    opts[DhcpOptionCode.HOSTNAME] = "test-host"

    encoded = opts.encode()
    assert len(encoded) > 0
    assert encoded[-1] == 255  # END mark

    # Decode back
    decoded_opts = DhcpOptions()
    decoded_opts.decode(memoryview(encoded))
    assert (
        decoded_opts.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
        == DhcpMessageType.DHCPDISCOVER
    )
    assert decoded_opts.get(DhcpOptionCode.HOSTNAME, decode=String) == "test-host"


def test_options_partial_encode_splits_and_returns_leftovers():
    """`partial_encode(maxsize)` fills the budget and hands back the remainder.

    This is what the old `test_options_partial_encode` was named for and never
    touched: it called `encode()`, which is `partial_encode(None)` -- no limit,
    so no split and always a `None` leftover. The split is what a reply near
    the client's maximum message size depends on, and it was untested.
    """
    opts = DhcpOptions()
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    opts[DhcpOptionCode.HOSTNAME] = "test-host"

    encoded, leftover = opts.partial_encode(8)

    # Exactly the budget, END included, and never a byte over it.
    assert len(encoded) == 8
    assert encoded[-1] == 255
    # 53/01/01 whole, then as much of the hostname as fits: 0c/02/"te".
    assert bytes(encoded) == b"\x35\x01\x01\x0c\x02te\xff"

    assert leftover is not None
    assert leftover.get(DhcpOptionCode.HOSTNAME, decode=False) == bytearray(b"st-host")
    assert DhcpOptionCode.DHCP_MESSAGE_TYPE not in leftover

    # The fragment that did fit is a complete, decodable option in its own
    # right -- RFC 3396 s4 requires each instance to carry its own code and
    # length octet -- rather than a dangling continuation.
    decoded = DhcpOptions()
    decoded.decode(memoryview(encoded))
    assert decoded.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPDISCOVER
    assert decoded.get(DhcpOptionCode.HOSTNAME, decode=String) == "te"

    # No limit means no split: the contrast is the point.
    whole, nothing_left = opts.partial_encode(None)
    assert nothing_left is None
    assert bytes(whole) == b"\x35\x01\x01\x0c\ttest-host\xff"


def test_typed_registrations_and_aliases():
    assert DhcpOptionCode.TCP_KEEPALIVE_GARBAGE.name == "TCP_KEEPALIVE_GARBAGE"
    assert DhcpOptionCode.NNTP_SERVER.name == "NNTP_SERVER"
    assert DhcpOptionCode.RFC868_TIMESERVER.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.SWAP_SERVER.get_type() is IPv4Address
    assert DhcpOptionCode.NETBIOS_SCOPE.get_type() is String
    assert DhcpOptionCode.LOG_SERVER.get_type()._args_[0] is IPv4Address
    # RFC 3361 s3.1: an encoding octet selects names (0) or addresses (1),
    # so this is not a bare address list.
    assert DhcpOptionCode.SIP_SERVERS.get_type() is SipServers
    # RFC 4280 s4.6: "DNS name compression MUST NOT be used" -- so option 88 is
    # NOT the compressed `DomainList` that RFC 3397's option 119 is. Details and
    # the measured payloads: tests/test_options_domain_lists.py.
    assert (
        DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST.get_type().__name__
        == "UncompressedDomainList"
    )
    assert DhcpOptionCode.BCMCS_IPV4_ADDRESS.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.ASSOCIATED_IP.get_type()._args_[0] is IPv4Address
    assert (
        DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE.get_type()._args_[0].__name__ == "U16"
    )
    assert DhcpOptionCode.PCODE.get_type() is String
    assert DhcpOptionCode.TCODE.get_type() is String
    assert DhcpOptionCode.IPV6_ONLY.get_type().__name__ == "U32"
    assert DhcpOptionCode.NETINFO_ADDRESS.get_type() is IPv4Address
    assert DhcpOptionCode.NETINFO_TAG.get_type() is String
    assert DhcpOptionCode.DHCP_CAPTIVE_PORTAL.get_type() is String
    assert DhcpOptionCode.AUTO_CONFIG.get_type() is Boolean
    assert DhcpOptionCode.VI_VENDOR_CLASS.get_type() is ViVendorClass
    assert DhcpOptionCode.CAPWAP_AC_V4.get_type()._args_[0] is IPv4Address
    assert (
        DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS.get_type().__name__ == "DomainList"
    )
    assert DhcpOptionCode.IPV4_ADDRESS_ANDSF.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.V4_SZTP_REDIRECT.get_type() is UriList
    assert DhcpOptionCode.V4_DOTS_RI.get_type().__name__ == "DomainName"
    assert DhcpOptionCode.V4_DOTS_ADDRESS.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.TFTP_SERVER_ADDRESS.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.BASE_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.START_TIME_OF_STATE.get_type().__name__ == "U32"
    assert DhcpOptionCode.QUERY_START_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.QUERY_END_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.DHCP_STATE.get_type().__name__ == "U8"
    assert DhcpOptionCode.DATA_SOURCE.get_type().__name__ == "U8"
    assert DhcpOptionCode.V4_PCP_SERVER.get_type().__name__ == "PcpServerList"
    assert DhcpOptionCode.MUD_URL_V4.get_type() is String
    assert DhcpOptionCode.CONFIGURATION_FILE.get_type() is String
    assert DhcpOptionCode.PATH_PREFIX.get_type() is String
    assert DhcpOptionCode.REBOOT_TIME.get_type().__name__ == "U32"
    assert DhcpOptionCode.V4_ACCESS_DOMAIN.get_type().__name__ == "DomainName"
    # RFC 4039 s4: "Code 80, Len 0" -- presence-only, not a one-octet boolean.
    assert DhcpOptionCode.RAPID_COMMIT.get_type() is Flag
    assert DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL.get_type() is Boolean
    assert DhcpOptionCode.TRAILER_ENCAPSULATION.get_type() is Boolean
    assert DhcpOptionCode.FORCERENEW_NONCE_CAPABLE.get_type()._args_[0] is U8
    assert DhcpOptionCode.MERIT_DUMP_FILE.get_type() is String
    assert DhcpOptionCode.ARP_TIMEOUT.get_type().__name__ == "U32"
    assert DhcpOptionCode.STATUS_CODE.get_type().__name__ == "StatusCode"
    assert DhcpOptionCode.POLICY_FILTER.get_type() is PolicyFilter
    assert DhcpOptionCode.STATIC_ROUTE.get_type() is StaticRoute
    # Opaque by default like option 43: iPXE sends option 77 unframed, and a
    # strict RFC 3004 codec rejects those packets. UserClass stays opt-in.
    assert DhcpOptionCode.USER_CLASS.get_type() is Bytes
    assert (
        DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION.get_type()
        is VendorSpecificInformation
    )
    assert DhcpOptionCode.RELAY_AGENT_INFORMATION.get_type() is RelayAgentInformation
    assert (
        DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION.get_type()
        is ViVendorSpecificInformation
    )
    # RFC 2937 s3: 16-bit name service option codes, not domain names.
    assert DhcpOptionCode.NAME_SERVICE_SEARCH.get_type()._args_[0].__name__ == "U16"
    assert DhcpOptionCode.SUBNET_SELECTION_OPTION.get_type() is IPv4Address
    assert DhcpOptionCode.RDNSS_SELECTION.get_type() is RdnssSelection
    assert DhcpOptionCode.IPV4_ADDRESS_MOS.get_type() is MoSIpv4AddressList
    assert DhcpOptionCode.IPV4_FQDN_MOS.get_type() is MoSFqdnList

    opts = DhcpOptions()
    opts[DhcpOptionCode.LOG_SERVER] = ["10.0.0.1", "10.0.0.2"]
    opts[DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST] = ["alpha.example", "beta.example"]
    opts[DhcpOptionCode.BCMCS_IPV4_ADDRESS] = ["10.0.0.7", "10.0.0.8"]
    opts[DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE] = [1, 2]
    opts[DhcpOptionCode.PCODE] = "Europe/Berlin"
    opts[DhcpOptionCode.TCODE] = "tz.example/ref"
    opts[DhcpOptionCode.RFC868_TIMESERVER] = ["10.0.0.4"]
    opts[DhcpOptionCode.IEN116_NAMESERVER] = ["10.0.0.5"]
    opts[DhcpOptionCode.SWAP_SERVER] = "10.0.0.6"
    opts[DhcpOptionCode.SIP_SERVERS] = ["10.0.0.3"]  # inferred as encoding 1
    opts[DhcpOptionCode.ASSOCIATED_IP] = ["192.0.2.20", "192.0.2.21"]
    opts[DhcpOptionCode.NETINFO_ADDRESS] = "192.0.2.21"
    opts[DhcpOptionCode.NETINFO_TAG] = "lab-a"
    opts[DhcpOptionCode.DHCP_CAPTIVE_PORTAL] = "https://portal.example/login"
    opts[DhcpOptionCode.VI_VENDOR_CLASS] = [
        ViVendorClassRecord(32473, [b"docsis", b"eRouter"]),
        (65537, [b"usp", b"agent"]),
    ]
    opts[DhcpOptionCode.CAPWAP_AC_V4] = ["192.0.2.30", "192.0.2.31"]
    opts[DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS] = [
        "service.example",
        "config.example",
    ]
    opts[DhcpOptionCode.IPV4_ADDRESS_ANDSF] = ["192.0.2.40", "192.0.2.41"]
    opts[DhcpOptionCode.V4_SZTP_REDIRECT] = [
        "https://bootstrap.example/one",
        "https://bootstrap.example/two",
    ]
    opts[DhcpOptionCode.V4_DOTS_RI] = "resolver-a.example"
    opts[DhcpOptionCode.V4_DOTS_ADDRESS] = ["192.0.2.50", "192.0.2.51"]
    opts[DhcpOptionCode.TFTP_SERVER_ADDRESS] = ["192.0.2.60", "192.0.2.61"]
    opts[DhcpOptionCode.V4_PCP_SERVER] = ["192.0.2.70", "192.0.2.71"]
    opts[DhcpOptionCode.MUD_URL_V4] = "https://mud.example/policy"
    opts[DhcpOptionCode.CONFIGURATION_FILE] = "/pxe/config.cfg"
    opts[DhcpOptionCode.PATH_PREFIX] = "/pxe/"
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
    opts[DhcpOptionCode.V4_ACCESS_DOMAIN] = "access.example"
    opts[DhcpOptionCode.IP_FORWARDING] = 1
    opts[DhcpOptionCode.RAPID_COMMIT] = True
    opts[DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL] = False
    opts[DhcpOptionCode.TRAILER_ENCAPSULATION] = 1
    opts[DhcpOptionCode.FORCERENEW_NONCE_CAPABLE] = [1]
    _assert_addresses(opts, DhcpOptionCode.LOG_SERVER, ["10.0.0.1", "10.0.0.2"])
    assert opts.get(DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST) == [
        "alpha.example",
        "beta.example",
    ]
    _assert_addresses(opts, DhcpOptionCode.BCMCS_IPV4_ADDRESS, ["10.0.0.7", "10.0.0.8"])
    assert opts.get(DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE) == [U16(1), U16(2)]
    assert opts.get(DhcpOptionCode.PCODE, decode=String) == "Europe/Berlin"
    assert opts.get(DhcpOptionCode.TCODE, decode=String) == "tz.example/ref"
    _assert_addresses(opts, DhcpOptionCode.RFC868_TIMESERVER, ["10.0.0.4"])
    _assert_addresses(opts, DhcpOptionCode.IEN116_NAMESERVER, ["10.0.0.5"])
    assert opts.get(DhcpOptionCode.SWAP_SERVER) == IPv4Address("10.0.0.6")
    sip = opts.get(DhcpOptionCode.SIP_SERVERS)
    assert sip == SipServers(["10.0.0.3"], SipServers.ENCODING_ADDRESS)
    assert opts.get(DhcpOptionCode.ASSOCIATED_IP) == [
        IPv4Address("192.0.2.20"),
        IPv4Address("192.0.2.21"),
    ]
    assert opts.get(DhcpOptionCode.NETINFO_ADDRESS) == IPv4Address("192.0.2.21")
    assert opts.get(DhcpOptionCode.NETINFO_TAG, decode=String) == "lab-a"
    assert (
        opts.get(DhcpOptionCode.DHCP_CAPTIVE_PORTAL, decode=String)
        == "https://portal.example/login"
    )
    assert opts.get(DhcpOptionCode.VI_VENDOR_CLASS) == ViVendorClass(
        [
            (32473, [b"docsis", b"eRouter"]),
            (65537, [b"usp", b"agent"]),
        ]
    )
    _assert_addresses(opts, DhcpOptionCode.CAPWAP_AC_V4, ["192.0.2.30", "192.0.2.31"])
    assert opts.get(DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS) == [
        "service.example",
        "config.example",
    ]
    _assert_addresses(
        opts, DhcpOptionCode.IPV4_ADDRESS_ANDSF, ["192.0.2.40", "192.0.2.41"]
    )
    assert opts.get(DhcpOptionCode.V4_SZTP_REDIRECT) == UriList(
        [
            "https://bootstrap.example/one",
            "https://bootstrap.example/two",
        ]
    )
    assert opts.get(DhcpOptionCode.V4_DOTS_RI) == "resolver-a.example"
    _assert_addresses(
        opts, DhcpOptionCode.V4_DOTS_ADDRESS, ["192.0.2.50", "192.0.2.51"]
    )
    _assert_addresses(
        opts, DhcpOptionCode.TFTP_SERVER_ADDRESS, ["192.0.2.60", "192.0.2.61"]
    )
    _assert_scalar(opts, DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME, U32, 1234)
    _assert_scalar(opts, DhcpOptionCode.IPV6_ONLY, U32, 4321)
    _assert_scalar(opts, DhcpOptionCode.BASE_TIME, U32, 111)
    _assert_scalar(opts, DhcpOptionCode.START_TIME_OF_STATE, U32, 222)
    _assert_scalar(opts, DhcpOptionCode.QUERY_START_TIME, U32, 333)
    _assert_scalar(opts, DhcpOptionCode.QUERY_END_TIME, U32, 444)
    _assert_scalar(opts, DhcpOptionCode.REBOOT_TIME, U32, 555)
    _assert_scalar(opts, DhcpOptionCode.DHCP_STATE, U8, 7)
    _assert_scalar(opts, DhcpOptionCode.DATA_SOURCE, U8, 3)
    assert opts.get(DhcpOptionCode.AUTO_CONFIG) == Boolean(1)
    assert (
        opts.get(DhcpOptionCode.MUD_URL_V4, decode=String)
        == "https://mud.example/policy"
    )
    assert (
        opts.get(DhcpOptionCode.CONFIGURATION_FILE, decode=String) == "/pxe/config.cfg"
    )
    assert opts.get(DhcpOptionCode.PATH_PREFIX, decode=String) == "/pxe/"
    assert opts.get(DhcpOptionCode.V4_ACCESS_DOMAIN) == "access.example"
    assert opts.get(DhcpOptionCode.IP_FORWARDING) == Boolean(1)
    assert opts.get(DhcpOptionCode.RAPID_COMMIT) == Flag()
    assert opts.get(DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL) == Boolean(0)
    assert opts.get(DhcpOptionCode.TRAILER_ENCAPSULATION) == Boolean(1)
    assert opts.get(DhcpOptionCode.FORCERENEW_NONCE_CAPABLE) == [U8(1)]

    opts[DhcpOptionCode.MERIT_DUMP_FILE] = "core.dump"
    assert opts.get(DhcpOptionCode.MERIT_DUMP_FILE, decode=String) == "core.dump"

    opts[DhcpOptionCode.POLICY_FILTER] = PolicyFilter(
        [
            ("192.0.2.1", "255.255.255.0"),
        ]
    )
    opts[DhcpOptionCode.STATIC_ROUTE] = StaticRoute(
        [
            ("192.0.2.0", "192.0.2.1"),
        ]
    )
    opts[DhcpOptionCode.USER_CLASS] = UserClass([b"alpha", b"\x00\xff"])
    opts[DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION] = VendorSpecificInformation(
        b"\x00\xff\x02vendor\x10"
    )
    opts[DhcpOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation([(9, b"\x02")])
    opts[DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION] = ViVendorSpecificInformation(
        [
            (32473, b"alpha"),
            ViVendorSpecificInformationRecord(65537, b"\x00\xff"),
        ]
    )
    opts[DhcpOptionCode.NAME_SERVICE_SEARCH] = [6, 44]  # DNS, then NetBIOS name server
    opts[DhcpOptionCode.SUBNET_SELECTION_OPTION] = "192.0.2.64"
    opts[DhcpOptionCode.RDNSS_SELECTION] = RdnssSelection(
        1, "192.0.2.1", "192.0.2.2", ["example.com"]
    )
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
    assert opts.get(DhcpOptionCode.USER_CLASS, decode=UserClass) == UserClass(
        [b"alpha", b"\x00\xff"]
    )
    assert isinstance(opts.get(DhcpOptionCode.USER_CLASS), Bytes)
    assert opts.get(
        DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION
    ) == VendorSpecificInformation(b"\x00\xff\x02vendor\x10")
    assert isinstance(opts.get(DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION), Bytes)
    assert opts.get(DhcpOptionCode.RELAY_AGENT_INFORMATION)[0].value == b"\x02"
    assert (
        opts.get(DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION)[0].enterprise_number
        == 32473
    )
    assert opts.get(DhcpOptionCode.NAME_SERVICE_SEARCH) == [6, 44]
    assert opts.get(DhcpOptionCode.SUBNET_SELECTION_OPTION) == IPv4Address("192.0.2.64")
    assert opts.get(DhcpOptionCode.RDNSS_SELECTION) == RdnssSelection(
        1, "192.0.2.1", "192.0.2.2", ["example.com"]
    )
    assert opts.get(DhcpOptionCode.V4_PCP_SERVER) == [["192.0.2.70", "192.0.2.71"]]
    assert opts.get(DhcpOptionCode.IPV4_ADDRESS_MOS) == MoSIpv4AddressList(
        [
            MoSIpv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
            (99, b"\x01\x02"),
        ]
    )
    assert opts.get(DhcpOptionCode.IPV4_FQDN_MOS) == MoSFqdnList(
        [
            MoSFqdnRecord(1, ["alpha.example", "beta.example"]),
            (99, b"\x03raw"),
        ]
    )


def test_registered_option_code_round_trips():
    opts = DhcpOptions()
    opts[DhcpOptionCode.SIP_SERVERS] = ["192.0.2.10", "192.0.2.11"]
    opts[DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST] = ["alpha.example", "beta.example"]
    opts[DhcpOptionCode.BCMCS_IPV4_ADDRESS] = ["192.0.2.14", "192.0.2.15"]
    opts[DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE] = [1, 2]
    opts[DhcpOptionCode.PCODE] = "Europe/Berlin"
    opts[DhcpOptionCode.TCODE] = "tz.example/ref"
    opts[DhcpOptionCode.RFC868_TIMESERVER] = ["192.0.2.12"]
    opts[DhcpOptionCode.SWAP_SERVER] = "192.0.2.13"
    opts[DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME] = 1234
    opts[DhcpOptionCode.ASSOCIATED_IP] = ["192.0.2.20", "192.0.2.21"]
    opts[DhcpOptionCode.IPV6_ONLY] = 4321
    opts[DhcpOptionCode.NETINFO_ADDRESS] = "192.0.2.21"
    opts[DhcpOptionCode.NETINFO_TAG] = "lab-a"
    opts[DhcpOptionCode.DHCP_CAPTIVE_PORTAL] = "https://portal.example/login"
    opts[DhcpOptionCode.AUTO_CONFIG] = True
    opts[DhcpOptionCode.VI_VENDOR_CLASS] = [
        ViVendorClassRecord(32473, [b"docsis", b"eRouter"]),
        (65537, [b"usp", b"agent"]),
    ]
    opts[DhcpOptionCode.CAPWAP_AC_V4] = ["192.0.2.30", "192.0.2.31"]
    opts[DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS] = [
        "service.example",
        "config.example",
    ]
    opts[DhcpOptionCode.IPV4_ADDRESS_ANDSF] = ["192.0.2.40", "192.0.2.41"]
    opts[DhcpOptionCode.V4_SZTP_REDIRECT] = [
        "https://bootstrap.example/one",
        "https://bootstrap.example/two",
    ]
    opts[DhcpOptionCode.V4_DOTS_RI] = "resolver-a.example"
    opts[DhcpOptionCode.V4_DOTS_ADDRESS] = ["192.0.2.50", "192.0.2.51"]
    opts[DhcpOptionCode.TFTP_SERVER_ADDRESS] = ["192.0.2.60", "192.0.2.61"]
    opts[DhcpOptionCode.BASE_TIME] = 111
    opts[DhcpOptionCode.START_TIME_OF_STATE] = 222
    opts[DhcpOptionCode.QUERY_START_TIME] = 333
    opts[DhcpOptionCode.QUERY_END_TIME] = 444
    opts[DhcpOptionCode.DHCP_STATE] = 7
    opts[DhcpOptionCode.DATA_SOURCE] = 3
    opts[DhcpOptionCode.V4_PCP_SERVER] = ["192.0.2.70", "192.0.2.71"]
    opts[DhcpOptionCode.MUD_URL_V4] = "https://mud.example/policy"
    opts[DhcpOptionCode.CONFIGURATION_FILE] = "/pxe/config.cfg"
    opts[DhcpOptionCode.PATH_PREFIX] = "/pxe/"
    opts[DhcpOptionCode.REBOOT_TIME] = 555
    opts[DhcpOptionCode.V4_ACCESS_DOMAIN] = "access.example"
    opts[DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL] = True
    opts[DhcpOptionCode.MERIT_DUMP_FILE] = "crash.dump"
    opts[DhcpOptionCode.STATUS_CODE] = 7
    opts[DhcpOptionCode.POLICY_FILTER] = PolicyFilter([("192.0.2.1", "255.255.255.0")])
    opts[DhcpOptionCode.STATIC_ROUTE] = StaticRoute([("192.0.2.0", "192.0.2.1")])
    opts[DhcpOptionCode.USER_CLASS] = UserClass([b"alpha", b"\x00\xff"])
    opts[DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION] = VendorSpecificInformation(
        b"\x00\xff\x02vendor\x10"
    )
    opts[DhcpOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation([(9, b"\x02")])
    opts[DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION] = ViVendorSpecificInformation(
        [
            (32473, b"alpha"),
            ViVendorSpecificInformationRecord(65537, b"\x00\xff"),
        ]
    )
    opts[DhcpOptionCode.NAME_SERVICE_SEARCH] = [6, 44]  # DNS, then NetBIOS name server
    opts[DhcpOptionCode.SUBNET_SELECTION_OPTION] = "192.0.2.64"
    opts[DhcpOptionCode.RDNSS_SELECTION] = RdnssSelection(
        1, "192.0.2.1", "192.0.2.2", ["example.com"]
    )
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

    assert decoded.get(DhcpOptionCode.SIP_SERVERS).values[0] == "192.0.2.10"
    assert decoded.get(DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST) == [
        "alpha.example",
        "beta.example",
    ]
    _assert_addresses(
        decoded, DhcpOptionCode.BCMCS_IPV4_ADDRESS, ["192.0.2.14", "192.0.2.15"]
    )
    assert decoded.get(DhcpOptionCode.CLIENT_SYSTEM_ARCHITECTURE) == [U16(1), U16(2)]
    assert decoded.get(DhcpOptionCode.PCODE, decode=String) == "Europe/Berlin"
    assert decoded.get(DhcpOptionCode.TCODE, decode=String) == "tz.example/ref"
    assert decoded.get(DhcpOptionCode.RFC868_TIMESERVER)[0] == IPv4Address("192.0.2.12")
    assert decoded.get(DhcpOptionCode.SWAP_SERVER) == IPv4Address("192.0.2.13")
    _assert_scalar(decoded, DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME, U32, 1234)
    assert decoded.get(DhcpOptionCode.ASSOCIATED_IP) == [
        IPv4Address("192.0.2.20"),
        IPv4Address("192.0.2.21"),
    ]
    _assert_scalar(decoded, DhcpOptionCode.IPV6_ONLY, U32, 4321)
    assert decoded.get(DhcpOptionCode.NETINFO_ADDRESS) == IPv4Address("192.0.2.21")
    assert decoded.get(DhcpOptionCode.NETINFO_TAG, decode=String) == "lab-a"
    assert (
        decoded.get(DhcpOptionCode.DHCP_CAPTIVE_PORTAL, decode=String)
        == "https://portal.example/login"
    )
    assert decoded.get(DhcpOptionCode.AUTO_CONFIG) == Boolean(1)
    assert decoded.get(DhcpOptionCode.VI_VENDOR_CLASS) == ViVendorClass(
        [
            (32473, [b"docsis", b"eRouter"]),
            (65537, [b"usp", b"agent"]),
        ]
    )
    _assert_addresses(
        decoded, DhcpOptionCode.CAPWAP_AC_V4, ["192.0.2.30", "192.0.2.31"]
    )
    assert decoded.get(DhcpOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS) == [
        "service.example",
        "config.example",
    ]
    _assert_addresses(
        decoded, DhcpOptionCode.IPV4_ADDRESS_ANDSF, ["192.0.2.40", "192.0.2.41"]
    )
    assert decoded.get(DhcpOptionCode.V4_SZTP_REDIRECT) == UriList(
        [
            "https://bootstrap.example/one",
            "https://bootstrap.example/two",
        ]
    )
    assert decoded.get(DhcpOptionCode.V4_DOTS_RI) == "resolver-a.example"
    _assert_addresses(
        decoded, DhcpOptionCode.V4_DOTS_ADDRESS, ["192.0.2.50", "192.0.2.51"]
    )
    _assert_addresses(
        decoded, DhcpOptionCode.TFTP_SERVER_ADDRESS, ["192.0.2.60", "192.0.2.61"]
    )
    _assert_scalar(decoded, DhcpOptionCode.BASE_TIME, U32, 111)
    _assert_scalar(decoded, DhcpOptionCode.START_TIME_OF_STATE, U32, 222)
    _assert_scalar(decoded, DhcpOptionCode.QUERY_START_TIME, U32, 333)
    _assert_scalar(decoded, DhcpOptionCode.QUERY_END_TIME, U32, 444)
    _assert_scalar(decoded, DhcpOptionCode.DHCP_STATE, U8, 7)
    _assert_scalar(decoded, DhcpOptionCode.DATA_SOURCE, U8, 3)
    assert decoded.get(DhcpOptionCode.V4_PCP_SERVER)[0] == ["192.0.2.70", "192.0.2.71"]
    assert (
        decoded.get(DhcpOptionCode.MUD_URL_V4, decode=String)
        == "https://mud.example/policy"
    )
    assert (
        decoded.get(DhcpOptionCode.CONFIGURATION_FILE, decode=String)
        == "/pxe/config.cfg"
    )
    assert decoded.get(DhcpOptionCode.PATH_PREFIX, decode=String) == "/pxe/"
    _assert_scalar(decoded, DhcpOptionCode.REBOOT_TIME, U32, 555)
    assert decoded.get(DhcpOptionCode.V4_ACCESS_DOMAIN) == "access.example"
    assert decoded.get(DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL) == Boolean(1)
    assert decoded.get(DhcpOptionCode.MERIT_DUMP_FILE, decode=String) == "crash.dump"
    assert decoded.get(DhcpOptionCode.STATUS_CODE).code == 7
    assert decoded.get(DhcpOptionCode.POLICY_FILTER)[0][0] == IPv4Address("192.0.2.1")
    assert decoded.get(DhcpOptionCode.STATIC_ROUTE)[0][1] == IPv4Address("192.0.2.1")
    assert decoded.get(DhcpOptionCode.USER_CLASS, decode=UserClass) == UserClass(
        [b"alpha", b"\x00\xff"]
    )
    assert isinstance(decoded.get(DhcpOptionCode.USER_CLASS), Bytes)
    assert decoded.get(
        DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION
    ) == VendorSpecificInformation(b"\x00\xff\x02vendor\x10")
    assert isinstance(decoded.get(DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION), Bytes)
    assert decoded.get(DhcpOptionCode.RELAY_AGENT_INFORMATION)[0].value == b"\x02"
    assert (
        decoded.get(DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION)[0].enterprise_number
        == 32473
    )
    assert decoded.get(DhcpOptionCode.NAME_SERVICE_SEARCH) == [6, 44]
    assert decoded.get(DhcpOptionCode.SUBNET_SELECTION_OPTION) == IPv4Address(
        "192.0.2.64"
    )
    assert decoded.get(DhcpOptionCode.RDNSS_SELECTION) == RdnssSelection(
        1, "192.0.2.1", "192.0.2.2", ["example.com"]
    )
    assert decoded.get(DhcpOptionCode.V4_PCP_SERVER) == [["192.0.2.70", "192.0.2.71"]]
    assert decoded.get(DhcpOptionCode.IPV4_ADDRESS_MOS) == MoSIpv4AddressList(
        [
            MoSIpv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
            (99, b"\x01\x02"),
        ]
    )
    assert decoded.get(DhcpOptionCode.IPV4_FQDN_MOS) == MoSFqdnList(
        [
            MoSFqdnRecord(1, ["alpha.example", "beta.example"]),
            (99, b"\x03raw"),
        ]
    )


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

    assert decoded.get(
        DhcpOptionCode.VENDOR_SPECIFIC_INFORMATION
    ) == VendorSpecificInformation(vendor_payload)
    assert decoded.get(
        DhcpOptionCode.VI_VENDOR_SPECIFIC_INFORMATION
    ) == ViVendorSpecificInformation(
        [
            (32473, b"alpha"),
            ViVendorSpecificInformationRecord(65537, b"\x00\xff"),
        ]
    )
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

    assert decoded.get(DhcpOptionCode.ASSOCIATED_IP) == [IPv4Address("192.0.2.25")]
    _assert_scalar(decoded, DhcpOptionCode.CLIENT_LAST_TRANSACTION_TIME, U32, 1234)
    _assert_scalar(decoded, DhcpOptionCode.DHCP_STATE, U8, 7)
    assert decoded.get(DhcpOptionCode.AUTO_CONFIG) == Boolean(1)
    assert decoded.get(DhcpOptionCode.BCMCS_DOMAIN_NAME_LIST) == ["alpha.example"]


def test_raw_wire_decoding_for_new_string_registrations():
    encoded = bytearray()
    portal = b"https://portal.example/login"
    pcode = b"Europe/Berlin"
    encoded.extend([DhcpOptionCode.DHCP_CAPTIVE_PORTAL, len(portal)])
    encoded.extend(portal)
    encoded.extend([DhcpOptionCode.PCODE, len(pcode)])
    encoded.extend(pcode)
    encoded.append(255)

    decoded = DhcpOptions()
    decoded.decode(memoryview(encoded))

    assert (
        decoded.get(DhcpOptionCode.DHCP_CAPTIVE_PORTAL, decode=String)
        == "https://portal.example/login"
    )
    assert decoded.get(DhcpOptionCode.PCODE, decode=String) == "Europe/Berlin"


def test_raw_wire_decoding_for_v4_sztp_redirect_registration():
    first = b"https://bootstrap.example/one"
    second = b"https://bootstrap.example/two"
    payload = (
        len(first).to_bytes(2, "big") + first + len(second).to_bytes(2, "big") + second
    )
    encoded = bytearray()
    encoded.extend([DhcpOptionCode.V4_SZTP_REDIRECT, len(payload)])
    encoded.extend(payload)
    encoded.append(255)

    decoded = DhcpOptions()
    decoded.decode(memoryview(encoded))

    assert decoded.get(DhcpOptionCode.V4_SZTP_REDIRECT) == UriList(
        [
            "https://bootstrap.example/one",
            "https://bootstrap.example/two",
        ]
    )


def test_raw_wire_decoding_for_vi_vendor_class_registration():
    first = b"\x06docsis\x07eRouter"
    second = b"\x03usp\x05agent"
    payload = (
        (32473).to_bytes(4, "big")
        + bytes([len(first)])
        + first
        + (65537).to_bytes(4, "big")
        + bytes([len(second)])
        + second
    )
    encoded = bytearray()
    encoded.extend([DhcpOptionCode.VI_VENDOR_CLASS, len(payload)])
    encoded.extend(payload)
    encoded.append(255)

    decoded = DhcpOptions()
    decoded.decode(memoryview(encoded))

    assert decoded.get(DhcpOptionCode.VI_VENDOR_CLASS) == ViVendorClass(
        [
            (32473, [b"docsis", b"eRouter"]),
            (65537, [b"usp", b"agent"]),
        ]
    )


def test_ccc_option_code_registration_and_round_trip():
    assert DhcpOptionCode.CCC.get_type() is CccOption

    value = CccOption(
        [
            CccPrimaryDhcpServerAddressSubOption(1, "192.0.2.1"),
            CccSecondaryDhcpServerAddressSubOption(2, "192.0.2.2"),
            CccProvisioningServerAddressSubOption(3, ("fqdn", "tsp.example")),
            CccAsReqAsRepBackoffRetrySubOption(4, (1, 2, 3)),
            CccApReqApRepBackoffRetrySubOption(5, (4, 5, 6)),
            CccKerberosRealmNameSubOption(6, "EXAMPLE.COM"),
            CccTicketGrantingServerUtilizationSubOption(7, True),
            CccProvisioningTimerSubOption(8, 9),
            CccSecurityTicketControlSubOption(9, 3),
            CccKdcServerAddressSubOption(10, ["192.0.2.10", "192.0.2.11"]),
            (99, b"\x01\x02\x03"),
        ]
    )

    opts = DhcpOptions()
    opts[DhcpOptionCode.CCC] = value
    encoded = opts.encode()

    decoded = DhcpOptions()
    decoded.decode(memoryview(encoded))

    assert decoded.get(DhcpOptionCode.CCC) == value
    assert decoded.get(DhcpOptionCode.CCC)[-1].code == 99
    assert decoded.get(DhcpOptionCode.CCC)[-1].value == b"\x01\x02\x03"


def test_register_type_rejects_invalid_type():
    with pytest.raises(TypeError):
        DhcpOptionCode.LOG_SERVER.register_type(int)  # type: ignore[arg-type]


def test_copy_shares_no_mutable_state_with_the_original():
    original = DhcpOptions()
    original[DhcpOptionCode.ROUTER] = [IPv4Address("192.0.2.1")]
    original[DhcpOptionCode.DNS] = [IPv4Address("192.0.2.53")]

    copied = original.copy()
    assert copied is not original
    assert copied._codemap is original._codemap
    assert dict(copied.items(decoded=False)) == dict(original.items(decoded=False))

    # Structural edits on the copy leave the original alone ...
    del copied[DhcpOptionCode.DNS]
    copied[DhcpOptionCode.SUBNET_MASK] = IPv4Address("255.255.255.0")
    assert DhcpOptionCode.DNS in original
    assert DhcpOptionCode.SUBNET_MASK not in original

    # ... and so do in-place edits of a payload handed out by get(decode=False),
    # which a shallow dict copy would still share.
    copied.get(DhcpOptionCode.ROUTER, decode=False).extend(b"\x00\x00\x00\x00")
    assert len(original[DhcpOptionCode.ROUTER]) == 4


# --- Encoder wire vectors (RFC 3396 framing, zero-length options, size budget) ---
#
# These paths had no coverage at all, which is why three encoder defects survived:
# every existing test checked the library against its own encoder rather than
# against expected bytes.


def test_zero_length_option_keeps_its_length_byte():
    """RFC 4039 RAPID_COMMIT is legally zero-length.

    Omitting the length octet makes the receiver read the *next* option's code as
    this option's length, swallowing everything after it.
    """
    options = DhcpOptions()
    options[DhcpOptionCode.RAPID_COMMIT] = bytearray()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER]
    )

    assert bytes(options.encode()) == b"\x50\x00\x35\x01\x01\xff"

    roundtrip = DhcpOptions()
    roundtrip.decode(options.encode())
    assert dict(roundtrip.items(decoded=False)) == {
        DhcpOptionCode.RAPID_COMMIT: bytearray(),
        DhcpOptionCode.DHCP_MESSAGE_TYPE: bytearray([DhcpMessageType.DHCPDISCOVER]),
    }


@pytest.mark.parametrize("size", [0, 1, 254, 255, 256, 300, 510, 511, 600])
def test_long_options_repeat_the_code_byte_on_every_fragment(size):
    """RFC 3396 s4: a long option is split into multiple instances of the same code,
    each carrying its own length octet."""
    payload = bytes(range(256)) * ((size // 256) + 1)
    payload = payload[:size]
    options = DhcpOptions()
    options[224] = bytearray(payload)

    wire = bytes(options.encode())

    # Walk the encoded bytes and assert every fragment is a full code/len/data frame.
    fragments = []
    index = 0
    while index < len(wire) and wire[index] != 0xFF:
        code, length = wire[index], wire[index + 1]
        fragments.append((code, length))
        index += 2 + length
    assert fragments, "expected at least one fragment"
    assert all(code == 224 for code, _ in fragments)
    assert sum(length for _, length in fragments) == size

    roundtrip = DhcpOptions()
    roundtrip.decode(bytearray(wire))
    assert bytes(roundtrip.get(224, decode=False)) == payload


@pytest.mark.parametrize(
    "maxsize,count,datalen",
    [(10, 1, 20), (20, 3, 5), (64, 8, 6), (312, 20, 14), (576, 40, 12)],
)
def test_partial_encode_never_exceeds_maxsize(maxsize, count, datalen):
    """The length octet must be charged against the budget like the code octet is,
    or an overloaded reply overruns the client's advertised maximum message size."""
    options = DhcpOptions()
    for index in range(count):
        options[200 + index] = bytearray(b"D" * datalen)

    encoded, leftover = options.partial_encode(maxsize)

    assert len(encoded) <= maxsize
    encoded_codes = {code for code, _ in _walk(encoded)}
    leftover_codes = (
        {int(code) for code, _ in leftover.items(decoded=False)} if leftover else set()
    )
    # Nothing is silently lost: every option is either encoded or handed back.
    assert encoded_codes | leftover_codes == {200 + index for index in range(count)}


def test_zero_length_option_that_does_not_fit_is_carried_to_the_leftover():
    options = DhcpOptions()
    options[224] = bytearray(b"X" * 8)
    options[DhcpOptionCode.RAPID_COMMIT] = bytearray()

    encoded, leftover = options.partial_encode(12)

    assert len(encoded) <= 12
    assert leftover is not None
    assert DhcpOptionCode.RAPID_COMMIT in leftover


def _walk(wire):
    """Yield (code, payload) frames from an encoded options field."""
    index = 0
    wire = bytes(wire)
    while index < len(wire) and wire[index] != 0xFF:
        code, length = wire[index], wire[index + 1]
        yield code, wire[index + 2 : index + 2 + length]
        index += 2 + length


def test_unregistered_codes_fall_back_to_opaque_bytes():
    """options/AGENTS.md documents a Bytes fallback for codes with no member.

    Only 163 of 0-255 are members, and RFC 3942 reserves 224-254 for
    site-specific use. Raising instead means a client sending any of them gets
    no service, because the receive path resolves every code before the packet
    reaches a handler.
    """
    for value in (199, 224, 250, 253):
        code = DhcpOptionCode(value)
        assert int(code) == value
        assert code.label() == "UNKNOWN"
        assert code.get_type() is Bytes
        assert repr(code) == f"[{value}]UNKNOWN"
        # Pseudo-members are cached, so a code compares and hashes consistently.
        assert DhcpOptionCode(value) is code

    options = DhcpOptions()
    options.decode(bytearray(b"\x35\x01\x01\xe0\x03\x01\x02\x03\xff"))
    assert bytes(options.get(224)) == b"\x01\x02\x03"
    assert dict(options.items(decoded=False))[224] == bytearray(b"\x01\x02\x03")
    assert options == options

    # Out of range is still an error: these are option *codes*, one octet each.
    with pytest.raises(ValueError):
        DhcpOptionCode(256)
    with pytest.raises(ValueError):
        DhcpOptionCode(-1)


def test_a_failing_set_leaves_the_previous_value_intact():
    """__setitem__ built the payload in place, so a codec that raised part-way
    left the option *emptied* rather than unchanged.

    A zero-length option is legal on the wire -- RFC 4039's RAPID_COMMIT is one
    -- so the wreckage encodes and sends cleanly: the failed set silently
    becomes a valid option meaning something else. Here the victim would be
    SERVER_IDENTIFIER, and a client that reads an empty one has no server to
    renew against.
    """
    options = DhcpOptions()
    options[DhcpOptionCode.SERVER_IDENTIFIER] = bytearray(b"\x0a\x00\x00\x01")

    with pytest.raises(Exception):
        options[DhcpOptionCode.SERVER_IDENTIFIER] = "not-an-ip-address"

    assert bytes(options[int(DhcpOptionCode.SERVER_IDENTIFIER)]) == b"\x0a\x00\x00\x01"
    assert bytes(options.encode()) == b"\x36\x04\x0a\x00\x00\x01\xff"

    # And a failing set on a key that was not there must not create it, empty.
    fresh = DhcpOptions()
    with pytest.raises(Exception):
        fresh[DhcpOptionCode.SERVER_IDENTIFIER] = "not-an-ip-address"
    assert int(DhcpOptionCode.SERVER_IDENTIFIER) not in fresh


def test_setting_a_bytearray_copies_it_instead_of_aliasing_the_caller():
    """A bytearray argument used to be stored by reference.

    Every other accepted type was already copied, which is what made the
    exception invisible: it only bites when a caller happens to reuse or mutate
    the buffer afterwards. `DhcpOptions.copy()` exists because this same
    aliasing bit the server's lease path.
    """
    options = DhcpOptions()
    buffer = bytearray(b"\x0a\x00\x00\x01")
    options[DhcpOptionCode.ROUTER] = buffer

    buffer[0] = 0xFF
    buffer.extend(b"\xde\xad")

    assert bytes(options[int(DhcpOptionCode.ROUTER)]) == b"\x0a\x00\x00\x01"
    assert options[int(DhcpOptionCode.ROUTER)] is not buffer

    # The reverse direction too: the stored payload must not be the object a
    # later caller mutates through.
    stored = options.get(DhcpOptionCode.ROUTER, decode=False)
    assert stored is not buffer


def test_reassigning_an_option_keeps_its_position():
    """The options order is wire-visible -- `encode` puts DHCP_MESSAGE_TYPE
    first -- so swapping the payload in must not move the key to the end."""
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPACK.value]
    )
    options[DhcpOptionCode.ROUTER] = bytearray(b"\x0a\x00\x00\xfe")

    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPOFFER.value]
    )

    assert [code for code, _ in _walk(options.encode())] == [
        int(DhcpOptionCode.DHCP_MESSAGE_TYPE),
        int(DhcpOptionCode.ROUTER),
    ]


def test_get_decodes_and_getitem_does_not():
    """Pins the container's one deliberate asymmetry, in both directions.

    `DhcpOptions` declares `MutableMapping[int, bytearray]`, and `get()` does
    not honour it: it decodes. That is the documented API -- `get(..., decode=)`
    is the surface every caller uses -- so this test exists to stop the
    asymmetry being "fixed" into conformance, which would silently change what
    every `options.get(code)` in the wild returns.

    Everything the ABC supplies routes through `__getitem__`, so it all yields
    raw bytes; only `get()` and `items()` decode.
    """
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPACK

    code = int(DhcpOptionCode.DHCP_MESSAGE_TYPE)
    raw = bytearray([DhcpMessageType.DHCPACK.value])

    # `get()` decodes, `[]` does not.
    assert options.get(code) == DhcpMessageType.DHCPACK
    assert options[code] == raw
    assert not isinstance(options[code], DhcpMessageType)

    # ...and every inherited MutableMapping accessor follows `[]`, not `get()`.
    assert dict(options)[code] == raw
    assert list(options.values()) == [raw]
    assert options.setdefault(code, bytearray()) == raw

    # `decode=False` is how you ask `get()` for what `[]` gives you.
    assert options.get(code, decode=False) == raw

    # `items()` is the other deviation: decoded is a freshly built list of
    # `DhcpOption` pairs, raw is the mapping's own live view.
    decoded_items = options.items()
    assert isinstance(decoded_items, list)
    assert [value for _code, value in decoded_items] == [DhcpMessageType.DHCPACK]
    assert not isinstance(options.items(decoded=False), list)
    assert dict(options.items(decoded=False)) == {code: raw}
