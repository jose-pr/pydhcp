import pytest
from pydhcp.packet import DHCPMessageType
from pydhcp.options import DHCPOptions
from pydhcp.options import DHCPOptionCode
from pydhcp.options import (
    IPv4AddressOption,
    SIPServers,
    ClientFQDN,
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
    VIVendorSpecificInformationRecord,
    VIVendorSpecificInformation,
    VIVendorClassRecord,
    VIVendorClass,
    RDNSSSelection,
    MoSIPv4AddressList,
    MoSFQDNList,
    MoSIPv4AddressRecord,
    MoSFQDNRecord,
    URIList,
    CCCOption,
    CCCPrimaryDHCPServerAddressSubOption,
    CCCSecondaryDHCPServerAddressSubOption,
    CCCProvisioningServerAddressSubOption,
    CCCASBackoffRetrySubOption,
    CCCAPBackoffRetrySubOption,
    CCCKerberosRealmNameSubOption,
    CCCTicketGrantingServerUtilizationSubOption,
    CCCProvisioningTimerSubOption,
    CCCSecurityTicketControlSubOption,
    CCCKDCServerAddressSubOption,
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

    `isinstance(value[0], IPv4AddressOption)` was the whole assertion before: the
    list's length, every entry after the first, and every address in it went
    unchecked, so a codec that stopped after one entry -- or produced the right
    count of wrong addresses -- passed. The per-element type check is kept as
    well because `IPv4AddressOption` compares equal to a plain
    `ipaddress.IPv4Address`, so values alone would not pin the type.
    """
    value = opts.get(code)
    assert [type(item) for item in value] == [IPv4AddressOption] * len(
        expected
    ), f"{code!r}: {[type(item).__name__ for item in value]}"
    assert list(value) == [
        IPv4AddressOption(a) for a in expected
    ], f"{code!r}: {value!r}"
    return value


def test_options_set_get():
    opts = DHCPOptions()

    # Test setting enum / DHCPOptionType
    opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    assert opts.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == DHCPMessageType.DHCPDISCOVER

    # Test setting raw bytes
    opts[DHCPOptionCode.ROUTER] = b"\xc0\xa8\x01\x01"  # 192.168.1.1
    # Test decoding with type
    from ipaddress import IPv4Address as IPv4

    assert opts.get(DHCPOptionCode.ROUTER, decode=IPv4AddressOption) == IPv4(
        "192.168.1.1"
    )

    # Test missing / default
    assert opts.get(999, default="hello") == "hello"


def test_options_encode_round_trip():
    # Renamed: this calls `encode()`, so it never exercised `partial_encode`'s
    # size limit or its leftover bag -- the two things that name refers to.
    # The real one is `test_options_partial_encode_splits_and_returns_leftovers`.
    opts = DHCPOptions()
    opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    opts[DHCPOptionCode.HOSTNAME] = "test-host"

    encoded = opts.encode()
    assert len(encoded) > 0
    assert encoded[-1] == 255  # END mark

    # Decode back
    decoded_opts = DHCPOptions.decode(memoryview(encoded))
    assert (
        decoded_opts.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
        == DHCPMessageType.DHCPDISCOVER
    )
    assert decoded_opts.get(DHCPOptionCode.HOSTNAME, decode=String) == "test-host"


def test_options_partial_encode_splits_and_returns_leftovers():
    """`partial_encode(maxsize)` fills the budget and hands back the remainder.

    This is what the old `test_options_partial_encode` was named for and never
    touched: it called `encode()`, which is `partial_encode(None)` -- no limit,
    so no split and always a `None` leftover. The split is what a reply near
    the client's maximum message size depends on, and it was untested.
    """
    opts = DHCPOptions()
    opts[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPDISCOVER
    opts[DHCPOptionCode.HOSTNAME] = "test-host"

    encoded, leftover = opts.partial_encode(8)

    # Exactly the budget, END included, and never a byte over it.
    assert len(encoded) == 8
    assert encoded[-1] == 255
    # 53/01/01 whole, then as much of the hostname as fits: 0c/02/"te".
    assert bytes(encoded) == b"\x35\x01\x01\x0c\x02te\xff"

    assert leftover is not None
    assert leftover.get(DHCPOptionCode.HOSTNAME, decode=False) == bytearray(b"st-host")
    assert DHCPOptionCode.DHCP_MESSAGE_TYPE not in leftover

    # The fragment that did fit is a complete, decodable option in its own
    # right -- RFC 3396 s4 requires each instance to carry its own code and
    # length octet -- rather than a dangling continuation.
    decoded = DHCPOptions.decode(memoryview(encoded))
    assert decoded.get(DHCPOptionCode.DHCP_MESSAGE_TYPE) == DHCPMessageType.DHCPDISCOVER
    assert decoded.get(DHCPOptionCode.HOSTNAME, decode=String) == "te"

    # No limit means no split: the contrast is the point.
    whole, nothing_left = opts.partial_encode(None)
    assert nothing_left is None
    assert bytes(whole) == b"\x35\x01\x01\x0c\ttest-host\xff"


def test_typed_registrations_and_aliases():
    assert DHCPOptionCode.TCP_KEEPALIVE_GARBAGE.name == "TCP_KEEPALIVE_GARBAGE"
    assert DHCPOptionCode.NNTP_SERVER.name == "NNTP_SERVER"
    assert DHCPOptionCode.RFC868_TIMESERVER.get_type()._args_[0] is IPv4AddressOption
    assert DHCPOptionCode.SWAP_SERVER.get_type() is IPv4AddressOption
    assert DHCPOptionCode.NETBIOS_SCOPE.get_type() is String
    assert DHCPOptionCode.LOG_SERVER.get_type()._args_[0] is IPv4AddressOption
    # RFC 3361 s3.1: an encoding octet selects names (0) or addresses (1),
    # so this is not a bare address list.
    assert DHCPOptionCode.SIP_SERVERS.get_type() is SIPServers
    # RFC 4280 s4.6: "DNS name compression MUST NOT be used" -- so option 88 is
    # NOT the compressed `DomainList` that RFC 3397's option 119 is. Details and
    # the measured payloads: tests/test_options_domain_lists.py.
    assert (
        DHCPOptionCode.BCMCS_DOMAIN_NAME_LIST.get_type().__name__
        == "UncompressedDomainList"
    )
    assert DHCPOptionCode.BCMCS_IPV4_ADDRESS.get_type()._args_[0] is IPv4AddressOption
    assert DHCPOptionCode.CLIENT_LAST_TRANSACTION_TIME.get_type().__name__ == "U32"
    assert DHCPOptionCode.ASSOCIATED_IP.get_type()._args_[0] is IPv4AddressOption
    assert (
        DHCPOptionCode.CLIENT_SYSTEM_ARCHITECTURE.get_type()._args_[0].__name__ == "U16"
    )
    assert DHCPOptionCode.PCODE.get_type() is String
    assert DHCPOptionCode.TCODE.get_type() is String
    assert DHCPOptionCode.IPV6_ONLY.get_type().__name__ == "U32"
    assert DHCPOptionCode.NETINFO_ADDRESS.get_type() is IPv4AddressOption
    assert DHCPOptionCode.NETINFO_TAG.get_type() is String
    assert DHCPOptionCode.DHCP_CAPTIVE_PORTAL.get_type() is String
    assert DHCPOptionCode.AUTO_CONFIG.get_type() is Boolean
    assert DHCPOptionCode.VI_VENDOR_CLASS.get_type() is VIVendorClass
    assert DHCPOptionCode.CAPWAP_AC_V4.get_type()._args_[0] is IPv4AddressOption
    assert (
        DHCPOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS.get_type().__name__ == "DomainList"
    )
    assert DHCPOptionCode.IPV4_ADDRESS_ANDSF.get_type()._args_[0] is IPv4AddressOption
    assert DHCPOptionCode.V4_SZTP_REDIRECT.get_type() is URIList
    assert DHCPOptionCode.V4_DOTS_RI.get_type().__name__ == "DomainName"
    assert DHCPOptionCode.V4_DOTS_ADDRESS.get_type()._args_[0] is IPv4AddressOption
    assert DHCPOptionCode.TFTP_SERVER_ADDRESS.get_type()._args_[0] is IPv4AddressOption
    assert DHCPOptionCode.BASE_TIME.get_type().__name__ == "U32"
    assert DHCPOptionCode.START_TIME_OF_STATE.get_type().__name__ == "U32"
    assert DHCPOptionCode.QUERY_START_TIME.get_type().__name__ == "U32"
    assert DHCPOptionCode.QUERY_END_TIME.get_type().__name__ == "U32"
    assert DHCPOptionCode.DHCP_STATE.get_type().__name__ == "U8"
    assert DHCPOptionCode.DATA_SOURCE.get_type().__name__ == "U8"
    assert DHCPOptionCode.V4_PCP_SERVER.get_type().__name__ == "PCPServerList"
    assert DHCPOptionCode.MUD_URL_V4.get_type() is String
    assert DHCPOptionCode.CONFIGURATION_FILE.get_type() is String
    assert DHCPOptionCode.PATH_PREFIX.get_type() is String
    assert DHCPOptionCode.REBOOT_TIME.get_type().__name__ == "U32"
    assert DHCPOptionCode.V4_ACCESS_DOMAIN.get_type().__name__ == "DomainName"
    # RFC 4039 s4: "Code 80, Len 0" -- presence-only, not a one-octet boolean.
    assert DHCPOptionCode.RAPID_COMMIT.get_type() is Flag
    assert DHCPOptionCode.ALL_SUBNETS_ARE_LOCAL.get_type() is Boolean
    assert DHCPOptionCode.TRAILER_ENCAPSULATION.get_type() is Boolean
    assert DHCPOptionCode.FORCERENEW_NONCE_CAPABLE.get_type()._args_[0] is U8
    assert DHCPOptionCode.MERIT_DUMP_FILE.get_type() is String
    assert DHCPOptionCode.ARP_TIMEOUT.get_type().__name__ == "U32"
    assert DHCPOptionCode.STATUS_CODE.get_type().__name__ == "StatusCode"
    assert DHCPOptionCode.POLICY_FILTER.get_type() is PolicyFilter
    assert DHCPOptionCode.STATIC_ROUTE.get_type() is StaticRoute
    # Opaque by default like option 43: iPXE sends option 77 unframed, and a
    # strict RFC 3004 codec rejects those packets. UserClass stays opt-in.
    assert DHCPOptionCode.USER_CLASS.get_type() is Bytes
    assert (
        DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION.get_type()
        is VendorSpecificInformation
    )
    assert DHCPOptionCode.RELAY_AGENT_INFORMATION.get_type() is RelayAgentInformation
    assert (
        DHCPOptionCode.VI_VENDOR_SPECIFIC_INFORMATION.get_type()
        is VIVendorSpecificInformation
    )
    # RFC 2937 s3: 16-bit name service option codes, not domain names.
    assert DHCPOptionCode.NAME_SERVICE_SEARCH.get_type()._args_[0].__name__ == "U16"
    assert DHCPOptionCode.SUBNET_SELECTION_OPTION.get_type() is IPv4AddressOption
    assert DHCPOptionCode.RDNSS_SELECTION.get_type() is RDNSSSelection
    assert DHCPOptionCode.IPV4_ADDRESS_MOS.get_type() is MoSIPv4AddressList
    assert DHCPOptionCode.IPV4_FQDN_MOS.get_type() is MoSFQDNList

    opts = DHCPOptions()
    opts[DHCPOptionCode.LOG_SERVER] = ["10.0.0.1", "10.0.0.2"]
    opts[DHCPOptionCode.BCMCS_DOMAIN_NAME_LIST] = ["alpha.example", "beta.example"]
    opts[DHCPOptionCode.BCMCS_IPV4_ADDRESS] = ["10.0.0.7", "10.0.0.8"]
    opts[DHCPOptionCode.CLIENT_SYSTEM_ARCHITECTURE] = [1, 2]
    opts[DHCPOptionCode.PCODE] = "Europe/Berlin"
    opts[DHCPOptionCode.TCODE] = "tz.example/ref"
    opts[DHCPOptionCode.RFC868_TIMESERVER] = ["10.0.0.4"]
    opts[DHCPOptionCode.IEN116_NAMESERVER] = ["10.0.0.5"]
    opts[DHCPOptionCode.SWAP_SERVER] = "10.0.0.6"
    opts[DHCPOptionCode.SIP_SERVERS] = ["10.0.0.3"]  # inferred as encoding 1
    opts[DHCPOptionCode.ASSOCIATED_IP] = ["192.0.2.20", "192.0.2.21"]
    opts[DHCPOptionCode.NETINFO_ADDRESS] = "192.0.2.21"
    opts[DHCPOptionCode.NETINFO_TAG] = "lab-a"
    opts[DHCPOptionCode.DHCP_CAPTIVE_PORTAL] = "https://portal.example/login"
    opts[DHCPOptionCode.VI_VENDOR_CLASS] = [
        VIVendorClassRecord(32473, [b"docsis", b"eRouter"]),
        (65537, [b"usp", b"agent"]),
    ]
    opts[DHCPOptionCode.CAPWAP_AC_V4] = ["192.0.2.30", "192.0.2.31"]
    opts[DHCPOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS] = [
        "service.example",
        "config.example",
    ]
    opts[DHCPOptionCode.IPV4_ADDRESS_ANDSF] = ["192.0.2.40", "192.0.2.41"]
    opts[DHCPOptionCode.V4_SZTP_REDIRECT] = [
        "https://bootstrap.example/one",
        "https://bootstrap.example/two",
    ]
    opts[DHCPOptionCode.V4_DOTS_RI] = "resolver-a.example"
    opts[DHCPOptionCode.V4_DOTS_ADDRESS] = ["192.0.2.50", "192.0.2.51"]
    opts[DHCPOptionCode.TFTP_SERVER_ADDRESS] = ["192.0.2.60", "192.0.2.61"]
    opts[DHCPOptionCode.V4_PCP_SERVER] = ["192.0.2.70", "192.0.2.71"]
    opts[DHCPOptionCode.MUD_URL_V4] = "https://mud.example/policy"
    opts[DHCPOptionCode.CONFIGURATION_FILE] = "/pxe/config.cfg"
    opts[DHCPOptionCode.PATH_PREFIX] = "/pxe/"
    opts[DHCPOptionCode.CLIENT_LAST_TRANSACTION_TIME] = 1234
    opts[DHCPOptionCode.IPV6_ONLY] = 4321
    opts[DHCPOptionCode.BASE_TIME] = 111
    opts[DHCPOptionCode.START_TIME_OF_STATE] = 222
    opts[DHCPOptionCode.QUERY_START_TIME] = 333
    opts[DHCPOptionCode.QUERY_END_TIME] = 444
    opts[DHCPOptionCode.REBOOT_TIME] = 555
    opts[DHCPOptionCode.DHCP_STATE] = 7
    opts[DHCPOptionCode.DATA_SOURCE] = 3
    opts[DHCPOptionCode.AUTO_CONFIG] = True
    opts[DHCPOptionCode.V4_ACCESS_DOMAIN] = "access.example"
    opts[DHCPOptionCode.IP_FORWARDING] = 1
    opts[DHCPOptionCode.RAPID_COMMIT] = True
    opts[DHCPOptionCode.ALL_SUBNETS_ARE_LOCAL] = False
    opts[DHCPOptionCode.TRAILER_ENCAPSULATION] = 1
    opts[DHCPOptionCode.FORCERENEW_NONCE_CAPABLE] = [1]
    _assert_addresses(opts, DHCPOptionCode.LOG_SERVER, ["10.0.0.1", "10.0.0.2"])
    assert opts.get(DHCPOptionCode.BCMCS_DOMAIN_NAME_LIST) == [
        "alpha.example",
        "beta.example",
    ]
    _assert_addresses(opts, DHCPOptionCode.BCMCS_IPV4_ADDRESS, ["10.0.0.7", "10.0.0.8"])
    assert opts.get(DHCPOptionCode.CLIENT_SYSTEM_ARCHITECTURE) == [U16(1), U16(2)]
    assert opts.get(DHCPOptionCode.PCODE, decode=String) == "Europe/Berlin"
    assert opts.get(DHCPOptionCode.TCODE, decode=String) == "tz.example/ref"
    _assert_addresses(opts, DHCPOptionCode.RFC868_TIMESERVER, ["10.0.0.4"])
    _assert_addresses(opts, DHCPOptionCode.IEN116_NAMESERVER, ["10.0.0.5"])
    assert opts.get(DHCPOptionCode.SWAP_SERVER) == IPv4AddressOption("10.0.0.6")
    sip = opts.get(DHCPOptionCode.SIP_SERVERS)
    assert sip == SIPServers(["10.0.0.3"], SIPServers.ENCODING_ADDRESS)
    assert opts.get(DHCPOptionCode.ASSOCIATED_IP) == [
        IPv4AddressOption("192.0.2.20"),
        IPv4AddressOption("192.0.2.21"),
    ]
    assert opts.get(DHCPOptionCode.NETINFO_ADDRESS) == IPv4AddressOption("192.0.2.21")
    assert opts.get(DHCPOptionCode.NETINFO_TAG, decode=String) == "lab-a"
    assert (
        opts.get(DHCPOptionCode.DHCP_CAPTIVE_PORTAL, decode=String)
        == "https://portal.example/login"
    )
    assert opts.get(DHCPOptionCode.VI_VENDOR_CLASS) == VIVendorClass(
        [
            (32473, [b"docsis", b"eRouter"]),
            (65537, [b"usp", b"agent"]),
        ]
    )
    _assert_addresses(opts, DHCPOptionCode.CAPWAP_AC_V4, ["192.0.2.30", "192.0.2.31"])
    assert opts.get(DHCPOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS) == [
        "service.example",
        "config.example",
    ]
    _assert_addresses(
        opts, DHCPOptionCode.IPV4_ADDRESS_ANDSF, ["192.0.2.40", "192.0.2.41"]
    )
    assert opts.get(DHCPOptionCode.V4_SZTP_REDIRECT) == URIList(
        [
            "https://bootstrap.example/one",
            "https://bootstrap.example/two",
        ]
    )
    assert opts.get(DHCPOptionCode.V4_DOTS_RI) == "resolver-a.example"
    _assert_addresses(
        opts, DHCPOptionCode.V4_DOTS_ADDRESS, ["192.0.2.50", "192.0.2.51"]
    )
    _assert_addresses(
        opts, DHCPOptionCode.TFTP_SERVER_ADDRESS, ["192.0.2.60", "192.0.2.61"]
    )
    _assert_scalar(opts, DHCPOptionCode.CLIENT_LAST_TRANSACTION_TIME, U32, 1234)
    _assert_scalar(opts, DHCPOptionCode.IPV6_ONLY, U32, 4321)
    _assert_scalar(opts, DHCPOptionCode.BASE_TIME, U32, 111)
    _assert_scalar(opts, DHCPOptionCode.START_TIME_OF_STATE, U32, 222)
    _assert_scalar(opts, DHCPOptionCode.QUERY_START_TIME, U32, 333)
    _assert_scalar(opts, DHCPOptionCode.QUERY_END_TIME, U32, 444)
    _assert_scalar(opts, DHCPOptionCode.REBOOT_TIME, U32, 555)
    _assert_scalar(opts, DHCPOptionCode.DHCP_STATE, U8, 7)
    _assert_scalar(opts, DHCPOptionCode.DATA_SOURCE, U8, 3)
    assert opts.get(DHCPOptionCode.AUTO_CONFIG) == Boolean(1)
    assert (
        opts.get(DHCPOptionCode.MUD_URL_V4, decode=String)
        == "https://mud.example/policy"
    )
    assert (
        opts.get(DHCPOptionCode.CONFIGURATION_FILE, decode=String) == "/pxe/config.cfg"
    )
    assert opts.get(DHCPOptionCode.PATH_PREFIX, decode=String) == "/pxe/"
    assert opts.get(DHCPOptionCode.V4_ACCESS_DOMAIN) == "access.example"
    assert opts.get(DHCPOptionCode.IP_FORWARDING) == Boolean(1)
    assert opts.get(DHCPOptionCode.RAPID_COMMIT) == Flag()
    assert opts.get(DHCPOptionCode.ALL_SUBNETS_ARE_LOCAL) == Boolean(0)
    assert opts.get(DHCPOptionCode.TRAILER_ENCAPSULATION) == Boolean(1)
    assert opts.get(DHCPOptionCode.FORCERENEW_NONCE_CAPABLE) == [U8(1)]

    opts[DHCPOptionCode.MERIT_DUMP_FILE] = "core.dump"
    assert opts.get(DHCPOptionCode.MERIT_DUMP_FILE, decode=String) == "core.dump"

    opts[DHCPOptionCode.POLICY_FILTER] = PolicyFilter(
        [
            ("192.0.2.1", "255.255.255.0"),
        ]
    )
    opts[DHCPOptionCode.STATIC_ROUTE] = StaticRoute(
        [
            ("192.0.2.0", "192.0.2.1"),
        ]
    )
    opts[DHCPOptionCode.USER_CLASS] = UserClass([b"alpha", b"\x00\xff"])
    opts[DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION] = VendorSpecificInformation(
        b"\x00\xff\x02vendor\x10"
    )
    opts[DHCPOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation([(9, b"\x02")])
    opts[DHCPOptionCode.VI_VENDOR_SPECIFIC_INFORMATION] = VIVendorSpecificInformation(
        [
            (32473, b"alpha"),
            VIVendorSpecificInformationRecord(65537, b"\x00\xff"),
        ]
    )
    opts[DHCPOptionCode.NAME_SERVICE_SEARCH] = [6, 44]  # DNS, then NetBIOS name server
    opts[DHCPOptionCode.SUBNET_SELECTION_OPTION] = "192.0.2.64"
    opts[DHCPOptionCode.RDNSS_SELECTION] = RDNSSSelection(
        1, "192.0.2.1", "192.0.2.2", ["example.com"]
    )
    opts[DHCPOptionCode.IPV4_ADDRESS_MOS] = [
        MoSIPv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
        (99, b"\x01\x02"),
    ]
    opts[DHCPOptionCode.IPV4_FQDN_MOS] = [
        MoSFQDNRecord(1, ["alpha.example", "beta.example"]),
        (99, b"\x03raw"),
    ]
    assert opts.get(DHCPOptionCode.POLICY_FILTER)[0][0] == IPv4AddressOption(
        "192.0.2.1"
    )
    assert opts.get(DHCPOptionCode.STATIC_ROUTE)[0][0] == IPv4AddressOption("192.0.2.0")
    assert opts.get(DHCPOptionCode.USER_CLASS, decode=UserClass) == UserClass(
        [b"alpha", b"\x00\xff"]
    )
    assert isinstance(opts.get(DHCPOptionCode.USER_CLASS), Bytes)
    assert opts.get(
        DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION
    ) == VendorSpecificInformation(b"\x00\xff\x02vendor\x10")
    assert isinstance(opts.get(DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION), Bytes)
    assert opts.get(DHCPOptionCode.RELAY_AGENT_INFORMATION)[0].value == b"\x02"
    assert (
        opts.get(DHCPOptionCode.VI_VENDOR_SPECIFIC_INFORMATION)[0].enterprise_number
        == 32473
    )
    assert opts.get(DHCPOptionCode.NAME_SERVICE_SEARCH) == [6, 44]
    assert opts.get(DHCPOptionCode.SUBNET_SELECTION_OPTION) == IPv4AddressOption(
        "192.0.2.64"
    )
    assert opts.get(DHCPOptionCode.RDNSS_SELECTION) == RDNSSSelection(
        1, "192.0.2.1", "192.0.2.2", ["example.com"]
    )
    assert opts.get(DHCPOptionCode.V4_PCP_SERVER) == [("192.0.2.70", "192.0.2.71")]
    assert opts.get(DHCPOptionCode.IPV4_ADDRESS_MOS) == MoSIPv4AddressList(
        [
            MoSIPv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
            (99, b"\x01\x02"),
        ]
    )
    assert opts.get(DHCPOptionCode.IPV4_FQDN_MOS) == MoSFQDNList(
        [
            MoSFQDNRecord(1, ["alpha.example", "beta.example"]),
            (99, b"\x03raw"),
        ]
    )


def test_registered_option_code_round_trips():
    opts = DHCPOptions()
    opts[DHCPOptionCode.SIP_SERVERS] = ["192.0.2.10", "192.0.2.11"]
    opts[DHCPOptionCode.BCMCS_DOMAIN_NAME_LIST] = ["alpha.example", "beta.example"]
    opts[DHCPOptionCode.BCMCS_IPV4_ADDRESS] = ["192.0.2.14", "192.0.2.15"]
    opts[DHCPOptionCode.CLIENT_SYSTEM_ARCHITECTURE] = [1, 2]
    opts[DHCPOptionCode.PCODE] = "Europe/Berlin"
    opts[DHCPOptionCode.TCODE] = "tz.example/ref"
    opts[DHCPOptionCode.RFC868_TIMESERVER] = ["192.0.2.12"]
    opts[DHCPOptionCode.SWAP_SERVER] = "192.0.2.13"
    opts[DHCPOptionCode.CLIENT_LAST_TRANSACTION_TIME] = 1234
    opts[DHCPOptionCode.ASSOCIATED_IP] = ["192.0.2.20", "192.0.2.21"]
    opts[DHCPOptionCode.IPV6_ONLY] = 4321
    opts[DHCPOptionCode.NETINFO_ADDRESS] = "192.0.2.21"
    opts[DHCPOptionCode.NETINFO_TAG] = "lab-a"
    opts[DHCPOptionCode.DHCP_CAPTIVE_PORTAL] = "https://portal.example/login"
    opts[DHCPOptionCode.AUTO_CONFIG] = True
    opts[DHCPOptionCode.VI_VENDOR_CLASS] = [
        VIVendorClassRecord(32473, [b"docsis", b"eRouter"]),
        (65537, [b"usp", b"agent"]),
    ]
    opts[DHCPOptionCode.CAPWAP_AC_V4] = ["192.0.2.30", "192.0.2.31"]
    opts[DHCPOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS] = [
        "service.example",
        "config.example",
    ]
    opts[DHCPOptionCode.IPV4_ADDRESS_ANDSF] = ["192.0.2.40", "192.0.2.41"]
    opts[DHCPOptionCode.V4_SZTP_REDIRECT] = [
        "https://bootstrap.example/one",
        "https://bootstrap.example/two",
    ]
    opts[DHCPOptionCode.V4_DOTS_RI] = "resolver-a.example"
    opts[DHCPOptionCode.V4_DOTS_ADDRESS] = ["192.0.2.50", "192.0.2.51"]
    opts[DHCPOptionCode.TFTP_SERVER_ADDRESS] = ["192.0.2.60", "192.0.2.61"]
    opts[DHCPOptionCode.BASE_TIME] = 111
    opts[DHCPOptionCode.START_TIME_OF_STATE] = 222
    opts[DHCPOptionCode.QUERY_START_TIME] = 333
    opts[DHCPOptionCode.QUERY_END_TIME] = 444
    opts[DHCPOptionCode.DHCP_STATE] = 7
    opts[DHCPOptionCode.DATA_SOURCE] = 3
    opts[DHCPOptionCode.V4_PCP_SERVER] = ["192.0.2.70", "192.0.2.71"]
    opts[DHCPOptionCode.MUD_URL_V4] = "https://mud.example/policy"
    opts[DHCPOptionCode.CONFIGURATION_FILE] = "/pxe/config.cfg"
    opts[DHCPOptionCode.PATH_PREFIX] = "/pxe/"
    opts[DHCPOptionCode.REBOOT_TIME] = 555
    opts[DHCPOptionCode.V4_ACCESS_DOMAIN] = "access.example"
    opts[DHCPOptionCode.ALL_SUBNETS_ARE_LOCAL] = True
    opts[DHCPOptionCode.MERIT_DUMP_FILE] = "crash.dump"
    opts[DHCPOptionCode.STATUS_CODE] = 7
    opts[DHCPOptionCode.POLICY_FILTER] = PolicyFilter([("192.0.2.1", "255.255.255.0")])
    opts[DHCPOptionCode.STATIC_ROUTE] = StaticRoute([("192.0.2.0", "192.0.2.1")])
    opts[DHCPOptionCode.USER_CLASS] = UserClass([b"alpha", b"\x00\xff"])
    opts[DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION] = VendorSpecificInformation(
        b"\x00\xff\x02vendor\x10"
    )
    opts[DHCPOptionCode.RELAY_AGENT_INFORMATION] = RelayAgentInformation([(9, b"\x02")])
    opts[DHCPOptionCode.VI_VENDOR_SPECIFIC_INFORMATION] = VIVendorSpecificInformation(
        [
            (32473, b"alpha"),
            VIVendorSpecificInformationRecord(65537, b"\x00\xff"),
        ]
    )
    opts[DHCPOptionCode.NAME_SERVICE_SEARCH] = [6, 44]  # DNS, then NetBIOS name server
    opts[DHCPOptionCode.SUBNET_SELECTION_OPTION] = "192.0.2.64"
    opts[DHCPOptionCode.RDNSS_SELECTION] = RDNSSSelection(
        1, "192.0.2.1", "192.0.2.2", ["example.com"]
    )
    opts[DHCPOptionCode.IPV4_ADDRESS_MOS] = [
        MoSIPv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
        (99, b"\x01\x02"),
    ]
    opts[DHCPOptionCode.IPV4_FQDN_MOS] = [
        MoSFQDNRecord(1, ["alpha.example", "beta.example"]),
        (99, b"\x03raw"),
    ]

    encoded = opts.encode()
    decoded = DHCPOptions.decode(memoryview(encoded))

    assert decoded.get(DHCPOptionCode.SIP_SERVERS).values[0] == "192.0.2.10"
    assert decoded.get(DHCPOptionCode.BCMCS_DOMAIN_NAME_LIST) == [
        "alpha.example",
        "beta.example",
    ]
    _assert_addresses(
        decoded, DHCPOptionCode.BCMCS_IPV4_ADDRESS, ["192.0.2.14", "192.0.2.15"]
    )
    assert decoded.get(DHCPOptionCode.CLIENT_SYSTEM_ARCHITECTURE) == [U16(1), U16(2)]
    assert decoded.get(DHCPOptionCode.PCODE, decode=String) == "Europe/Berlin"
    assert decoded.get(DHCPOptionCode.TCODE, decode=String) == "tz.example/ref"
    assert decoded.get(DHCPOptionCode.RFC868_TIMESERVER)[0] == IPv4AddressOption(
        "192.0.2.12"
    )
    assert decoded.get(DHCPOptionCode.SWAP_SERVER) == IPv4AddressOption("192.0.2.13")
    _assert_scalar(decoded, DHCPOptionCode.CLIENT_LAST_TRANSACTION_TIME, U32, 1234)
    assert decoded.get(DHCPOptionCode.ASSOCIATED_IP) == [
        IPv4AddressOption("192.0.2.20"),
        IPv4AddressOption("192.0.2.21"),
    ]
    _assert_scalar(decoded, DHCPOptionCode.IPV6_ONLY, U32, 4321)
    assert decoded.get(DHCPOptionCode.NETINFO_ADDRESS) == IPv4AddressOption(
        "192.0.2.21"
    )
    assert decoded.get(DHCPOptionCode.NETINFO_TAG, decode=String) == "lab-a"
    assert (
        decoded.get(DHCPOptionCode.DHCP_CAPTIVE_PORTAL, decode=String)
        == "https://portal.example/login"
    )
    assert decoded.get(DHCPOptionCode.AUTO_CONFIG) == Boolean(1)
    assert decoded.get(DHCPOptionCode.VI_VENDOR_CLASS) == VIVendorClass(
        [
            (32473, [b"docsis", b"eRouter"]),
            (65537, [b"usp", b"agent"]),
        ]
    )
    _assert_addresses(
        decoded, DHCPOptionCode.CAPWAP_AC_V4, ["192.0.2.30", "192.0.2.31"]
    )
    assert decoded.get(DHCPOptionCode.SIP_UA_CONFIG_SERVICE_DOMAINS) == [
        "service.example",
        "config.example",
    ]
    _assert_addresses(
        decoded, DHCPOptionCode.IPV4_ADDRESS_ANDSF, ["192.0.2.40", "192.0.2.41"]
    )
    assert decoded.get(DHCPOptionCode.V4_SZTP_REDIRECT) == URIList(
        [
            "https://bootstrap.example/one",
            "https://bootstrap.example/two",
        ]
    )
    assert decoded.get(DHCPOptionCode.V4_DOTS_RI) == "resolver-a.example"
    _assert_addresses(
        decoded, DHCPOptionCode.V4_DOTS_ADDRESS, ["192.0.2.50", "192.0.2.51"]
    )
    _assert_addresses(
        decoded, DHCPOptionCode.TFTP_SERVER_ADDRESS, ["192.0.2.60", "192.0.2.61"]
    )
    _assert_scalar(decoded, DHCPOptionCode.BASE_TIME, U32, 111)
    _assert_scalar(decoded, DHCPOptionCode.START_TIME_OF_STATE, U32, 222)
    _assert_scalar(decoded, DHCPOptionCode.QUERY_START_TIME, U32, 333)
    _assert_scalar(decoded, DHCPOptionCode.QUERY_END_TIME, U32, 444)
    _assert_scalar(decoded, DHCPOptionCode.DHCP_STATE, U8, 7)
    _assert_scalar(decoded, DHCPOptionCode.DATA_SOURCE, U8, 3)
    assert decoded.get(DHCPOptionCode.V4_PCP_SERVER)[0] == ("192.0.2.70", "192.0.2.71")
    assert (
        decoded.get(DHCPOptionCode.MUD_URL_V4, decode=String)
        == "https://mud.example/policy"
    )
    assert (
        decoded.get(DHCPOptionCode.CONFIGURATION_FILE, decode=String)
        == "/pxe/config.cfg"
    )
    assert decoded.get(DHCPOptionCode.PATH_PREFIX, decode=String) == "/pxe/"
    _assert_scalar(decoded, DHCPOptionCode.REBOOT_TIME, U32, 555)
    assert decoded.get(DHCPOptionCode.V4_ACCESS_DOMAIN) == "access.example"
    assert decoded.get(DHCPOptionCode.ALL_SUBNETS_ARE_LOCAL) == Boolean(1)
    assert decoded.get(DHCPOptionCode.MERIT_DUMP_FILE, decode=String) == "crash.dump"
    assert decoded.get(DHCPOptionCode.STATUS_CODE).code == 7
    assert decoded.get(DHCPOptionCode.POLICY_FILTER)[0][0] == IPv4AddressOption(
        "192.0.2.1"
    )
    assert decoded.get(DHCPOptionCode.STATIC_ROUTE)[0][1] == IPv4AddressOption(
        "192.0.2.1"
    )
    assert decoded.get(DHCPOptionCode.USER_CLASS, decode=UserClass) == UserClass(
        [b"alpha", b"\x00\xff"]
    )
    assert isinstance(decoded.get(DHCPOptionCode.USER_CLASS), Bytes)
    assert decoded.get(
        DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION
    ) == VendorSpecificInformation(b"\x00\xff\x02vendor\x10")
    assert isinstance(decoded.get(DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION), Bytes)
    assert decoded.get(DHCPOptionCode.RELAY_AGENT_INFORMATION)[0].value == b"\x02"
    assert (
        decoded.get(DHCPOptionCode.VI_VENDOR_SPECIFIC_INFORMATION)[0].enterprise_number
        == 32473
    )
    assert decoded.get(DHCPOptionCode.NAME_SERVICE_SEARCH) == [6, 44]
    assert decoded.get(DHCPOptionCode.SUBNET_SELECTION_OPTION) == IPv4AddressOption(
        "192.0.2.64"
    )
    assert decoded.get(DHCPOptionCode.RDNSS_SELECTION) == RDNSSSelection(
        1, "192.0.2.1", "192.0.2.2", ["example.com"]
    )
    assert decoded.get(DHCPOptionCode.V4_PCP_SERVER) == [("192.0.2.70", "192.0.2.71")]
    assert decoded.get(DHCPOptionCode.IPV4_ADDRESS_MOS) == MoSIPv4AddressList(
        [
            MoSIPv4AddressRecord(1, ["192.0.2.10", "192.0.2.11"]),
            (99, b"\x01\x02"),
        ]
    )
    assert decoded.get(DHCPOptionCode.IPV4_FQDN_MOS) == MoSFQDNList(
        [
            MoSFQDNRecord(1, ["alpha.example", "beta.example"]),
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
    encoded.extend([DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION, len(vendor_payload)])
    encoded.extend(vendor_payload)
    encoded.extend([DHCPOptionCode.VI_VENDOR_SPECIFIC_INFORMATION, len(vi_payload)])
    encoded.extend(vi_payload)
    encoded.append(255)

    decoded = DHCPOptions.decode(memoryview(encoded))

    assert decoded.get(
        DHCPOptionCode.VENDOR_SPECIFIC_INFORMATION
    ) == VendorSpecificInformation(vendor_payload)
    assert decoded.get(
        DHCPOptionCode.VI_VENDOR_SPECIFIC_INFORMATION
    ) == VIVendorSpecificInformation(
        [
            (32473, b"alpha"),
            VIVendorSpecificInformationRecord(65537, b"\x00\xff"),
        ]
    )
    assert DHCPOptionCode.IPV4_ADDRESS_MOS.get_type() is MoSIPv4AddressList
    assert DHCPOptionCode.IPV4_FQDN_MOS.get_type() is MoSFQDNList


def test_raw_wire_decoding_for_new_primitive_registrations():
    encoded = bytearray()
    encoded.extend([DHCPOptionCode.ASSOCIATED_IP, 4])
    encoded.extend(IPv4AddressOption("192.0.2.25").packed)
    encoded.extend([DHCPOptionCode.CLIENT_LAST_TRANSACTION_TIME, 4])
    encoded.extend((1234).to_bytes(4, "big"))
    encoded.extend([DHCPOptionCode.DHCP_STATE, 1, 7])
    encoded.extend([DHCPOptionCode.AUTO_CONFIG, 1, 1])
    encoded.extend([DHCPOptionCode.BCMCS_DOMAIN_NAME_LIST, 15])
    encoded.extend(b"\x05alpha\x07example\x00")
    encoded.append(255)

    decoded = DHCPOptions.decode(memoryview(encoded))

    assert decoded.get(DHCPOptionCode.ASSOCIATED_IP) == [
        IPv4AddressOption("192.0.2.25")
    ]
    _assert_scalar(decoded, DHCPOptionCode.CLIENT_LAST_TRANSACTION_TIME, U32, 1234)
    _assert_scalar(decoded, DHCPOptionCode.DHCP_STATE, U8, 7)
    assert decoded.get(DHCPOptionCode.AUTO_CONFIG) == Boolean(1)
    assert decoded.get(DHCPOptionCode.BCMCS_DOMAIN_NAME_LIST) == ["alpha.example"]


def test_raw_wire_decoding_for_new_string_registrations():
    encoded = bytearray()
    portal = b"https://portal.example/login"
    pcode = b"Europe/Berlin"
    encoded.extend([DHCPOptionCode.DHCP_CAPTIVE_PORTAL, len(portal)])
    encoded.extend(portal)
    encoded.extend([DHCPOptionCode.PCODE, len(pcode)])
    encoded.extend(pcode)
    encoded.append(255)

    decoded = DHCPOptions.decode(memoryview(encoded))

    assert (
        decoded.get(DHCPOptionCode.DHCP_CAPTIVE_PORTAL, decode=String)
        == "https://portal.example/login"
    )
    assert decoded.get(DHCPOptionCode.PCODE, decode=String) == "Europe/Berlin"


def test_raw_wire_decoding_for_v4_sztp_redirect_registration():
    first = b"https://bootstrap.example/one"
    second = b"https://bootstrap.example/two"
    payload = (
        len(first).to_bytes(2, "big") + first + len(second).to_bytes(2, "big") + second
    )
    encoded = bytearray()
    encoded.extend([DHCPOptionCode.V4_SZTP_REDIRECT, len(payload)])
    encoded.extend(payload)
    encoded.append(255)

    decoded = DHCPOptions.decode(memoryview(encoded))

    assert decoded.get(DHCPOptionCode.V4_SZTP_REDIRECT) == URIList(
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
    encoded.extend([DHCPOptionCode.VI_VENDOR_CLASS, len(payload)])
    encoded.extend(payload)
    encoded.append(255)

    decoded = DHCPOptions.decode(memoryview(encoded))

    assert decoded.get(DHCPOptionCode.VI_VENDOR_CLASS) == VIVendorClass(
        [
            (32473, [b"docsis", b"eRouter"]),
            (65537, [b"usp", b"agent"]),
        ]
    )


def test_ccc_option_code_registration_and_round_trip():
    assert DHCPOptionCode.CCC.get_type() is CCCOption

    value = CCCOption(
        [
            CCCPrimaryDHCPServerAddressSubOption(1, "192.0.2.1"),
            CCCSecondaryDHCPServerAddressSubOption(2, "192.0.2.2"),
            CCCProvisioningServerAddressSubOption(3, ("fqdn", "tsp.example")),
            CCCASBackoffRetrySubOption(4, (1, 2, 3)),
            CCCAPBackoffRetrySubOption(5, (4, 5, 6)),
            CCCKerberosRealmNameSubOption(6, "EXAMPLE.COM"),
            CCCTicketGrantingServerUtilizationSubOption(7, True),
            CCCProvisioningTimerSubOption(8, 9),
            CCCSecurityTicketControlSubOption(9, 3),
            CCCKDCServerAddressSubOption(10, ["192.0.2.10", "192.0.2.11"]),
            (99, b"\x01\x02\x03"),
        ]
    )

    opts = DHCPOptions()
    opts[DHCPOptionCode.CCC] = value
    encoded = opts.encode()

    decoded = DHCPOptions.decode(memoryview(encoded))

    assert decoded.get(DHCPOptionCode.CCC) == value
    assert decoded.get(DHCPOptionCode.CCC)[-1].code == 99
    assert decoded.get(DHCPOptionCode.CCC)[-1].value == b"\x01\x02\x03"


def test_register_type_rejects_invalid_type():
    with pytest.raises(TypeError):
        DHCPOptionCode.LOG_SERVER.register_type(int)  # type: ignore[arg-type]


def test_copy_shares_no_mutable_state_with_the_original():
    original = DHCPOptions()
    original[DHCPOptionCode.ROUTER] = [IPv4AddressOption("192.0.2.1")]
    original[DHCPOptionCode.DNS] = [IPv4AddressOption("192.0.2.53")]

    copied = original.copy()
    assert copied is not original
    # private: the code map as stored
    assert copied._codemap is original._codemap
    assert dict(copied.items(decoded=False)) == dict(original.items(decoded=False))

    # Structural edits on the copy leave the original alone ...
    del copied[DHCPOptionCode.DNS]
    copied[DHCPOptionCode.SUBNET_MASK] = IPv4AddressOption("255.255.255.0")
    assert DHCPOptionCode.DNS in original
    assert DHCPOptionCode.SUBNET_MASK not in original

    # ... and so do in-place edits of a payload handed out by get(decode=False),
    # which a shallow dict copy would still share.
    copied.get(DHCPOptionCode.ROUTER, decode=False).extend(b"\x00\x00\x00\x00")
    assert len(original[DHCPOptionCode.ROUTER]) == 4


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
    options = DHCPOptions()
    options[DHCPOptionCode.RAPID_COMMIT] = bytearray()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DHCPMessageType.DHCPDISCOVER]
    )

    assert bytes(options.encode()) == b"\x50\x00\x35\x01\x01\xff"

    roundtrip = DHCPOptions.decode(options.encode())
    assert dict(roundtrip.items(decoded=False)) == {
        DHCPOptionCode.RAPID_COMMIT: bytearray(),
        DHCPOptionCode.DHCP_MESSAGE_TYPE: bytearray([DHCPMessageType.DHCPDISCOVER]),
    }


@pytest.mark.parametrize("size", [0, 1, 254, 255, 256, 300, 510, 511, 600])
def test_long_options_repeat_the_code_byte_on_every_fragment(size):
    """RFC 3396 s4: a long option is split into multiple instances of the same code,
    each carrying its own length octet."""
    payload = bytes(range(256)) * ((size // 256) + 1)
    payload = payload[:size]
    options = DHCPOptions()
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

    roundtrip = DHCPOptions.decode(bytearray(wire))
    assert bytes(roundtrip.get(224, decode=False)) == payload


@pytest.mark.parametrize(
    "maxsize,count,datalen",
    [(10, 1, 20), (20, 3, 5), (64, 8, 6), (312, 20, 14), (576, 40, 12)],
)
def test_partial_encode_never_exceeds_maxsize(maxsize, count, datalen):
    """The length octet must be charged against the budget like the code octet is,
    or an overloaded reply overruns the client's advertised maximum message size."""
    options = DHCPOptions()
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
    options = DHCPOptions()
    options[224] = bytearray(b"X" * 8)
    options[DHCPOptionCode.RAPID_COMMIT] = bytearray()

    encoded, leftover = options.partial_encode(12)

    assert len(encoded) <= 12
    assert leftover is not None
    assert DHCPOptionCode.RAPID_COMMIT in leftover


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
        code = DHCPOptionCode(value)
        assert int(code) == value
        assert code.label() == "UNKNOWN"
        assert code.get_type() is Bytes
        assert repr(code) == f"[{value}]UNKNOWN"
        # Pseudo-members are cached, so a code compares and hashes consistently.
        assert DHCPOptionCode(value) is code

    options = DHCPOptions.decode(bytearray(b"\x35\x01\x01\xe0\x03\x01\x02\x03\xff"))
    assert bytes(options.get(224)) == b"\x01\x02\x03"
    assert dict(options.items(decoded=False))[224] == bytearray(b"\x01\x02\x03")
    assert options == options

    # Out of range is still an error: these are option *codes*, one octet each.
    with pytest.raises(ValueError):
        DHCPOptionCode(256)
    with pytest.raises(ValueError):
        DHCPOptionCode(-1)


def test_a_failing_set_leaves_the_previous_value_intact():
    """__setitem__ built the payload in place, so a codec that raised part-way
    left the option *emptied* rather than unchanged.

    A zero-length option is legal on the wire -- RFC 4039's RAPID_COMMIT is one
    -- so the wreckage encodes and sends cleanly: the failed set silently
    becomes a valid option meaning something else. Here the victim would be
    SERVER_IDENTIFIER, and a client that reads an empty one has no server to
    renew against.
    """
    options = DHCPOptions()
    options[DHCPOptionCode.SERVER_IDENTIFIER] = bytearray(b"\x0a\x00\x00\x01")

    with pytest.raises(Exception):
        options[DHCPOptionCode.SERVER_IDENTIFIER] = "not-an-ip-address"

    assert bytes(options[int(DHCPOptionCode.SERVER_IDENTIFIER)]) == b"\x0a\x00\x00\x01"
    assert bytes(options.encode()) == b"\x36\x04\x0a\x00\x00\x01\xff"

    # And a failing set on a key that was not there must not create it, empty.
    fresh = DHCPOptions()
    with pytest.raises(Exception):
        fresh[DHCPOptionCode.SERVER_IDENTIFIER] = "not-an-ip-address"
    assert int(DHCPOptionCode.SERVER_IDENTIFIER) not in fresh


def test_setting_a_bytearray_copies_it_instead_of_aliasing_the_caller():
    """A bytearray argument used to be stored by reference.

    Every other accepted type was already copied, which is what made the
    exception invisible: it only bites when a caller happens to reuse or mutate
    the buffer afterwards. `DHCPOptions.copy()` exists because this same
    aliasing bit the server's lease path.
    """
    options = DHCPOptions()
    buffer = bytearray(b"\x0a\x00\x00\x01")
    options[DHCPOptionCode.ROUTER] = buffer

    buffer[0] = 0xFF
    buffer.extend(b"\xde\xad")

    assert bytes(options[int(DHCPOptionCode.ROUTER)]) == b"\x0a\x00\x00\x01"
    assert options[int(DHCPOptionCode.ROUTER)] is not buffer

    # The reverse direction too: the stored payload must not be the object a
    # later caller mutates through.
    stored = options.get(DHCPOptionCode.ROUTER, decode=False)
    assert stored is not buffer


def test_reassigning_an_option_keeps_its_position():
    """The options order is wire-visible -- `encode` puts DHCP_MESSAGE_TYPE
    first -- so swapping the payload in must not move the key to the end."""
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DHCPMessageType.DHCPACK.value]
    )
    options[DHCPOptionCode.ROUTER] = bytearray(b"\x0a\x00\x00\xfe")

    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DHCPMessageType.DHCPOFFER.value]
    )

    assert [code for code, _ in _walk(options.encode())] == [
        int(DHCPOptionCode.DHCP_MESSAGE_TYPE),
        int(DHCPOptionCode.ROUTER),
    ]


def test_get_decodes_and_getitem_does_not():
    """Pins the container's one deliberate asymmetry, in both directions.

    `DHCPOptions` declares `MutableMapping[int, bytearray]`, and `get()` does
    not honour it: it decodes. That is the documented API -- `get(..., decode=)`
    is the surface every caller uses -- so this test exists to stop the
    asymmetry being "fixed" into conformance, which would silently change what
    every `options.get(code)` in the wild returns.

    Everything the ABC supplies routes through `__getitem__`, so it all yields
    raw bytes; only `get()` and `items()` decode.
    """
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPACK

    code = int(DHCPOptionCode.DHCP_MESSAGE_TYPE)
    raw = bytearray([DHCPMessageType.DHCPACK.value])

    # `get()` decodes, `[]` does not.
    assert options.get(code) == DHCPMessageType.DHCPACK
    assert options[code] == raw
    assert not isinstance(options[code], DHCPMessageType)

    # ...and every inherited MutableMapping accessor follows `[]`, not `get()`.
    assert dict(options)[code] == raw
    assert list(options.values()) == [raw]
    assert options.setdefault(code, bytearray()) == raw

    # `decode=False` is how you ask `get()` for what `[]` gives you.
    assert options.get(code, decode=False) == raw

    # `items()` is the other deviation: decoded is a freshly built list of
    # `DHCPOption` pairs, raw is the mapping's own live view.
    decoded_items = options.items()
    assert isinstance(decoded_items, list)
    assert [value for _code, value in decoded_items] == [DHCPMessageType.DHCPACK]
    assert not isinstance(options.items(decoded=False), list)
    assert dict(options.items(decoded=False)) == {code: raw}


def test_option_212_is_named_sixrd_and_grd_is_its_alias() -> None:
    """IANA option 212 is OPTION_6RD; a leading digit is not a name, so the member
    is SIXRD and GRD stays as an alias member that resolves to it."""
    assert DHCPOptionCode(212).name == "SIXRD"
    assert DHCPOptionCode.GRD is DHCPOptionCode.SIXRD
    assert DHCPOptionCode["GRD"] is DHCPOptionCode.SIXRD
