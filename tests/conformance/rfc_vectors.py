"""Wire vectors for every structured option codec, written from the RFCs.

Each `Vector` is a pair the RFC fixes: the octets of an option payload (the
bytes after the code and length octets) and the value they mean. The octets
come from the RFC's own figure or table where it prints bytes (RFC 3397 s3,
RFC 3442 s3, RFC 3361 s3.1) and from the layout it draws where it does not;
none is taken from what a codec emits. `test_rfc_vectors.py` reads them in
both directions.

`name` carries the RFC and section. `args` are the arguments the codec's
constructor takes for the stated value. `pending` maps a direction to the
reason the codec does not yet agree with the RFC, and the test expects that
direction to fail until the entry is removed.
"""

from __future__ import annotations

import dataclasses
import typing as _ty

from pydhcp.options import (
    I32,
    U8,
    U16,
    U32,
    Boolean,
    CCCOption,
    ClasslessRoute,
    ClientFQDN,
    ClientIdentifier,
    DHCPOptionCode,
    DHCPOptionCodes,
    DomainList,
    DomainName,
    Flag,
    IPv4AddressOption,
    List,
    MoSFQDNList,
    MoSIPv4AddressList,
    OctetString,
    OptionOverload,
    PCPServerList,
    PolicyFilter,
    RDNSSSelection,
    RelayAgentInformation,
    SIPServers,
    StaticRoute,
    StatusCode,
    String,
    UncompressedDomainList,
    URIList,
    UserClass,
    VendorSpecificInformation,
    VIVendorClass,
    VIVendorSpecificInformation,
)
from pydhcp.packet import DHCPMessageType


@dataclasses.dataclass(frozen=True)
class Vector:
    name: str
    codec: _ty.Any
    octets: bytes
    args: tuple[_ty.Any, ...]
    #: The option code whose registered codec this is, when it is bound.
    code: _ty.Optional[int] = None
    #: "both", or "decode" when the RFC's octets are not what a sender emits
    #: (a destination with host bits set, a compression pointer).
    direction: str = "both"
    pending: _ty.Mapping[str, str] = dataclasses.field(default_factory=dict)


def _h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


def _label(text: str) -> bytes:
    return bytes([len(text)]) + text.encode()


EXAMPLE_COM = _label("example") + _label("com") + b"\x00"
EXAMPLE_NET = _label("example") + _label("net") + b"\x00"

#: RFC 3397 s3: eng.apple.com and marketing.apple.com, the second ending in a
#: pointer to "apple" at offset 4 of the option data.
RFC3397_PAYLOAD = b"\x03eng\x05apple\x03com\x00" + b"\x09marketing" + b"\xc0\x04"

#: RFC 3442 s3 prints the destination descriptors of seven routes; the router
#: is 192.0.2.1 in every row here.
_ROUTER = _h("c0 00 02 01")
RFC3442_TABLE = [
    ("0.0.0.0/0", _h("00")),
    ("10.0.0.0/8", _h("08 0a")),
    ("10.0.0.0/24", _h("18 0a 00 00")),
    ("10.17.0.0/16", _h("10 0a 11")),
    ("10.27.129.0/24", _h("18 0a 1b 81")),
    ("10.229.0.128/25", _h("19 0a e5 00 80")),
    ("10.198.122.47/32", _h("20 0a c6 7a 2f")),
]

_RDNSS_ADDRESSES = _h("c0 00 02 01") + _h("c0 00 02 02")

VECTORS: list[Vector] = [
    # RFC 2132: the layouts of the options the registry binds to a scalar or list.
    Vector(
        "rfc2132-s3.3-subnet-mask",
        IPv4AddressOption,
        _h("ff ff ff 00"),
        ("255.255.255.0",),
        code=1,
    ),
    Vector(
        "rfc2132-s3.4-time-offset-negative", I32, _h("ff ff b9 b0"), (-18000,), code=2
    ),
    Vector(
        "rfc2132-s3.5-router-list",
        List[IPv4AddressOption],
        _h("c0 00 02 01 c0 00 02 02"),
        (["192.0.2.1", "192.0.2.2"],),
        code=3,
    ),
    Vector("rfc2132-s3.14-host-name", String, b"host", ("host",), code=12),
    Vector("rfc2132-s3.15-boot-file-size", U16, _h("01 00"), (256,), code=13),
    Vector("rfc2132-s4.1-ip-forwarding", Boolean, _h("01"), (1,), code=19),
    Vector(
        "rfc2132-s4.3-policy-filter",
        PolicyFilter,
        _h("c0 00 02 00 ff ff ff 00"),
        ([("192.0.2.0", "255.255.255.0")],),
        code=21,
    ),
    Vector("rfc2132-s4.5-default-ip-ttl", U8, _h("40"), (64,), code=23),
    Vector(
        "rfc2132-s4.7-path-mtu-plateau-table",
        List[U16],
        _h("00 44 01 28"),
        ([68, 296],),
        code=25,
    ),
    Vector(
        "rfc2132-s5.8-static-route",
        StaticRoute,
        _h("0a 00 00 00 c0 00 02 01"),
        ([("10.0.0.0", "192.0.2.1")],),
        code=33,
    ),
    Vector(
        "rfc2132-s8.4-vendor-specific-information",
        VendorSpecificInformation,
        _h("01 02 61 62"),
        (b"\x01\x02ab",),
        code=43,
    ),
    Vector("rfc2132-s8.7-netbios-node-type", U8, _h("08"), (8,), code=46),
    Vector("rfc2132-s9.2-lease-time", U32, _h("00 01 51 80"), (86400,), code=51),
    Vector(
        "rfc2132-s9.3-option-overload-both", OptionOverload, _h("03"), (3,), code=52
    ),
    Vector(
        "rfc2132-s9.6-message-type-discover", DHCPMessageType, _h("01"), (1,), code=53
    ),
    Vector("rfc2132-s9.6-message-type-ack", DHCPMessageType, _h("05"), (5,), code=53),
    Vector(
        "rfc2132-s9.8-parameter-request-list",
        DHCPOptionCodes[DHCPOptionCode],
        _h("01 03 0f 06"),
        ([1, 3, 15, 6],),
        code=55,
    ),
    Vector("rfc2132-s9.10-maximum-message-size", U16, _h("02 40"), (576,), code=57),
    Vector(
        "rfc2132-s9.13-vendor-class-identifier",
        OctetString,
        b"MSFT 5.0",
        ("MSFT 5.0",),
        code=60,
    ),
    Vector(
        "rfc2132-s9.14-client-identifier-ethernet",
        ClientIdentifier,
        _h("01 00 11 22 33 44 55"),
        (_h("01 00 11 22 33 44 55"),),
        code=61,
    ),
    Vector(
        "rfc4361-s6.1-client-identifier-duid",
        ClientIdentifier,
        _h("ff 00 00 00 01 00 01 00 01 aa bb cc dd 00 11 22 33 44 55"),
        (_h("ff 00 00 00 01 00 01 00 01 aa bb cc dd 00 11 22 33 44 55"),),
        code=61,
    ),
    Vector("rfc4039-s3-rapid-commit", Flag, b"", (), code=80),
    Vector(
        "rfc4702-s2.1-client-fqdn-encoded",
        ClientFQDN,
        _h("05 00 00") + _label("host") + _label("example") + b"\x00",
        ("host.example", 5),
        code=81,
    ),
    # RFC 3046 s2.0: sub-options are code, length, value, with no pad and no end.
    Vector(
        "rfc3046-s2.0-circuit-id-and-remote-id",
        RelayAgentInformation,
        _h("01 04") + b"eth0" + _h("02 06 0a 1b 2c 3d 4e 5f"),
        ([(1, b"eth0"), (2, _h("0a 1b 2c 3d 4e 5f"))],),
        code=82,
    ),
    Vector(
        "rfc3046-s2.0-sub-option-codes-0-and-255-are-not-framing",
        RelayAgentInformation,
        _h("00 01 09 ff 01 07"),
        ([(0, b"\x09"), (255, b"\x07")],),
        code=82,
    ),
    Vector(
        "rfc4280-s4.6-bcmcs-domain-names",
        UncompressedDomainList,
        EXAMPLE_COM + EXAMPLE_NET,
        (["example.com", "example.net"],),
        code=88,
    ),
    Vector(
        "rfc3397-s3-search-list-compressed",
        DomainList,
        RFC3397_PAYLOAD,
        (["eng.apple.com", "marketing.apple.com"],),
        code=119,
    ),
    Vector(
        "rfc3361-s3.1-two-names",
        SIPServers,
        b"\x00" + EXAMPLE_COM + EXAMPLE_NET,
        (["example.com", "example.net"], 0),
        code=120,
    ),
    Vector(
        "rfc3361-s3.2-two-addresses",
        SIPServers,
        _h("01 c0 00 02 01 c0 00 02 02"),
        (["192.0.2.1", "192.0.2.2"], 1),
        code=120,
    ),
    # RFC 3361 s3.1: "Clients MUST support compression according to ... 4.1.4";
    # offsets count from the encoding octet, the start of the option data.
    Vector(
        "rfc3361-s3.1-compressed-second-name",
        SIPServers,
        b"\x00" + EXAMPLE_COM + _label("sip") + _h("c0 01"),
        (["example.com", "sip.example.com"], 0),
        code=120,
        direction="decode",
    ),
    Vector(
        "rfc3925-s3-vi-vendor-class",
        VIVendorClass,
        _h("00 00 01 37 03 02") + b"ab",
        ([(311, [b"ab"])],),
        code=124,
    ),
    Vector(
        "rfc3925-s4-vi-vendor-specific-information",
        VIVendorSpecificInformation,
        _h("00 00 01 37 05 01 03 aa bb cc"),
        ([(311, _h("01 03 aa bb cc"))],),
        code=125,
    ),
    Vector(
        "rfc5678-s4.1-ipv4-address-mos",
        MoSIPv4AddressList,
        _h("01 04 c0 00 02 01"),
        ([(1, ["192.0.2.1"])],),
        code=139,
    ),
    Vector(
        "rfc5678-s4.2-fqdn-mos",
        MoSFQDNList,
        _h("01 0d") + EXAMPLE_COM,
        ([(1, ["example.com"])],),
        code=140,
    ),
    Vector(
        "rfc8572-s8.1-sztp-redirect-uri",
        URIList,
        _h("00 12") + b"https://sztp.test/",
        (["https://sztp.test/"],),
        code=143,
    ),
    Vector(
        "rfc6704-s3.1-forcerenew-nonce-hmac-md5", List[U8], _h("01"), ([1],), code=145
    ),
    Vector(
        "rfc6731-s4.3-domain-list",
        RDNSSSelection,
        _h("01") + _RDNSS_ADDRESSES + EXAMPLE_COM,
        (1, "192.0.2.1", "192.0.2.2", ["example.com"]),
        code=146,
    ),
    Vector(
        "rfc6731-s4.3-root-domain-is-the-default-rdnss",
        RDNSSSelection,
        _h("01") + _RDNSS_ADDRESSES + EXAMPLE_COM + b"\x00",
        (1, "192.0.2.1", "192.0.2.2", ["example.com", "."]),
        code=146,
    ),
    Vector(
        "rfc6731-s4.3-only-the-root-domain",
        RDNSSSelection,
        _h("00") + _RDNSS_ADDRESSES + b"\x00",
        (0, "192.0.2.1", "192.0.2.2", ["."]),
        code=146,
    ),
    Vector(
        "rfc6731-s4.3-reserved-bits-are-ignored-on-receipt",
        RDNSSSelection,
        _h("fd") + _RDNSS_ADDRESSES + EXAMPLE_COM,
        (1, "192.0.2.1", "192.0.2.2", ["example.com"]),
        code=146,
        direction="decode",
    ),
    Vector(
        "rfc8973-s5.2-dots-reference-identifier",
        DomainName,
        EXAMPLE_COM,
        ("example.com",),
        code=147,
    ),
    Vector(
        "rfc6926-s6.2.2-status-code",
        StatusCode,
        b"\x00success",
        (0, "success"),
        code=151,
    ),
    Vector(
        "rfc7291-s4-pcp-server-list",
        PCPServerList,
        _h("08 c0 00 02 01 c0 00 02 02"),
        ([["192.0.2.1", "192.0.2.2"]],),
        code=158,
    ),
    Vector(
        "rfc2937-s3-name-service-search",
        List[U16],
        _h("00 06 00 29"),
        ([6, 41],),
        code=117,
    ),
    Vector(
        "rfc4578-s2.1-client-system-architecture",
        List[U16],
        _h("00 00 00 07"),
        ([0, 7],),
        code=93,
    ),
    Vector("rfc8925-s3.2-ipv6-only-wait", U32, _h("00 00 07 08"), (1800,), code=108),
    Vector(
        "rfc5986-s3.2-access-network-domain-name",
        DomainName,
        EXAMPLE_COM,
        ("example.com",),
        code=213,
    ),
    Vector(
        "rfc3004-s4-user-class",
        UserClass,
        _h("03") + b"abc" + _h("02") + b"de",
        ([b"abc", b"de"],),
    ),
    # RFC 3495 s5: the CableLabs client configuration sub-options.
    Vector(
        "rfc3495-s5.1-tsp-primary-dhcp-server",
        CCCOption,
        _h("01 04 c0 00 02 01"),
        ([(1, "192.0.2.1")],),
        code=122,
    ),
    Vector(
        "rfc3495-s5.2-tsp-secondary-dhcp-server",
        CCCOption,
        _h("02 04 c0 00 02 02"),
        ([(2, "192.0.2.2")],),
        code=122,
    ),
    Vector(
        "rfc3495-s5.2-provisioning-server-address",
        CCCOption,
        _h("03 05 01 c0 00 02 01"),
        ([(3, "192.0.2.1")],),
        code=122,
    ),
    Vector(
        "rfc3495-s5.2-provisioning-server-fqdn",
        CCCOption,
        _h("03 0e 00") + EXAMPLE_COM,
        ([(3, "example.com")],),
        code=122,
    ),
    Vector(
        "rfc3495-s5.3-as-req-backoff-and-retry",
        CCCOption,
        _h("04 0c 00 00 00 0a 00 00 00 3c 00 00 00 03"),
        ([(4, (10, 60, 3))],),
        code=122,
    ),
    Vector(
        "rfc3495-s5.6-tgs-utilization", CCCOption, _h("07 01 01"), ([(7, 1)],), code=122
    ),
    Vector(
        "rfc3495-s5.7-provisioning-timer",
        CCCOption,
        _h("08 01 05"),
        ([(8, 5)],),
        code=122,
    ),
]

# RFC 3442 s3: the seven descriptors in its table, each with its router.
for _network, _descriptor in RFC3442_TABLE:
    VECTORS.append(
        Vector(
            f"rfc3442-s3-descriptor-{_network}",
            List[ClasslessRoute],
            _descriptor + _ROUTER,
            ([("192.0.2.1", _network)],),
            code=121,
        )
    )

VECTORS.append(
    # RFC 3442 s3: a destination of 129.210.177.132 under a /25 is installed as
    # 129.210.177.128; the octets the server sent are not what a sender emits.
    Vector(
        "rfc3442-s3-host-bits-of-129.210.177.132-slash-25-are-zeroed",
        List[ClasslessRoute],
        _h("19 81 d2 b1 84") + _ROUTER,
        ([("192.0.2.1", "129.210.177.128/25")],),
        code=121,
        direction="decode",
    )
)
