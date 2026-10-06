"""Sample values of every option codec, shared by the tests of the value laws.

`SAMPLES` holds, for each class the codec package exports and for each class the
registry builds by subscription, the constructor arguments of one value and of a
different one. A class added without a sample fails
`test_value_laws.py::test_every_exported_codec_has_a_sample`.
"""

from __future__ import annotations

import re
import typing as _ty

from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType
from pydhcp.options._codecs import *  # noqa: F401,F403

#: class -> (arguments of one value, arguments of a different value).
SAMPLES: dict[type, tuple[tuple[_ty.Any, ...], tuple[_ty.Any, ...]]] = {
    IPv4AddressOption: (("192.0.2.1",), ("192.0.2.2",)),
    ClasslessRoute: (("192.0.2.1", "10.0.0.0/8"), ("192.0.2.2", "10.0.0.0/8")),
    PolicyFilter: (([("10.0.0.0", "255.0.0.0")],), ([("10.1.0.0", "255.255.0.0")],)),
    StaticRoute: (([("10.0.0.0", "192.0.2.1")],), ([("10.1.0.0", "192.0.2.1")],)),
    DomainList: ((["example.com"],), (["example.org"],)),
    UncompressedDomainList: ((["example.com"],), (["example.org"],)),
    RDNSSSelection: (
        (1, "192.0.2.1", "192.0.2.2", ["example.com"]),
        (2, "192.0.2.1", "192.0.2.2", ["example.com"]),
    ),
    ClientFQDN: (("host.example.com", 1), ("other.example.com", 1)),
    SIPServers: ((["192.0.2.1"],), (["192.0.2.2"],)),
    DomainName: (("example.com",), ("example.org",)),
    StatusCode: ((1, "refused"), (2, "refused")),
    PCPServerList: (([["192.0.2.1"]],), ([["192.0.2.2"]],)),
    Bytes: ((b"ab",), (b"abc",)),
    URIList: ((["http://example.com"],), (["http://example.org"],)),
    String: (("host",), ("other",)),
    OctetString: (("host",), ("other",)),
    Boolean: ((1,), (0,)),
    Flag: ((), None),  # type: ignore[dict-item]
    U8: ((1,), (2,)),
    U16: ((7,), (8,)),
    U32: ((86400,), (86401,)),
    I32: ((-5,), (5,)),
    ClientIdentifier: ((b"\x01\x02\x03",), (b"\x01\x02\x04",)),
    OptionOverload: ((1,), (2,)),
    UserClass: (([b"ab"],), ([b"abc"],)),
    TLVOption: ((1, b"x"), (2, b"x")),
    EncapsulatedOptions: (([(1, b"x")],), ([(2, b"x")],)),
    VendorSpecificInformation: ((b"ab",), (b"abc",)),
    RelayAgentInformation: (([(1, b"x")],), ([(2, b"x")],)),
    VIVendorSpecificInformationRecord: ((1, b"x"), (2, b"x")),
    VIVendorSpecificInformation: (([(1, b"x")],), ([(2, b"x")],)),
    VIVendorClassRecord: ((1, [b"x"]), (2, [b"x"])),
    VIVendorClass: (([(1, [b"x"])],), ([(2, [b"x"])],)),
    MoSIPv4AddressRecord: ((1, ["192.0.2.1"]), (2, ["192.0.2.1"])),
    MoSFQDNRecord: ((1, ["example.com"]), (2, ["example.com"])),
    MoSIPv4AddressList: (([(1, ["192.0.2.1"])],), ([(2, ["192.0.2.1"])],)),
    MoSFQDNList: (([(1, ["example.com"])],), ([(2, ["example.com"])],)),
    CCCOption: (
        ([(1, "192.0.2.1"), (3, "example.com"), (200, b"x")],),
        ([(1, "192.0.2.2")],),
    ),
    CCCSubOption: ((200, b"x"), (201, b"x")),
    CCCPrimaryDHCPServerAddress: (("192.0.2.1",), ("192.0.2.2",)),
    CCCSecondaryDHCPServerAddress: (("192.0.2.1",), ("192.0.2.2",)),
    CCCProvisioningServerAddress: (("192.0.2.1",), ("example.com",)),
    CCCProvisioningServerFQDN: (("example.com",), ("example.org",)),
    CCCKerberosRealmName: (("EXAMPLE.COM",), ("EXAMPLE.ORG",)),
    CCCASBackoffRetry: ((1, 2, 3), (1, 2, 4)),
    CCCAPBackoffRetry: ((1, 2, 3), (1, 2, 4)),
    CCCTicketGrantingServerUtilization: ((1,), (0,)),
    CCCProvisioningTimer: ((5,), (6,)),
    CCCSecurityTicketControl: ((1,), (2,)),
    CCCKDCServerAddressList: ((["192.0.2.1"],), (["192.0.2.2"],)),
    CCCPrimaryDHCPServerAddressSubOption: ((1, "192.0.2.1"), (1, "192.0.2.2")),
    CCCSecondaryDHCPServerAddressSubOption: ((2, "192.0.2.1"), (2, "192.0.2.2")),
    CCCProvisioningServerAddressSubOption: ((3, "192.0.2.1"), (3, "example.com")),
    CCCASBackoffRetrySubOption: ((4, (1, 2, 3)), (4, (1, 2, 4))),
    CCCAPBackoffRetrySubOption: ((5, (1, 2, 3)), (5, (1, 2, 4))),
    CCCKerberosRealmNameSubOption: ((6, "EXAMPLE.COM"), (6, "EXAMPLE.ORG")),
    CCCTicketGrantingServerUtilizationSubOption: ((7, 1), (7, 0)),
    CCCProvisioningTimerSubOption: ((8, 5), (8, 6)),
    CCCSecurityTicketControlSubOption: ((9, 1), (9, 2)),
    CCCKDCServerAddressSubOption: ((10, ["192.0.2.1"]), (10, ["192.0.2.2"])),
    DHCPMessageType: ((5,), (2,)),
    # The classes the registry builds by subscription.
    List[IPv4AddressOption]: ((["192.0.2.1"],), (["192.0.2.2"],)),
    List[U8]: (([1, 2],), ([1, 3],)),
    List[U16]: (([1, 2],), ([1, 3],)),
    List[ClasslessRoute]: (
        ([("192.0.2.1", "10.0.0.0/8")],),
        ([("192.0.2.2", "10.0.0.0/8")],),
    ),
    DHCPOptionCodes[DHCPOptionCode]: (([1, 3],), ([1, 6],)),
}

#: Exported classes that are contracts or bases, not values.
NOT_VALUES = {
    "DHCPOptionType",
    "List",
    "RecordList",
    "DHCPOptionCodes",
    "BaseFixedLengthInteger",
    "FixedLengthInteger",
}

#: An equal value spelled another way, for the classes that accept one.
ALT_SPELLINGS: dict[type, tuple[_ty.Any, ...]] = {
    IPv4AddressOption: (b"\xc0\x00\x02\x01",),
    ClasslessRoute: (("192.0.2.1", "10.0.0.0/8"),),
    U16: ("7",),
    Boolean: (True,),
    List[IPv4AddressOption]: ("192.0.2.1",),
    DHCPOptionCodes[DHCPOptionCode]: ((1, 3),),
}

#: class -> (a raw item that is accepted, an item that is refused or None).
ITEMS: dict[type, tuple[_ty.Any, _ty.Any]] = {
    List[IPv4AddressOption]: ("192.0.2.9", "not an address"),
    List[U8]: (7, 300),
    List[U16]: (7, 70000),
    List[ClasslessRoute]: (("192.0.2.9", "10.0.0.0/8"), "nonsense"),
    DHCPOptionCodes[DHCPOptionCode]: (9, 300),
    DomainList: ("b.example.com", 5),
    UncompressedDomainList: ("b.example.com", 5),
    URIList: ("http://example.net", None),
    PolicyFilter: (("10.9.0.0", "255.255.0.0"), ("x", "y")),
    StaticRoute: (("10.9.0.0", "192.0.2.1"), ("0.0.0.0", "192.0.2.1")),
    PCPServerList: (["192.0.2.9"], []),
    UserClass: (b"zz", b""),
    EncapsulatedOptions: ((9, b"z"), (1,)),
    RelayAgentInformation: ((9, b"z"), (1,)),
    VIVendorSpecificInformation: ((9, b"z"), (1,)),
    VIVendorClass: ((9, [b"z"]), (9, [b""])),
    MoSIPv4AddressList: ((2, ["192.0.2.9"]), (1, ["not an address"])),
    MoSFQDNList: ((2, ["b.example.com"]), (1, ["a..b"])),
    CCCOption: ((200, b"z"), (4, "x")),
    CCCKDCServerAddressList: ("192.0.2.9", "not an address"),
}


def make(cls: type, which: int = 0) -> _ty.Any:
    """The `which`-th sample value of `cls`."""
    return cls(*SAMPLES[cls][which])


def label(cls: type) -> str:
    """The class name as a reader writes it: `List[U8]`, not the module path."""
    return re.sub(r"[\w.]+\.(\w+)", r"\1", cls.__name__)
