"""The text the message display shows for each decoded option.

`DHCPMessage.summary()` and the capture formats print an option through
`_option_text`. The table below is that text for the first sample of every
codec class, pinned so a change to a value's `repr` cannot change what a user
reads.
"""

from __future__ import annotations

import pytest

from conftest import build_request
from pydhcp import DHCPMessage, DHCPOptions
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType

# `_option_text` is the one function the display formats an option with.
from pydhcp.packet._display import _option_text

from value_samples import SAMPLES, label, make

DISPLAY: dict[str, str] = {
    "IPv4AddressOption": "192.0.2.1",
    "ClasslessRoute": "ClasslessRoute(gateway=192.0.2.1, network=10.0.0.0/8)",
    "PolicyFilter": "(IPv4Address('10.0.0.0'), IPv4Address('255.0.0.0'))",
    "StaticRoute": "(IPv4Address('10.0.0.0'), IPv4Address('192.0.2.1'))",
    "DomainList": "'example.com'",
    "UncompressedDomainList": "'example.com'",
    "RDNSSSelection": "RDNSSSelection(flags=1, primary=192.0.2.1, secondary=192.0.2.2, domains=['example.com'])",
    "ClientFQDN": "ClientFQDN(name='host.example.com', flags=0x01, rcode1=0, rcode2=0)",
    "SIPServers": "SIPServers(address, ['192.0.2.1'])",
    "DomainName": "'example.com'",
    "StatusCode": "StatusCode(code=1, message='refused')",
    "PCPServerList": "['192.0.2.1']",
    "Bytes": "b'ab'",
    "URIList": "'http://example.com'",
    "String": "'host'",
    "OctetString": "'host'",
    "Boolean": "Boolean(True)",
    "Flag": "Flag()",
    "U8": "U8(1)",
    "U16": "U16(7)",
    "U32": "U32(86400)",
    "I32": "I32(-5)",
    "ClientIdentifier": "ETHERNET(02:03)|01:02:03",
    "OptionOverload": "<OptionOverload.FILE: 1>",
    "UserClass": "b'ab'",
    "TLVOption": "TLVOption(code=1, value=b'x')",
    "EncapsulatedOptions": "TLVOption(code=1, value=b'x')",
    "VendorSpecificInformation": "b'ab'",
    "RelayAgentInformation": "TLVOption(code=1, value=b'x')",
    "VIVendorSpecificInformationRecord": "VIVendorSpecificInformationRecord(enterprise_number=1, value=b'x')",
    "VIVendorSpecificInformation": "VIVendorSpecificInformationRecord(enterprise_number=1, value=b'x')",
    "VIVendorClassRecord": "VIVendorClassRecord(enterprise_number=1, value=[b'x'])",
    "VIVendorClass": "VIVendorClassRecord(enterprise_number=1, value=[b'x'])",
    "MoSIPv4AddressRecord": "MoSIPv4AddressRecord(code=1, value=[192.0.2.1])",
    "MoSFQDNRecord": "MoSFQDNRecord(code=1, value=['example.com'])",
    "MoSIPv4AddressList": "MoSIPv4AddressRecord(code=1, value=[192.0.2.1])",
    "MoSFQDNList": "MoSFQDNRecord(code=1, value=['example.com'])",
    "CCCOption": "CCCPrimaryDHCPServerAddressSubOption(code=1, value=192.0.2.1)\nCCCProvisioningServerAddressSubOption(code=3, value=CCCProvisioningServerAddress(kind='fqdn', value='example.com'))\nCCCSubOption(code=200, value=b'x')",
    "CCCSubOption": "CCCSubOption(code=200, value=b'x')",
    "CCCPrimaryDHCPServerAddress": "192.0.2.1",
    "CCCSecondaryDHCPServerAddress": "192.0.2.1",
    "CCCProvisioningServerAddress": "CCCProvisioningServerAddress(kind='ipv4', value=192.0.2.1)",
    "CCCProvisioningServerFQDN": "'example.com'",
    "CCCKerberosRealmName": "'EXAMPLE.COM'",
    "CCCASBackoffRetry": "CCCASBackoffRetry(initial_timeout=1, maximum_timeout=2, maximum_retry_count=3)",
    "CCCAPBackoffRetry": "CCCAPBackoffRetry(initial_timeout=1, maximum_timeout=2, maximum_retry_count=3)",
    "CCCTicketGrantingServerUtilization": "Boolean(True)",
    "CCCProvisioningTimer": "CCCProvisioningTimer(5)",
    "CCCSecurityTicketControl": "CCCSecurityTicketControl(1)",
    "CCCKDCServerAddressList": "192.0.2.1",
    "CCCPrimaryDHCPServerAddressSubOption": "CCCPrimaryDHCPServerAddressSubOption(code=1, value=192.0.2.1)",
    "CCCSecondaryDHCPServerAddressSubOption": "CCCSecondaryDHCPServerAddressSubOption(code=2, value=192.0.2.1)",
    "CCCProvisioningServerAddressSubOption": "CCCProvisioningServerAddressSubOption(code=3, value=CCCProvisioningServerAddress(kind='ipv4', value=192.0.2.1))",
    "CCCASBackoffRetrySubOption": "CCCASBackoffRetrySubOption(code=4, value=CCCASBackoffRetry(initial_timeout=1, maximum_timeout=2, maximum_retry_count=3))",
    "CCCAPBackoffRetrySubOption": "CCCAPBackoffRetrySubOption(code=5, value=CCCAPBackoffRetry(initial_timeout=1, maximum_timeout=2, maximum_retry_count=3))",
    "CCCKerberosRealmNameSubOption": "CCCKerberosRealmNameSubOption(code=6, value='EXAMPLE.COM')",
    "CCCTicketGrantingServerUtilizationSubOption": "CCCTicketGrantingServerUtilizationSubOption(code=7, value=Boolean(True))",
    "CCCProvisioningTimerSubOption": "CCCProvisioningTimerSubOption(code=8, value=CCCProvisioningTimer(5))",
    "CCCSecurityTicketControlSubOption": "CCCSecurityTicketControlSubOption(code=9, value=CCCSecurityTicketControl(1))",
    "CCCKDCServerAddressSubOption": "CCCKDCServerAddressSubOption(code=10, value=[192.0.2.1])",
    "DHCPMessageType": "DHCPACK",
    "List[IPv4AddressOption]": "192.0.2.1",
    "List[U8]": "U8(1)\nU8(2)",
    "List[U16]": "U16(1)\nU16(2)",
    "List[ClasslessRoute]": "ClasslessRoute(gateway=192.0.2.1, network=10.0.0.0/8)",
    "DHCPOptionCodes[DHCPOptionCode]": "[001]SUBNET_MASK\n[003]ROUTER",
}


def test_the_table_covers_every_sample() -> None:
    assert sorted(DISPLAY) == sorted(label(cls) for cls in SAMPLES)


@pytest.mark.parametrize("cls", list(SAMPLES), ids=label)
def test_an_option_is_displayed_as_it_always_was(cls: type) -> None:
    assert _option_text(make(cls)) == DISPLAY[label(cls)]


def test_a_message_dump_shows_the_option_text() -> None:
    options = DHCPOptions()
    options[DHCPOptionCode.ROUTER] = ["192.0.2.1", "192.0.2.2"]
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPACK
    options[DHCPOptionCode.HOSTNAME] = "host"
    dump = DHCPMessage.decode(build_request(options=options).encode()).summary()
    assert ": 192.0.2.1\n" in dump
    assert ": DHCPACK" in dump
    assert ": 'host'" in dump


def test_an_input_that_is_now_read_is_displayed_and_serialised() -> None:
    """Values the codecs accept on receipt, each with its text and its JSON."""
    import json

    from pydhcp.options import RDNSSSelection, RelayAgentInformation, StaticRoute
    from pydhcp.packet import DHCPFlags

    addresses = bytes([192, 0, 2, 1, 192, 0, 2, 2])
    cases = [
        (
            RDNSSSelection.unpack(
                bytearray(b"\xfd" + addresses + b"\x07example\x03com\x00\x00")
            ),
            "RDNSSSelection(flags=1, primary=192.0.2.1, secondary=192.0.2.2, "
            "domains=['example.com', ''])",
            [1, "192.0.2.1", "192.0.2.2", ["example.com", ""]],
        ),
        (
            StaticRoute.unpack(bytearray(bytes(4) + bytes([192, 0, 2, 1]))),
            "(IPv4Address('0.0.0.0'), IPv4Address('192.0.2.1'))",
            [["0.0.0.0", "192.0.2.1"]],
        ),
        (
            RelayAgentInformation.unpack(bytearray(bytes([0, 1, 9, 255, 0]))),
            "TLVOption(code=0, value=b'\\t')\nTLVOption(code=255, value=b'')",
            [[0, "09"], [255, ""]],
        ),
        (DHCPMessageType(99), "TYPE_99", 99),
    ]
    for value, text, structured in cases:
        assert _option_text(value) == text
        encoded = json.loads(
            json.dumps(getattr(value, "to_json", lambda: int(value))())
        )
        assert encoded == structured
    message = DHCPMessage.decode(build_request().encode())
    message.flags = DHCPFlags(0x8001)
    assert "BROADCAST|0x0001" in message.summary()
