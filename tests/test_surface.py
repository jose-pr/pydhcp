"""The public surface: exactly what each ``__all__`` exports.

A name added, removed or renamed changes a list here in the same commit, so the
surface never moves by accident. Each list is sorted the way ``sorted`` sorts it.
"""

from __future__ import annotations

import importlib
import typing

import pytest

EXPECTED_ROOT = [
    "AsyncDHCPCapture",
    "AsyncDHCPListener",
    "AsyncDHCPRelay",
    "AsyncDHCPServer",
    "CaptureEvent",
    "CccApReqApRepBackoffRetry",
    "CccApReqApRepBackoffRetrySubOption",
    "CccAsReqAsRepBackoffRetry",
    "CccAsReqAsRepBackoffRetrySubOption",
    "CccKdcServerAddressList",
    "CccKdcServerAddressSubOption",
    "CccKerberosRealmName",
    "CccKerberosRealmNameSubOption",
    "CccOption",
    "CccPrimaryDhcpServerAddress",
    "CccPrimaryDhcpServerAddressSubOption",
    "CccProvisioningServerAddress",
    "CccProvisioningServerAddressSubOption",
    "CccProvisioningServerFqdn",
    "CccProvisioningTimer",
    "CccProvisioningTimerSubOption",
    "CccSecondaryDhcpServerAddress",
    "CccSecondaryDhcpServerAddressSubOption",
    "CccSecurityTicketControl",
    "CccSecurityTicketControlSubOption",
    "CccSubOption",
    "CccTicketGrantingServerUtilization",
    "CccTicketGrantingServerUtilizationSubOption",
    "ClasslessRoute",
    "ClientIdentifier",
    "DHCPCapture",
    "DHCPClient",
    "DHCPDecodeError",
    "DHCPError",
    "DHCPLease",
    "DHCPListener",
    "DHCPMessage",
    "DHCPOption",
    "DHCPOptionCode",
    "DHCPOptionCodes",
    "DHCPOptionType",
    "DHCPOptions",
    "DHCPRelay",
    "DHCPRequestContext",
    "DHCPServer",
    "DHCPTransport",
    "DHCPValueError",
    "DomainList",
    "FileLeaseBackend",
    "IPv4",
    "IPv4Interface",
    "IPv4Network",
    "InMemoryLeaseBackend",
    "LeaseBackend",
    "MACAddress",
    "MoSFqdnList",
    "MoSFqdnRecord",
    "MoSIpv4AddressList",
    "MoSIpv4AddressRecord",
    "NetworkInterface",
    "NoClientIdentityError",
    "OptionOverload",
    "PktInfoUDPTransport",
    "PolicyFilter",
    "RdnssSelection",
    "RelayAgentInformation",
    "SocketAddress",
    "StaticRoute",
    "TlvOption",
    "U16",
    "U32",
    "U8",
    "UDPTransport",
    "UncompressedDomainList",
    "UriList",
    "UserClass",
    "VendorSpecificInformation",
    "ViVendorClass",
    "ViVendorClassRecord",
    "ViVendorSpecificInformation",
    "ViVendorSpecificInformationRecord",
    "__version__",
    "compile_capture_filter",
]

EXPECTED_CLI = [
    "App",
    "CAPTURE_FORMATS",
    "Capture",
    "HOOK_TIMEOUT_SECONDS",
    "Interfaces",
    "LOGGER",
    "MAX_PER_CAPTURE_FILES",
    "PACKET_FORMATS",
    "Packet",
    "Relay",
    "Server",
    "main",
]

EXPECTED_EXCEPTIONS = [
    "DHCPDecodeError",
    "DHCPError",
    "DHCPValueError",
    "NoClientIdentityError",
]

EXPECTED_LISTENER = [
    "AsyncDHCPListener",
    "BROADCAST_ADDRESS",
    "DHCPListener",
    "DHCPRequestContext",
    "DHCPTransport",
    "ListenAddress",
    "ListenBinding",
    "ListenPort",
    "ListenSpec",
    "PktInfoUDPTransport",
    "UDPTransport",
]

EXPECTED_OPTIONS_TYPE = [
    "BaseFixedLengthInteger",
    "Boolean",
    "Bytes",
    "CccApReqApRepBackoffRetry",
    "CccApReqApRepBackoffRetrySubOption",
    "CccAsReqAsRepBackoffRetry",
    "CccAsReqAsRepBackoffRetrySubOption",
    "CccKdcServerAddressList",
    "CccKdcServerAddressSubOption",
    "CccKerberosRealmName",
    "CccKerberosRealmNameSubOption",
    "CccOption",
    "CccPrimaryDhcpServerAddress",
    "CccPrimaryDhcpServerAddressSubOption",
    "CccProvisioningServerAddress",
    "CccProvisioningServerAddressSubOption",
    "CccProvisioningServerFqdn",
    "CccProvisioningTimer",
    "CccProvisioningTimerSubOption",
    "CccSecondaryDhcpServerAddress",
    "CccSecondaryDhcpServerAddressSubOption",
    "CccSecurityTicketControl",
    "CccSecurityTicketControlSubOption",
    "CccSubOption",
    "CccTicketGrantingServerUtilization",
    "CccTicketGrantingServerUtilizationSubOption",
    "ClasslessRoute",
    "ClientFqdn",
    "ClientIdentifier",
    "DHCPOptionCodes",
    "DHCPOptionType",
    "DomainList",
    "DomainName",
    "EncapsulatedOptions",
    "FixedLengthInteger",
    "Flag",
    "I32",
    "IPv4AddressOption",
    "List",
    "MoSFqdnList",
    "MoSFqdnRecord",
    "MoSIpv4AddressList",
    "MoSIpv4AddressRecord",
    "OctetString",
    "OptionOverload",
    "PcpServerList",
    "PolicyFilter",
    "RdnssSelection",
    "RecordList",
    "RelayAgentInformation",
    "SipServers",
    "StaticRoute",
    "StatusCode",
    "String",
    "TlvOption",
    "U16",
    "U32",
    "U8",
    "UncompressedDomainList",
    "UriList",
    "UserClass",
    "VendorSpecificInformation",
    "ViVendorClass",
    "ViVendorClassRecord",
    "ViVendorSpecificInformation",
    "ViVendorSpecificInformationRecord",
]

EXPECTED_PACKET = [
    "DHCPFlags",
    "DHCPMessage",
    "DHCPMessageType",
    "DHCPOpcode",
    "DHCPPort",
    "HardwareAddressType",
    "dump_mapping",
    "dump_message",
    "load_mapping",
    "load_message",
]

EXPECTED_PACKET_ENUMS = [
    "DHCPFlags",
    "DHCPMessageType",
    "DHCPOpcode",
    "DHCPPort",
    "HardwareAddressType",
]

EXPECTED_PACKET_MESSAGE = [
    "DHCPMessage",
]

EXPECTED_SERVER = [
    "AsyncDHCPServer",
    "DHCPServer",
]

SURFACE = {
    "pydhcp": EXPECTED_ROOT,
    "pydhcp.cli": EXPECTED_CLI,
    "pydhcp.exceptions": EXPECTED_EXCEPTIONS,
    "pydhcp.listener": EXPECTED_LISTENER,
    "pydhcp.options.type": EXPECTED_OPTIONS_TYPE,
    "pydhcp.packet": EXPECTED_PACKET,
    "pydhcp.packet.enums": EXPECTED_PACKET_ENUMS,
    "pydhcp.packet.message": EXPECTED_PACKET_MESSAGE,
    "pydhcp.server": EXPECTED_SERVER,
}


@pytest.mark.parametrize("module_name", sorted(SURFACE))
def test_all_is_exactly_the_pinned_list(module_name: str) -> None:
    module = importlib.import_module(module_name)
    assert sorted(module.__all__) == SURFACE[module_name]


@pytest.mark.parametrize("module_name", sorted(SURFACE))
def test_every_export_exists_and_is_listed_once(module_name: str) -> None:
    module = importlib.import_module(module_name)
    assert len(set(module.__all__)) == len(module.__all__)
    missing = [name for name in module.__all__ if not hasattr(module, name)]
    assert missing == []


def _defined_here(obj: object) -> bool:
    """True for a class or function this package defines under its own name."""
    return (
        isinstance(getattr(obj, "__module__", None), str)
        and obj.__module__.split(".")[0] == "pydhcp"  # type: ignore[attr-defined]
        and isinstance(getattr(obj, "__qualname__", None), str)
        and "<locals>" not in obj.__qualname__  # type: ignore[attr-defined]
    )


@pytest.mark.parametrize("module_name", sorted(SURFACE))
def test_every_export_is_the_defining_object(module_name: str) -> None:
    """An export is the object its home module defines, not a wrapper of it."""
    module = importlib.import_module(module_name)
    wrong: typing.List[str] = []
    for name in module.__all__:
        obj = getattr(module, name)
        if not _defined_here(obj):
            continue
        home: typing.Any = importlib.import_module(obj.__module__)
        for part in obj.__qualname__.split("."):
            home = getattr(home, part, None)
        if home is not obj:
            wrong.append(name)
    assert wrong == []
