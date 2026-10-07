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
    "AsyncDHCPClient",
    "AsyncDHCPListener",
    "AsyncDHCPRelay",
    "AsyncDHCPServer",
    "CaptureEvent",
    "ClasslessRoute",
    "ClientIdentifier",
    "DHCPCapture",
    "DHCPClient",
    "DHCPConfigError",
    "DHCPDecodeError",
    "DHCPError",
    "DHCPFlags",
    "DHCPHookError",
    "DHCPLease",
    "DHCPListener",
    "DHCPMessage",
    "DHCPMessageType",
    "DHCPOpcode",
    "DHCPOption",
    "DHCPOptionCode",
    "DHCPOptionCodes",
    "DHCPOptionType",
    "DHCPOptions",
    "DHCPPort",
    "DHCPRefusedError",
    "DHCPRelay",
    "DHCPRequestContext",
    "DHCPServer",
    "DHCPTimeoutError",
    "DHCPTransport",
    "DHCPValueError",
    "DomainList",
    "FileLeaseBackend",
    "IPv4AddressLike",
    "InMemoryLeaseBackend",
    "LeaseBackend",
    "MACAddress",
    "NetworkInterface",
    "NoClientIdentityError",
    "OptionOverload",
    "PktInfoUDPTransport",
    "PolicyFilter",
    "RDNSSSelection",
    "RelayAgentInformation",
    "SocketAddress",
    "StaticRoute",
    "TLVOption",
    "U16",
    "U32",
    "U8",
    "UDPTransport",
    "URIList",
    "UncompressedDomainList",
    "UserClass",
    "VendorSpecificInformation",
    "__version__",
    "compile_capture_filter",
]

EXPECTED_CLI = [
    "App",
    "Capture",
    "Interfaces",
    "Packet",
    "Relay",
    "Replay",
    "Server",
    "main",
]

EXPECTED_EXCEPTIONS = [
    "DHCPConfigError",
    "DHCPDecodeError",
    "DHCPError",
    "DHCPHookError",
    "DHCPRefusedError",
    "DHCPTimeoutError",
    "DHCPValueError",
    "NoClientIdentityError",
]

EXPECTED_LISTENER = [
    "AsyncDHCPListener",
    "BROADCAST_ADDRESS",
    "DHCPListener",
    "DHCPMetrics",
    "DHCPRequestContext",
    "DHCPTransport",
    "ListenLike",
    "PktInfoUDPTransport",
    "UDPTransport",
]

EXPECTED_OPTIONS_TYPE = [
    "BaseFixedLengthInteger",
    "Boolean",
    "Bytes",
    "CCCAPBackoffRetry",
    "CCCAPBackoffRetrySubOption",
    "CCCASBackoffRetry",
    "CCCASBackoffRetrySubOption",
    "CCCKDCServerAddressList",
    "CCCKDCServerAddressSubOption",
    "CCCKerberosRealmName",
    "CCCKerberosRealmNameSubOption",
    "CCCOption",
    "CCCPrimaryDHCPServerAddress",
    "CCCPrimaryDHCPServerAddressSubOption",
    "CCCProvisioningServerAddress",
    "CCCProvisioningServerAddressSubOption",
    "CCCProvisioningServerFQDN",
    "CCCProvisioningTimer",
    "CCCProvisioningTimerSubOption",
    "CCCSecondaryDHCPServerAddress",
    "CCCSecondaryDHCPServerAddressSubOption",
    "CCCSecurityTicketControl",
    "CCCSecurityTicketControlSubOption",
    "CCCSubOption",
    "CCCTicketGrantingServerUtilization",
    "CCCTicketGrantingServerUtilizationSubOption",
    "ClasslessRoute",
    "ClientFQDN",
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
    "MoSFQDNList",
    "MoSFQDNRecord",
    "MoSIPv4AddressList",
    "MoSIPv4AddressRecord",
    "OctetString",
    "OptionCodec",
    "OptionOverload",
    "PCPServerList",
    "PolicyFilter",
    "RDNSSSelection",
    "RecordList",
    "RelayAgentInformation",
    "SIPServers",
    "StaticRoute",
    "StatusCode",
    "String",
    "TLVOption",
    "U16",
    "U32",
    "U8",
    "URIList",
    "UncompressedDomainList",
    "UserClass",
    "VIVendorClass",
    "VIVendorClassRecord",
    "VIVendorSpecificInformation",
    "VIVendorSpecificInformationRecord",
    "VendorSpecificInformation",
]

EXPECTED_PACKET = [
    "DHCPFlags",
    "DHCPMessage",
    "DHCPMessageType",
    "DHCPOpcode",
    "DHCPPort",
    "HardwareAddressType",
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

EXPECTED_OPTIONS = sorted(
    EXPECTED_OPTIONS_TYPE
    + [
        "BaseDHCPOptionCode",
        "DHCPOption",
        "DHCPOptionCode",
        "DHCPOptions",
        "MAX_OPTION_CODE",
        "MIN_OPTION_CODE",
        "OptionCode",
    ]
)

EXPECTED_CLIENT = ["AsyncDHCPClient", "ClientIdentifierLike", "DHCPClient"]

EXPECTED_RELAY = [
    "AsyncDHCPRelay",
    "DEFAULT_MAX_HOPS",
    "DHCPRelay",
    "RFC1542_MAX_HOPS",
    "ServerAddressLike",
]

EXPECTED_CAPTURE = [
    "AsyncDHCPCapture",
    "CaptureEvent",
    "CaptureHook",
    "CapturePredicate",
    "CaptureSink",
    "DHCPCapture",
    "DHCPCaptureWriter",
    "DHCPLayer",
    "FILENAME_FIELDS",
    "HOOK_TIMEOUT_SECONDS",
    "MAX_CAPTURE_FILES",
    "PacketFilterLike",
    "UNIQUE_FILENAME_FIELDS",
    "capture_dissector",
    "command_hook",
    "compile_capture_filter",
    "dissect_dhcp",
    "pktcap_plugin",
    "read_capture",
    "register_dhcp_dissector",
    "replay_capture",
]

EXPECTED_LEASE = [
    "DHCPLease",
    "FileLeaseBackend",
    "InMemoryLeaseBackend",
    "LeaseBackend",
]

EXPECTED_STRUCTURED = [
    "dumps",
    "loads",
]

# private: the name is looked up in the module that reads it, so the host or the clock can be stood for
SURFACE = {
    "pydhcp": EXPECTED_ROOT,
    "pydhcp.capture": EXPECTED_CAPTURE,
    "pydhcp.cli": EXPECTED_CLI,
    "pydhcp.client": EXPECTED_CLIENT,
    "pydhcp.exceptions": EXPECTED_EXCEPTIONS,
    "pydhcp.lease": EXPECTED_LEASE,
    "pydhcp.listener": EXPECTED_LISTENER,
    "pydhcp.options": EXPECTED_OPTIONS,
    "pydhcp.options._codecs": EXPECTED_OPTIONS_TYPE,
    "pydhcp.packet": EXPECTED_PACKET,
    "pydhcp.packet._enums": EXPECTED_PACKET_ENUMS,
    "pydhcp.packet._message": EXPECTED_PACKET_MESSAGE,
    "pydhcp.packet.structured": EXPECTED_STRUCTURED,
    "pydhcp.relay": EXPECTED_RELAY,
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


@pytest.mark.parametrize("module_name", sorted(SURFACE))
def test_no_export_is_a_typevar_a_logger_or_underscored(module_name: str) -> None:
    import logging

    module = importlib.import_module(module_name)
    wrong = [
        name
        for name in module.__all__
        if isinstance(getattr(module, name), (typing.TypeVar, logging.Logger))
        or (name.startswith("_") and name != "__version__")
    ]
    assert wrong == []


def test_a_name_exported_twice_is_one_object() -> None:
    """The root and a package re-export the same object, never a wrapper."""
    homes: typing.Dict[str, typing.Dict[int, str]] = {}
    for module_name in SURFACE:
        module = importlib.import_module(module_name)
        for name in module.__all__:
            homes.setdefault(name, {})[id(getattr(module, name))] = module_name
    assert {n: sorted(h.values()) for n, h in homes.items() if len(h) > 1} == {}


def test_the_root_mac_address_is_the_netimps_type() -> None:
    """`NetworkInterface.mac` hands one to a caller; the root names it, the same object."""
    import netimps
    import pydhcp

    assert pydhcp.MACAddress is netimps.MACAddress
    assert "MACAddress" in pydhcp.__all__
