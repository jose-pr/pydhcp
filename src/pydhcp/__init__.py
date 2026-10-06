from __future__ import annotations

from importlib.metadata import version as _version

from . import _log  # noqa: F401 -- attaches the package logger's NullHandler
from .exceptions import (
    DHCPError as DHCPError,
    DHCPDecodeError as DHCPDecodeError,
    DHCPValueError as DHCPValueError,
    NoClientIdentityError as NoClientIdentityError,
)
from .listener import (
    DHCPListener as DHCPListener,
    AsyncDHCPListener as AsyncDHCPListener,
    DHCPTransport as DHCPTransport,
    UDPTransport as UDPTransport,
    PktInfoUDPTransport as PktInfoUDPTransport,
    DHCPRequestContext as DHCPRequestContext,
)
from .packet._enums import (
    DHCPFlags as DHCPFlags,
    DHCPMessageType as DHCPMessageType,
    DHCPOpcode as DHCPOpcode,
    DHCPPort as DHCPPort,
)
from .packet._message import DHCPMessage as DHCPMessage
from .options import (
    DHCPOptions as DHCPOptions,
    DHCPOption as DHCPOption,
    DHCPOptionCode as DHCPOptionCode,
)
from .options._codecs import (
    DHCPOptionType as DHCPOptionType,
    DHCPOptionCodes as DHCPOptionCodes,
    ClasslessRoute as ClasslessRoute,
    PolicyFilter as PolicyFilter,
    StaticRoute as StaticRoute,
    DomainList as DomainList,
    UncompressedDomainList as UncompressedDomainList,
    ClientIdentifier as ClientIdentifier,
    OptionOverload as OptionOverload,
    UserClass as UserClass,
    TLVOption as TLVOption,
    VendorSpecificInformation as VendorSpecificInformation,
    RelayAgentInformation as RelayAgentInformation,
    RDNSSSelection as RDNSSSelection,
    URIList as URIList,
    U8 as U8,
    U16 as U16,
    U32 as U32,
)
from ._network import (
    SocketAddress as SocketAddress,
    NetworkInterface as NetworkInterface,
)
from .server import DHCPServer as DHCPServer, AsyncDHCPServer as AsyncDHCPServer
from .client import AsyncDHCPClient as AsyncDHCPClient, DHCPClient as DHCPClient
from .relay import DHCPRelay as DHCPRelay, AsyncDHCPRelay as AsyncDHCPRelay
from .capture import (
    CaptureEvent as CaptureEvent,
    DHCPCapture as DHCPCapture,
    AsyncDHCPCapture as AsyncDHCPCapture,
    compile_capture_filter as compile_capture_filter,
)
from .lease import (
    DHCPLease as DHCPLease,
    LeaseBackend as LeaseBackend,
    InMemoryLeaseBackend as InMemoryLeaseBackend,
    FileLeaseBackend as FileLeaseBackend,
)

__version__ = _version("pydhcp")

__all__ = [
    "__version__",
    "DHCPError",
    "DHCPDecodeError",
    "DHCPValueError",
    "NoClientIdentityError",
    "DHCPListener",
    "AsyncDHCPListener",
    "DHCPTransport",
    "UDPTransport",
    "PktInfoUDPTransport",
    "DHCPRequestContext",
    "DHCPMessage",
    "DHCPMessageType",
    "DHCPOpcode",
    "DHCPFlags",
    "DHCPPort",
    "DHCPOptions",
    "DHCPOption",
    "DHCPOptionCode",
    "DHCPOptionType",
    "DHCPOptionCodes",
    "ClasslessRoute",
    "PolicyFilter",
    "StaticRoute",
    "DomainList",
    "UncompressedDomainList",
    "ClientIdentifier",
    "OptionOverload",
    "UserClass",
    "TLVOption",
    "VendorSpecificInformation",
    "RelayAgentInformation",
    "RDNSSSelection",
    "URIList",
    "U8",
    "U16",
    "U32",
    "SocketAddress",
    "NetworkInterface",
    "DHCPServer",
    "AsyncDHCPServer",
    "DHCPClient",
    "AsyncDHCPClient",
    "DHCPRelay",
    "AsyncDHCPRelay",
    "CaptureEvent",
    "DHCPCapture",
    "AsyncDHCPCapture",
    "compile_capture_filter",
    "DHCPLease",
    "LeaseBackend",
    "InMemoryLeaseBackend",
    "FileLeaseBackend",
]
