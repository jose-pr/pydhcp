from __future__ import annotations

import ipaddress as _ipaddress
import typing as _ty

#: The unspecified IPv4 address, the "every address" bind target and the source
#: of a client that has none yet.
WILDCARD_V4: _ty.Final = _ipaddress.IPv4Address("0.0.0.0")
INFINITE_LEASE_TIME: _ty.Final = 0xFFFFFFFF
DHCP_MIN_LEGAL_PACKET_SIZE: _ty.Final = 576

#: The minimal BOOTP message, RFC 951's fixed header plus its 64-octet vend
#: field. RFC 1542 s2.1 has a relay agent check that a datagram's UDP payload is
#: large enough to hold this, and "BOOTP messages not meeting these consistency
#: checks MUST be silently discarded" -- so an agent implementing the check is
#: required to drop anything shorter. Outgoing messages are padded to it, which
#: is what ISC's BOOTP_MIN_LEN does and what ISC dhclient was measured sending.
BOOTP_MIN_PACKET_SIZE: _ty.Final = 300
UDP_MIN_PACKET_SIZE: _ty.Final = 28  # IPV4 , 48 for ipv6
UDP_MAX_PACKET_SIZE: _ty.Final = 65_535
