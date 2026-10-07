# Common DHCP Options

This page shows the typed option workflow: assign native Python values to `DHCPOptions`, let the registered option type do the encoding, and inspect decoded values with `repr()`.

## Single IPv4 option

```python
from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode

options = DHCPOptions()
options[DHCPOptionCode.SERVER_IDENTIFIER] = "192.0.2.1"
```

## List of IPv4 addresses

```python
from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode

options = DHCPOptions()
options[DHCPOptionCode.DNS] = ["192.0.2.53", "192.0.2.54"]
```

## Boolean and presence options

```python
from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode

options = DHCPOptions()
options[DHCPOptionCode.ALL_SUBNETS_ARE_LOCAL] = True
```

Some options carry their meaning purely by being present. RFC 4039 defines
Rapid Commit as "Code 80, Len 0", so it encodes no payload; delete the option
to express absence rather than assigning a false value.

```python
from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode

options = DHCPOptions()
options[DHCPOptionCode.RAPID_COMMIT] = True
```

## Fixed-width integer option

```python
from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode

options = DHCPOptions()
options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = 3600
```

## String option

```python
from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode

options = DHCPOptions()
options[DHCPOptionCode.HOSTNAME] = "workstation-01"
```

## Classless static route

```python
from ipaddress import ip_network

from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode
from ipaddress import IPv4Address as IPv4
from pydhcp.options import ClasslessRoute

options = DHCPOptions()
# RFC 3442 carries one or more routes, and a server sending option 121 SHOULD
# include the default route -- so this option is a list.
options[DHCPOptionCode.CLASSLESS_STATIC_ROUTE] = [
    ClasslessRoute(IPv4("192.0.2.1"), ip_network("0.0.0.0/0")),
    ClasslessRoute(IPv4("192.0.2.1"), ip_network("10.0.0.0/8")),
]
```

## Domain search list

```python
from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode

options = DHCPOptions()
options[DHCPOptionCode.DOMAIN_SEARCH] = ["example.internal", "lab.example.internal"]
```

## Decoded display

`DHCPOptions.items(decoded=True)` returns typed values, so `repr()` now shows the improved type-specific output.

```python
from ipaddress import ip_network

from pydhcp import DHCPOptions
from pydhcp.options import DHCPOptionCode
from ipaddress import IPv4Address as IPv4
from pydhcp.options import Boolean, ClasslessRoute

options = DHCPOptions()
options[DHCPOptionCode.RAPID_COMMIT] = True
options[DHCPOptionCode.CLASSLESS_STATIC_ROUTE] = [
    ClasslessRoute(IPv4("192.0.2.1"), ip_network("10.0.0.0/8")),
]

for code, value in options.items(decoded=True):
    print(code, repr(value))
```

## Which options are implemented

Every option code the library names, with the codec that reads and writes it, the RFC that
defines it and where the reading or writing departs from the RFC text. The table is generated
from the option registry (`python docs/options_table.py --write` regenerates it), and a test
fails when the page and the registry disagree.

<!-- options-table:begin -->
161 option codes are named, and a further two (0 and 255) frame the option stream. 123 of the named codes have a structured codec; the other 38 are carried as opaque `Bytes` (the octets are kept and forwarded unchanged). Any other code from 0 to 255 is also read as opaque `Bytes`.

| Code | Name | Codec | RFC | Departure from the RFC text |
| ---: | --- | --- | --- | --- |
| 0 | `PAD` | framing | RFC 2132 | Framing, not an option with a value: no codec. |
| 1 | `SUBNET_MASK` | `IPv4AddressOption` | RFC 2132 |  |
| 2 | `TIME_OFFSET` | `I32` | RFC 2132 |  |
| 3 | `ROUTER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 4 | `RFC868_TIMESERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 5 | `IEN116_NAMESERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 6 | `DNS` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 7 | `LOG_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 8 | `COOKIE_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 9 | `LPR_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 10 | `IMPRESS_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 11 | `RLP_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 12 | `HOSTNAME` | `String` | RFC 2132 |  |
| 13 | `BOOT_FILE_SIZE` | `U16` | RFC 2132 |  |
| 14 | `MERIT_DUMP_FILE` | `String` | RFC 2132 |  |
| 15 | `DOMAIN_NAME` | `String` | RFC 2132 |  |
| 16 | `SWAP_SERVER` | `IPv4AddressOption` | RFC 2132 |  |
| 17 | `ROOT_PATH` | `String` | RFC 2132 |  |
| 18 | `EXTENSION_FILE` | `String` | RFC 2132 |  |
| 19 | `IP_FORWARDING` | `Boolean` | RFC 2132 |  |
| 20 | `NON_LOCAL_SOURCE_ROUTING` | `Boolean` | RFC 2132 |  |
| 21 | `POLICY_FILTER` | `PolicyFilter` | RFC 2132 |  |
| 22 | `MAX_DATAGRAM_REASSEMBLY_SIZE` | `U16` | RFC 2132 |  |
| 23 | `IP_TTL` | `U8` | RFC 2132 |  |
| 24 | `MTU_TIMEOUT` | `U32` | RFC 2132 |  |
| 25 | `MTU_PLATEAU` | `List[U16]` | RFC 2132 |  |
| 26 | `INTERFACE_MTU` | `U16` | RFC 2132 |  |
| 27 | `ALL_SUBNETS_ARE_LOCAL` | `Boolean` | RFC 2132 |  |
| 28 | `BROADCAST_ADDRESS` | `IPv4AddressOption` | RFC 2132 |  |
| 29 | `MASK_DISCOVERY` | `Boolean` | RFC 2132 |  |
| 30 | `MASK_SUPPLIER` | `Boolean` | RFC 2132 |  |
| 31 | `ROUTER_DISCOVERY` | `Boolean` | RFC 2132 |  |
| 32 | `ROUTER_SOLICITATION_ADDRESS` | `IPv4AddressOption` | RFC 2132 |  |
| 33 | `STATIC_ROUTE` | `StaticRoute` | RFC 2132 | A route to `0.0.0.0` is read; building or writing one raises. |
| 34 | `TRAILER_ENCAPSULATION` | `Boolean` | RFC 2132 |  |
| 35 | `ARP_TIMEOUT` | `U32` | RFC 2132 |  |
| 36 | `ETHERNET_ENCAPSULATION` | `Boolean` | RFC 2132 |  |
| 37 | `TCP_DEFAULT_TTL` | `U8` | RFC 2132 |  |
| 38 | `TCP_KEEPALIVE_INTERVAL` | `U32` | RFC 2132 |  |
| 39 | `TCP_KEEPALIVE_GARBAGE` | `Boolean` | RFC 2132 |  |
| 40 | `NIS_DOMAIN` | `String` | RFC 2132 |  |
| 41 | `NIS_SERVERS` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 42 | `NTP_SERVERS` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 43 | `VENDOR_SPECIFIC_INFORMATION` | `VendorSpecificInformation` | RFC 2132 |  |
| 44 | `NBNS_SERVERS` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 45 | `NBDD_SERVERS` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 46 | `NETBIOS_NODE_TYPE` | `U8` | RFC 2132 |  |
| 47 | `NETBIOS_SCOPE` | `String` | RFC 2132 |  |
| 48 | `X_WINDOW_FONT_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 49 | `X_WINDOW_MANAGER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 50 | `REQUESTED_IP` | `IPv4AddressOption` | RFC 2132 |  |
| 51 | `IP_ADDRESS_LEASE_TIME` | `U32` | RFC 2132 |  |
| 52 | `OPTION_OVERLOAD` | `OptionOverload` | RFC 2132 |  |
| 53 | `DHCP_MESSAGE_TYPE` | `DHCPMessageType` | RFC 2132 |  |
| 54 | `SERVER_IDENTIFIER` | `IPv4AddressOption` | RFC 2132 |  |
| 55 | `PARAMETER_REQUEST_LIST` | `DHCPOptionCodes[DHCPOptionCode]` | RFC 2132 |  |
| 56 | `DHCP_MESSAGE` | `String` | RFC 2132 |  |
| 57 | `MAXIMUM_DHCP_MESSAGE_SIZE` | `U16` | RFC 2132 |  |
| 58 | `RENEWAL_TIME` | `U32` | RFC 2132 |  |
| 59 | `REBINDING_TIME` | `U32` | RFC 2132 |  |
| 60 | `VENDOR_CLASS_IDENTIFIER` | `OctetString` | RFC 2132 |  |
| 61 | `CLIENT_IDENTIFIER` | `ClientIdentifier` | RFC 2132 |  |
| 62 | `NETWARE_DOMAIN` | `Bytes` (opaque) | RFC 2242 |  |
| 63 | `NETWARE_OPTION` | `Bytes` (opaque) | RFC 2242 |  |
| 64 | `NIS_PLUS_DOMAIN` | `String` | RFC 2132 |  |
| 65 | `NIS_PLUS_SERVERS` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 66 | `TFTP_SERVER` | `String` | RFC 2132 |  |
| 67 | `BOOTFILE_NAME` | `String` | RFC 2132 |  |
| 68 | `HOME_AGENT_ADDRESSES` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 69 | `SMTP_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 70 | `POP3_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 71 | `NNTP_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 72 | `WWW_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 73 | `FINGER_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 74 | `IRC_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 75 | `STREETTALK_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 76 | `STDA_SERVER` | `List[IPv4AddressOption]` | RFC 2132 |  |
| 77 | `USER_CLASS` | `Bytes` (opaque) | RFC 3004 |  |
| 78 | `DIRECTORY_AGENT` | `Bytes` (opaque) | RFC 2610 |  |
| 79 | `SERVICE_SCOPE` | `Bytes` (opaque) | RFC 2610 |  |
| 80 | `RAPID_COMMIT` | `Flag` | RFC 4039 |  |
| 81 | `CLIENT_FQDN` | `ClientFQDN` | RFC 4702 |  |
| 82 | `RELAY_AGENT_INFORMATION` | `RelayAgentInformation` | RFC 3046 | Sub-options 0 and 255 are read as codes (RFC 3046 defines no pad and no end). |
| 83 | `ISNS` | `Bytes` (opaque) | RFC 4174 |  |
| 85 | `NDS_SERVERS` | `Bytes` (opaque) | RFC 2241 |  |
| 86 | `NDS_TREE_NAME` | `Bytes` (opaque) | RFC 2241 |  |
| 87 | `NDS_CONTEXT` | `Bytes` (opaque) | RFC 2241 |  |
| 88 | `BCMCS_DOMAIN_NAME_LIST` | `UncompressedDomainList` | RFC 4280 | Written uncompressed (RFC 4280 section 4.6). |
| 89 | `BCMCS_IPV4_ADDRESS` | `List[IPv4AddressOption]` | RFC 4280 |  |
| 90 | `AUTHENTICATION` | `Bytes` (opaque) | RFC 3118 |  |
| 91 | `CLIENT_LAST_TRANSACTION_TIME` | `U32` | RFC 4388 |  |
| 92 | `ASSOCIATED_IP` | `List[IPv4AddressOption]` | RFC 4388 |  |
| 93 | `CLIENT_SYSTEM_ARCHITECTURE` | `List[U16]` | RFC 4578 |  |
| 94 | `CLIENT_NDI` | `Bytes` (opaque) | RFC 4578 |  |
| 95 | `LDAP` | `Bytes` (opaque) | RFC 3679 |  |
| 97 | `UUID` | `Bytes` (opaque) | RFC 4578 |  |
| 98 | `USERAUTH` | `Bytes` (opaque) | RFC 2485 |  |
| 99 | `GEOCONF_CIVIC` | `Bytes` (opaque) | RFC 4776 |  |
| 100 | `PCODE` | `String` | RFC 4833 |  |
| 101 | `TCODE` | `String` | RFC 4833 |  |
| 108 | `IPV6_ONLY` | `U32` | RFC 8925 |  |
| 109 | `DHCP4_OVER_DHCP6_SOURCE_ADDRESS` | `Bytes` (opaque) | RFC 8539 |  |
| 112 | `NETINFO_ADDRESS` | `IPv4AddressOption` | RFC 3679 |  |
| 113 | `NETINFO_TAG` | `String` | RFC 3679 |  |
| 114 | `DHCP_CAPTIVE_PORTAL` | `String` | RFC 8910 |  |
| 116 | `AUTO_CONFIG` | `Boolean` | RFC 2563 |  |
| 117 | `NAME_SERVICE_SEARCH` | `List[U16]` | RFC 2937 |  |
| 118 | `SUBNET_SELECTION_OPTION` | `IPv4AddressOption` | RFC 3011 |  |
| 119 | `DOMAIN_SEARCH` | `DomainList` | RFC 3397 | Written compressed (RFC 3397). |
| 120 | `SIP_SERVERS` | `SIPServers` | RFC 3361 | Compressed names are read (RFC 3361); names are written uncompressed. |
| 121 | `CLASSLESS_STATIC_ROUTE` | `List[ClasslessRoute]` | RFC 3442 | A destination with host bits set is read with them zeroed; `ClasslessRoute(...)` stays strict. |
| 122 | `CCC` | `CCCOption` | RFC 3495 |  |
| 123 | `GEOCONF` | `Bytes` (opaque) | RFC 6225 |  |
| 124 | `VI_VENDOR_CLASS` | `VIVendorClass` | RFC 3925 |  |
| 125 | `VI_VENDOR_SPECIFIC_INFORMATION` | `VIVendorSpecificInformation` | RFC 3925 |  |
| 128 | `PXE_VENDOR_SPECIFIC_1` | `Bytes` (opaque) | RFC 4578 (reserved) |  |
| 129 | `PXE_VENDOR_SPECIFIC_2` | `Bytes` (opaque) | RFC 4578 (reserved) |  |
| 130 | `PXE_VENDOR_SPECIFIC_3` | `Bytes` (opaque) | RFC 4578 (reserved) |  |
| 131 | `PXE_VENDOR_SPECIFIC_4` | `Bytes` (opaque) | RFC 4578 (reserved) |  |
| 132 | `PXE_VENDOR_SPECIFIC_5` | `Bytes` (opaque) | RFC 4578 (reserved) |  |
| 133 | `PXE_VENDOR_SPECIFIC_6` | `Bytes` (opaque) | RFC 4578 (reserved) |  |
| 134 | `PXE_VENDOR_SPECIFIC_7` | `Bytes` (opaque) | RFC 4578 (reserved) |  |
| 135 | `PXE_VENDOR_SPECIFIC_8` | `Bytes` (opaque) | RFC 4578 (reserved) |  |
| 136 | `PANA_AGENT` | `Bytes` (opaque) | RFC 5192 |  |
| 137 | `V4_LOST` | `Bytes` (opaque) | RFC 5223 |  |
| 138 | `CAPWAP_AC_V4` | `List[IPv4AddressOption]` | RFC 5417 |  |
| 139 | `IPV4_ADDRESS_MOS` | `MoSIPv4AddressList` | RFC 5678 |  |
| 140 | `IPV4_FQDN_MOS` | `MoSFQDNList` | RFC 5678 |  |
| 141 | `SIP_UA_CONFIG_SERVICE_DOMAINS` | `DomainList` | RFC 6011 | Written compressed (RFC 3397). |
| 142 | `IPV4_ADDRESS_ANDSF` | `List[IPv4AddressOption]` | RFC 6153 |  |
| 143 | `V4_SZTP_REDIRECT` | `URIList` | RFC 8572 |  |
| 144 | `GEOLOC` | `Bytes` (opaque) | RFC 6225 |  |
| 145 | `FORCERENEW_NONCE_CAPABLE` | `List[U8]` | RFC 6704 |  |
| 146 | `RDNSS_SELECTION` | `RDNSSSelection` | RFC 6731 | Written uncompressed; the root name and the reserved flag bits are read as RFC 6731 allows. |
| 147 | `V4_DOTS_RI` | `DomainName` | RFC 8973 |  |
| 148 | `V4_DOTS_ADDRESS` | `List[IPv4AddressOption]` | RFC 8973 |  |
| 150 | `TFTP_SERVER_ADDRESS` | `List[IPv4AddressOption]` | RFC 5859 |  |
| 151 | `STATUS_CODE` | `StatusCode` | RFC 6926 |  |
| 152 | `BASE_TIME` | `U32` | RFC 6926 |  |
| 153 | `START_TIME_OF_STATE` | `U32` | RFC 6926 |  |
| 154 | `QUERY_START_TIME` | `U32` | RFC 6926 |  |
| 155 | `QUERY_END_TIME` | `U32` | RFC 6926 |  |
| 156 | `DHCP_STATE` | `U8` | RFC 6926 |  |
| 157 | `DATA_SOURCE` | `U8` | RFC 6926 |  |
| 158 | `V4_PCP_SERVER` | `PCPServerList` | RFC 7291 |  |
| 159 | `V4_PORTPARAMS` | `Bytes` (opaque) | RFC 7618 |  |
| 161 | `MUD_URL_V4` | `String` | RFC 8520 |  |
| 162 | `V4_DNR` | `Bytes` (opaque) | RFC 9463 |  |
| 175 | `ETHERBOOT` | `Bytes` (opaque) | none |  |
| 176 | `IP_TELEPHONE` | `Bytes` (opaque) | none |  |
| 177 | `LEGACY_CCC` | `Bytes` (opaque) | none |  |
| 208 | `PXE_LINUX_MAGIC` | `Bytes` (opaque) | RFC 5071 |  |
| 209 | `CONFIGURATION_FILE` | `String` | RFC 5071 |  |
| 210 | `PATH_PREFIX` | `String` | RFC 5071 |  |
| 211 | `REBOOT_TIME` | `U32` | RFC 5071 |  |
| 212 | `SIXRD` | `Bytes` (opaque) | RFC 5969 | `DHCPOptionCode.GRD` is an alias member of `SIXRD`. |
| 213 | `V4_ACCESS_DOMAIN` | `DomainName` | RFC 5986 |  |
| 220 | `SUBNET_ALLOCATION` | `Bytes` (opaque) | RFC 6656 |  |
| 221 | `VSS` | `Bytes` (opaque) | RFC 6607 |  |
| 249 | `MSFT_CLASSLESS_STATIC_ROUTE` | `List[ClasslessRoute]` | none | Microsoft's number for option 121; read like it. |
| 252 | `WPAD` | `String` | none |  |
| 254 | `ALL_VPNS` | `Bytes` (opaque) | none |  |
| 255 | `END` | framing | RFC 2132 | Framing, not an option with a value: no codec. |
<!-- options-table:end -->
