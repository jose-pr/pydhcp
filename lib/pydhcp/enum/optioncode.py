import typing as _ty
import enum as _enum

from .. import _options
from ..optiontype import Bytes


class DhcpOptionCode(_options.BaseDhcpOptionCode, _enum.IntEnum):
    __CODEMAP: list[type["_options.DhcpOptionType"]] = [Bytes] * 256

    def register_type(code, optiontype: type["_options.DhcpOptionType"]):
        DhcpOptionCode.__CODEMAP[code] = optiontype

    def get_type(code) -> "type[_options.DhcpOptionType]":
        return DhcpOptionCode.__CODEMAP[code]

    def label(code) -> str:
        label = getattr(code, "name", None)
        if not label:
            return _options.BaseDhcpOptionCode.label(code)
        return label

    #
    #   VENDOR EXTENSIONS
    #   DEFINED in RFC 1497
    #
    PAD = 0
    """The pad option can be used to cause subsequent fields to align on
   word boundaries.

   The code for the pad option is 0, and its length is 1 octet."""
    SUBNET_MASK = 1
    """The subnet mask option specifies the client's subnet mask as per RFC
   950.
   If both the subnet mask and the router option are specified in a DHCP
   reply, the subnet mask option MUST be first.

   The code for the subnet mask option is 1, and its length is 4 octets."""
    TIME_OFFSET = 2
    """The time offset field specifies the offset of the client's subnet in
   seconds from Coordinated Universal Time (UTC).  The offset is
   expressed as a two's complement 32-bit integer.  A positive offset
   indicates a location east of the zero meridian and a negative offset
   indicates a location west of the zero meridian.

   The code for the time offset option is 2, and its length is 4 octets."""
    ROUTER = 3
    """The router option specifies a list of IP addresses for routers on the
   client's subnet.  Routers SHOULD be listed in order of preference.

   The code for the router option is 3.  The minimum length for the
   router option is 4 octets, and the length MUST always be a multiple
   of 4."""
    RFC868_TIMESERVER = 4
    """The time server option specifies a list of RFC 868 time servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the time server option is 4.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4."""
    IEN116_NAMESERVER = 5
    """The name server option specifies a list of IEN 116 [7] name servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the name server option is 5.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4."""
    DNS = 6
    """The domain name server option specifies a list of Domain Name System
   (STD 13, RFC 1035 [8]) name servers available to the client.  Servers
   SHOULD be listed in order of preference.

   The code for the domain name server option is 6.  The minimum length
   for this option is 4 octets, and the length MUST always be a multiple
   of 4."""
    LOG_SERVER = 7
    """The log server option specifies a list of MIT-LCS UDP log servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the log server option is 7.  The minimum length for this
   option is 4 octets, and the length MUST always be a multiple of 4."""
    COOKIE_SERVER = 8
    """ The cookie server option specifies a list of RFC 865 [9] cookie
   servers available to the client.  Servers SHOULD be listed in order
   of preference.

   The code for the log server option is 8.  The minimum length for this
   option is 4 octets, and the length MUST always be a multiple of 4."""
    LPR_SERVER = 9
    """The LPR server option specifies a list of RFC 1179 [10] line printer
   servers available to the client.  Servers SHOULD be listed in order
   of preference.

   The code for the LPR server option is 9.  The minimum length for this
   option is 4 octets, and the length MUST always be a multiple of 4."""
    IMPRESS_SERVER = 10
    """  The Impress server option specifies a list of Imagen Impress servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the Impress server option is 10.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4."""
    RLP_SERVER = 11
    """his option specifies a list of RFC 887 [11] Resource Location
   servers available to the client.  Servers SHOULD be listed in order
   of preference.

   The code for this option is 11.  The minimum length for this option
   is 4 octets, and the length MUST always be a multiple of 4."""
    HOSTNAME = 12
    """This option specifies the name of the client.  The name may or may
   not be qualified with the local domain name (see section 3.17 for the
   preferred way to retrieve the domain name).  See RFC 1035 for
   character set restrictions.

   The code for this option is 12, and its minimum length is 1."""
    BOOT_FILE_SIZE = 13
    """This option specifies the length in 512-octet blocks of the default
   boot image for the client.  The file length is specified as an
   unsigned 16-bit integer.

   The code for this option is 13, and its length is 2."""
    MERIT_DUMP_FILE = 14
    """This option specifies the path-name of a file to which the client's
   core image should be dumped in the event the client crashes.  The
   path is formatted as a character string consisting of characters from
   the NVT ASCII character set.

   The code for this option is 14.  Its minimum length is 1."""
    DOMAIN_NAME = 15
    """This option specifies the domain name that client should use when
   resolving hostnames via the Domain Name System.

   The code for this option is 15.  Its minimum length is 1."""
    SWAP_SERVER = 16
    """This specifies the IP address of the client's swap server.

   The code for this option is 16 and its length is 4."""
    ROOT_PATH = 17
    """This option specifies the path-name that contains the client's root
   disk.  The path is formatted as a character string consisting of
   characters from the NVT ASCII character set.

   The code for this option is 17.  Its minimum length is 1."""
    EXTENSION_FILE = 18
    """A string to specify a file, retrievable via TFTP, which contains
   information which can be interpreted in the same way as the 64-octet
   vendor-extension field within the BOOTP response, with the following
   exceptions:
          - the length of the file is unconstrained;
          - all references to Tag 18 (i.e., instances of the
            BOOTP Extensions Path field) within the file are
            ignored.

   The code for this option is 18.  Its minimum length is 1."""
    #
    # IP Layer Parameters per Host
    # This section details the options that affect the operation of the IP
    # layer on a per-host basis.
    #
    IP_FORWARDING = 19
    """This option specifies whether the client should configure its IP
   layer for packet forwarding.  A value of 0 means disable IP
   forwarding, and a value of 1 means enable IP forwarding.

   The code for this option is 19, and its length is 1."""
    NON_LOCAL_SOURCE_ROUTING = 20
    """This option specifies whether the client should configure its IP
   layer to allow forwarding of datagrams with non-local source routes
   (see Section 3.3.5 of [4] for a discussion of this topic).  A value
   of 0 means disallow forwarding of such datagrams, and a value of 1
   means allow forwarding.

   The code for this option is 20, and its length is 1."""
    POLICY_FILTER = 21
    """This option specifies policy filters for non-local source routing.
   The filters consist of a list of IP addresses and masks which specify
   destination/mask pairs with which to filter incoming source routes.

   Any source routed datagram whose next-hop address does not match one
   of the filters should be discarded by the client.

   The code for this option is 21.  The minimum length of this option is
   8, and the length MUST be a multiple of 8."""
    MAX_DATAGRAM_REASSEMBLY_SIZE = 22
    """This option specifies the maximum size datagram that the client
   should be prepared to reassemble.  The size is specified as a 16-bit
   unsigned integer.  The minimum value legal value is 576.

   The code for this option is 22, and its length is 2."""
    IP_TTL = 23
    """This option specifies the default time-to-live that the client should
   use on outgoing datagrams.  The TTL is specified as an octet with a
   value between 1 and 255.

   The code for this option is 23, and its length is 1."""
    MTU_TIMEOUT = 24
    """This option specifies the timeout (in seconds) to use when aging Path
   MTU values discovered by the mechanism defined in RFC 1191 [12].  The
   timeout is specified as a 32-bit unsigned integer.

   The code for this option is 24, and its length is 4."""
    MTU_PLATEAU = 25
    """This option specifies a table of MTU sizes to use when performing
   Path MTU Discovery as defined in RFC 1191.  The table is formatted as
   a list of 16-bit unsigned integers, ordered from smallest to largest.
   The minimum MTU value cannot be smaller than 68.

   The code for this option is 25.  Its minimum length is 2, and the
   length MUST be a multiple of 2."""

    #
    #   IP Layer Parameters per Interface
    #
    # This section details the options that affect the operation of the IP
    # layer on a per-interface basis.  It is expected that a client can
    # issue multiple requests, one per interface, in order to configure
    # interfaces with their specific parameters.
    #
    INTERFACE_MTU = 26
    """ This option specifies the MTU to use on this interface.  The MTU is
   specified as a 16-bit unsigned integer.  The minimum legal value for
   the MTU is 68.

   The code for this option is 26, and its length is 2."""
    ALL_SUBNETS_ARE_LOCAL = 27
    """This option specifies whether or not the client may assume that all
   subnets of the IP network to which the client is connected use the
   same MTU as the subnet of that network to which the client is
   directly connected.  A value of 1 indicates that all subnets share
   the same MTU.  A value of 0 means that the client should assume that
   some subnets of the directly connected network may have smaller MTUs.

   The code for this option is 27, and its length is 1."""
    BROADCAST_ADDRESS = 28
    """   This option specifies the broadcast address in use on the client's
   subnet.  Legal values for broadcast addresses are specified in
   section 3.2.1.3 of [4].

   The code for this option is 28, and its length is 4."""
    MASK_DISCOVERY = 29
    """ This option specifies whether or not the client should perform subnet
   mask discovery using ICMP.  A value of 0 indicates that the client
   should not perform mask discovery.  A value of 1 means that the
   client should perform mask discovery.

   The code for this option is 29, and its length is 1."""
    MASK_SUPPLIER = 30
    """This option specifies whether or not the client should respond to
   subnet mask requests using ICMP.  A value of 0 indicates that the
   client should not respond.  A value of 1 means that the client should
   respond.

   The code for this option is 30, and its length is 1."""
    ROUTER_DISCOVERY = 31
    """This option specifies whether or not the client should solicit
   routers using the Router Discovery mechanism defined in RFC 1256
   [13].  A value of 0 indicates that the client should not perform
   router discovery.  A value of 1 means that the client should perform
   router discovery.

   The code for this option is 31, and its length is 1."""
    ROUTER_SOLICITATION_ADDRESS = 32
    """This option specifies the address to which the client should transmit
   router solicitation requests.

   The code for this option is 32, and its length is 4."""
    STATIC_ROUTE = 33
    """ This option specifies a list of static routes that the client should
   install in its routing cache.  If multiple routes to the same
   destination are specified, they are listed in descending order of
   priority.

   The routes consist of a list of IP address pairs.  The first address
   is the destination address, and the second address is the router for
   the destination.

   The default route (0.0.0.0) is an illegal destination for a static
   route.  See section 3.5 for information about the router option.

   The code for this option is 33.  The minimum length of this option is
   8, and the length MUST be a multiple of 8."""

    #
    #   Link Layer Parameters per Interface
    # This section lists the options that affect the operation of the data
    # link layer on a per-interface basis.
    #
    #

    TRAILER_ENCAPSULATION = 34
    """This option specifies whether or not the client should negotiate the
   use of trailers (RFC 893 [14]) when using the ARP protocol.  A value
   of 0 indicates that the client should not attempt to use trailers.  A
   value of 1 means that the client should attempt to use trailers.

   The code for this option is 34, and its length is 1."""
    ARP_TIMEOUT = 35
    """ This option specifies the timeout in seconds for ARP cache entries.
   The time is specified as a 32-bit unsigned integer.

   The code for this option is 35, and its length is 4."""
    ETHERNET_ENCAPSULATION = 36
    """This option specifies whether or not the client should use Ethernet
   Version 2 (RFC 894 [15]) or IEEE 802.3 (RFC 1042 [16]) encapsulation
   if the interface is an Ethernet.  A value of 0 indicates that the
   client should use RFC 894 encapsulation.  A value of 1 means that the
   client should use RFC 1042 encapsulation.

   The code for this option is 36, and its length is 1."""

    #
    #
    #   TCP Parameters:
    #
    #    This section lists the options that affect the operation of the TCP
    #    layer on a per-interface basis.
    #
    #
    TCP_DEFAULT_TTL = 37
    """This option specifies the default TTL that the client should use when
   sending TCP segments.  The value is represented as an 8-bit unsigned
   integer.  The minimum value is 1.

   The code for this option is 37, and its length is 1."""
    TCP_KEEPALIVE_INTERVAL = 38
    """This option specifies the interval (in seconds) that the client TCP
   should wait before sending a keepalive message on a TCP connection.
   The time is specified as a 32-bit unsigned integer.  A value of zero
   indicates that the client should not generate keepalive messages on
   connections unless specifically requested by an application.

   The code for this option is 38, and its length is 4."""

    TCP_KEEPALICE_GARBAGE = 39
    """This option specifies the whether or not the client should send TCP
   keepalive messages with a octet of garbage for compatibility with
   older implementations.  A value of 0 indicates that a garbage octet
   should not be sent. A value of 1 indicates that a garbage octet
   should be sent.

   The code for this option is 39, and its length is 1."""

    #
    #
    #   Application and Service Parameters:
    #
    #    This section details some miscellaneous options used to configure
    #    miscellaneous applications and services.
    #
    #

    NIS_DOMAIN = 40
    """   This option specifies the name of the client's NIS [17] domain.  The
   domain is formatted as a character string consisting of characters
   from the NVT ASCII character set.

   The code for this option is 40.  Its minimum length is 1."""

    NIS_SERVERS = 41
    """This option specifies a list of IP addresses indicating NIS servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for this option is 41.  Its minimum length is 4, and the
   length MUST be a multiple of 4."""
    NTP_SERVERS = 42
    """This option specifies a list of IP addresses indicating NTP [18]
   servers available to the client.  Servers SHOULD be listed in order
   of preference.

   The code for this option is 42.  Its minimum length is 4, and the
   length MUST be a multiple of 4."""
    VENDOR_SPECIFIC_INFORMATION = 43
    """This option is used by clients and servers to exchange vendor-
   specific information.  The information is an opaque object of n
   octets, presumably interpreted by vendor-specific code on the clients
   and servers.  The definition of this information is vendor specific.
   The vendor is indicated in the vendor class identifier option.
   Servers not equipped to interpret the vendor-specific information
   sent by a client MUST ignore it (although it may be reported).
   Clients which do not receive desired vendor-specific information
   SHOULD make an attempt to operate without it, although they may do so
   (and announce they are doing so) in a degraded mode.

   If a vendor potentially encodes more than one item of information in
   this option, then the vendor SHOULD encode the option using
   "Encapsulated vendor-specific options" as described below:

   The Encapsulated vendor-specific options field SHOULD be encoded as a
   sequence of code/length/value fields of identical syntax to the DHCP
   options field with the following exceptions:

      1) There SHOULD NOT be a "magic cookie" field in the encapsulated
         vendor-specific extensions field.

      2) Codes other than 0 or 255 MAY be redefined by the vendor within
         the encapsulated vendor-specific extensions field, but SHOULD
         conform to the tag-length-value syntax defined in section 2.

      3) Code 255 (END), if present, signifies the end of the
         encapsulated vendor extensions, not the end of the vendor
         extensions field. If no code 255 is present, then the end of
         the enclosing vendor-specific information field is taken as the
         end of the encapsulated vendor-specific extensions field.

   The code for this option is 43 and its minimum length is 1."""
    NBNS_SERVERS = 44
    """The NetBIOS name server (NBNS) option specifies a list of RFC
   1001/1002 [19] [20] NBNS name servers listed in order of preference.

   The code for this option is 44.  The minimum length of the option is
   4 octets, and the length must always be a multiple of 4."""
    NBDD_SERVERS = 45
    """The NetBIOS datagram distribution server (NBDD) option specifies a
   list of RFC 1001/1002 NBDD servers listed in order of preference. The
   code for this option is 45.  The minimum length of the option is 4
   octets, and the length must always be a multiple of 4."""
    NETBIOS_NODE_TYPE = 46
    """   The NetBIOS node type option allows NetBIOS over TCP/IP clients which
   are configurable to be configured as described in RFC 1001/1002.  The
   value is specified as a single octet which identifies the client type
   as follows:

      Value         Node Type

      -----         ---------
      
      0x1           B-node
      
      0x2           P-node
      
      0x4           M-node
      
      0x8           H-node

   In the above chart, the notation '0x' indicates a number in base-16
   (hexadecimal).

   The code for this option is 46.  The length of this option is always
   1."""
    NETBIOS_SCOPE = 47
    """
   The NetBIOS scope option specifies the NetBIOS over TCP/IP scope
   parameter for the client as specified in RFC 1001/1002. See [19],
   [20], and [8] for character-set restrictions.

   The code for this option is 47.  The minimum length of this option is
   1."""
    X_WINDOW_FONT_SERVER = 48
    """This option specifies a list of X Window System [21] Font servers
   available to the client. Servers SHOULD be listed in order of
   preference.

   The code for this option is 48.  The minimum length of this option is
   4 octets, and the length MUST be a multiple of 4."""
    X_WINDOW_MANAGER = 49
    """This option specifies a list of IP addresses of systems that are
   running the X Window System Display Manager and are available to the
   client.

   Addresses SHOULD be listed in order of preference.

   The code for the this option is 49. The minimum length of this option
   is 4, and the length MUST be a multiple of 4."""
    NETWARE_DOMAIN = 62
    NETWARE_OPTION = 63
    NIS_PLUS_DOMAIN = 64
    """ This option specifies the name of the client's NIS+ [17] domain.  The
   domain is formatted as a character string consisting of characters
   from the NVT ASCII character set.

   The code for this option is 64.  Its minimum length is 1."""
    NIS_PLUS_SERVERS = 65
    """ This option specifies a list of IP addresses indicating NIS+ servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for this option is 65.  Its minimum length is 4, and the
   length MUST be a multiple of 4."""
    HOME_AGENT_ADDRESSES = 68
    """This option specifies a list of IP addresses indicating mobile IP
   home agents available to the client.  Agents SHOULD be listed in
   order of preference.

   The code for this option is 68.  Its minimum length is 0 (indicating
   no home agents are available) and the length MUST be a multiple of 4.
   It is expected that the usual length will be four octets, containing
   a single home agent's address."""
    SMTP_SERVER = 69
    """The SMTP server option specifies a list of SMTP servers available to
   the client.  Servers SHOULD be listed in order of preference.

   The code for the SMTP server option is 69.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4."""
    POP3_SERVER = 70
    """ The POP3 server option specifies a list of POP3 available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the POP3 server option is 70.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4."""
    NNTP_SREVER = 71
    """
   The NNTP server option specifies a list of NNTP available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the NNTP server option is 71. The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4."""
    WWW_SERVER = 72
    """The WWW server option specifies a list of WWW available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the WWW server option is 72.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4."""
    FINGER_SERVER = 73
    """   The Finger server option specifies a list of Finger available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the Finger server option is 73.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4."""
    IRC_SERVER = 74
    """The IRC server option specifies a list of IRC available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the IRC server option is 74.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4."""
    STREETTALK_SERVER = 75
    """The StreetTalk server option specifies a list of StreetTalk servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the StreetTalk server option is 75.  The minimum length
   for this option is 4 octets, and the length MUST always be a multiple
   of 4."""
    STDA_SERVER = 76
    """ The StreetTalk Directory Assistance (STDA) server option specifies a
   list of STDA servers available to the client.  Servers SHOULD be
   listed in order of preference.

   The code for the StreetTalk Directory Assistance server option is 76.
   The minimum length for this option is 4 octets, and the length MUST
   always be a multiple of 4."""

    #
    #
    # DHCP Extensions:
    #   This section details the options that are specific to DHCP.
    #

    REQUESTED_IP = 50
    """This option is used in a client request (DHCPDISCOVER) to allow the
   client to request that a particular IP address be assigned.

   The code for this option is 50, and its length is 4."""
    IP_ADDRESS_LEASE_TIME = 51
    """This option is used in a client request (DHCPDISCOVER or DHCPREQUEST)
   to allow the client to request a lease time for the IP address.  In a
   server reply (DHCPOFFER), a DHCP server uses this option to specify
   the lease time it is willing to offer.

   The time is in units of seconds, and is specified as a 32-bit
   unsigned integer.

   The code for this option is 51, and its length is 4."""
    OPTION_OVERLOAD = 52
    """   This option is used to indicate that the DHCP 'sname' or 'file'
   fields are being overloaded by using them to carry DHCP options. A
   DHCP server inserts this option if the returned parameters will
   exceed the usual space allotted for options.

   If this option is present, the client interprets the specified
   additional fields after it concludes interpretation of the standard
   option fields.

   The code for this option is 52, and its length is 1.  Legal values
   for this option are:

           Value   Meaning
           -----   --------
             1     the 'file' field is used to hold options
             2     the 'sname' field is used to hold options
             3     both fields are used to hold options"""
    DHCP_MESSAGE_TYPE = 53
    """   This option is used to convey the type of the DHCP message.  The code
   for this option is 53, and its length is 1.  Legal values for this
   option are:

           Value   Message Type
           -----   ------------
             1     DHCPDISCOVER
             2     DHCPOFFER
             3     DHCPREQUEST
             4     DHCPDECLINE
             5     DHCPACK
             6     DHCPNAK
             7     DHCPRELEASE
             8     DHCPINFORM"""
    SERVER_IDENTIFIER = 54
    """This option is used in DHCPOFFER and DHCPREQUEST messages, and may
   optionally be included in the DHCPACK and DHCPNAK messages.  DHCP
   servers include this option in the DHCPOFFER in order to allow the
   client to distinguish between lease offers.  DHCP clients use the
   contents of the 'server identifier' field as the destination address
   for any DHCP messages unicast to the DHCP server.  DHCP clients also
   indicate which of several lease offers is being accepted by including
   this option in a DHCPREQUEST message.

   The identifier is the IP address of the selected server.

   The code for this option is 54, and its length is 4."""
    PARAMETER_REQUEST_LIST = 55
    """This option is used by a DHCP client to request values for specified
   configuration parameters.  The list of requested parameters is
   specified as n octets, where each octet is a valid DHCP option code
   as defined in this document.

   The client MAY list the options in order of preference.  The DHCP
   server is not required to return the options in the requested order,
   but MUST try to insert the requested options in the order requested
   by the client.

   The code for this option is 55.  Its minimum length is 1."""
    DHCP_MESSAGE = 56
    """   This option is used by a DHCP server to provide an error message to a
   DHCP client in a DHCPNAK message in the event of a failure. A client
   may use this option in a DHCPDECLINE message to indicate the why the
   client declined the offered parameters.  The message consists of n
   octets of NVT ASCII text, which the client may display on an
   available output device.

   The code for this option is 56 and its minimum length is 1."""
    MAXIMUM_DHCP_MESSAGE_SIZE = 57
    """
   This option specifies the maximum length DHCP message that it is
   willing to accept.  The length is specified as an unsigned 16-bit
   integer.  A client may use the maximum DHCP message size option in
   DHCPDISCOVER or DHCPREQUEST messages, but should not use the option
   in DHCPDECLINE messages.

   The code for this option is 57, and its length is 2.  The minimum
   legal value is 576 octets."""
    RENEWAL_TIME = 58
    """ This option specifies the time interval from address assignment until
   the client transitions to the RENEWING state.

   The value is in units of seconds, and is specified as a 32-bit
   unsigned integer.

   The code for this option is 58, and its length is 4."""
    REBINDING_TIME = 59
    """This option specifies the time interval from address assignment until
   the client transitions to the REBINDING state.

   The value is in units of seconds, and is specified as a 32-bit
   unsigned integer.

   The code for this option is 59, and its length is 4."""
    VENDOR_CLASS_IDENTIFIER = 60
    """ This option is used by DHCP clients to optionally identify the vendor
   type and configuration of a DHCP client.  The information is a string
   of n octets, interpreted by servers.  Vendors may choose to define
   specific vendor class identifiers to convey particular configuration
   or other identification information about a client.  For example, the
   identifier may encode the client's hardware configuration.  Servers
   not equipped to interpret the class-specific information sent by a
   client MUST ignore it (although it may be reported). Servers that

   respond SHOULD only use option 43 to return the vendor-specific
   information to the client.

   The code for this option is 60, and its minimum length is 1."""
    CLIENT_IDENTIFIER = 61
    """  This option is used by DHCP clients to specify their unique
   identifier.  DHCP servers use this value to index their database of
   address bindings.  This value is expected to be unique for all
   clients in an administrative domain.

   Identifiers SHOULD be treated as opaque objects by DHCP servers.

   The client identifier MAY consist of type-value pairs similar to the
   'htype'/'chaddr' fields defined in [3]. For instance, it MAY consist
   of a hardware type and hardware address. In this case the type field
   SHOULD be one of the ARP hardware types defined in STD2 [22].  A
   hardware type of 0 (zero) should be used when the value field
   contains an identifier other than a hardware address (e.g. a fully
   qualified domain name).

   For correct identification of clients, each client's client-
   identifier MUST be unique among the client-identifiers used on the
   subnet to which the client is attached.  Vendors and system
   administrators are responsible for choosing client-identifiers that
   meet this requirement for uniqueness.

   The code for this option is 61, and its minimum length is 2."""
    TFTP_SERVER = 66
    """This option is used to identify a TFTP server when the 'sname' field
   in the DHCP header has been used for DHCP options.

   The code for this option is 66, and its minimum length is 1."""
    BOOTFILE_NAME = 67
    """This option is used to identify a bootfile when the 'file' field in
   the DHCP header has been used for DHCP options.

   The code for this option is 67, and its minimum length is 1."""

    #
    # EXTRAS
    #
    USER_CLASS = 77
    DIRECTORY_AGENT = 78
    SERVICE_SCOPE = 79
    RAPID_COMMIT = 80
    CLIENT_FQDN = 81
    RELAY_AGENT_INFORMATION = 82
    ISNS = 83
    # 85 UNASSIGNED
    NDS_SERVERS = 85
    NDS_TREE_NAME = 86
    NDS_CONTEXT = 87
    BCMCS_DOMAIN_NAME_LIST = 88
    BCMCS_IPV4_ADDRESS = 89
    AUTHENTICATION = 90
    CLIENT_LAST_TRANSACTION_TIME = 91
    ASSOCIATED_IP = 92
    CLIENT_SYSTEM_ARCHITECTURE = 93
    CLIENT_NDI = 94
    LDAP = 95

    # 96 UNASSIGNED
    UUID = 97
    USERAUTH = 98
    GEOCONF_CIVIC = 99
    PCODE = 100
    TCODE = 101
    # 102-107 UNASSIGNED
    IPV6_ONLY = 108
    DHCP4_OVER_DHCP6_SOURCE_ADDRESS = 109
    # 110-111 UNASSIGNED
    NETINFO_ADDRESS = 112
    NETINFO_TAG = 113
    DHCP_CAPTIVE_PORTAL = 114
    # 115
    AUTO_CONFIG = 116
    NAME_SERVICE_SEARCH = 117
    SUBNET_SELECTION_OPTION = 118
    DOMAIN_SEARCH = 119
    SIP_SERVERS = 120
    CLASSLESS_STATIC_ROUTE = 121
    CCC = 122
    GEOCONF = 123
    VI_VENDOR_CLASS = 124
    VI_VENDOR_SPECIFIC_INFORMATION = 125
    # 126-127
    PXE_VENDOR_SPECIFIC_1 = 128
    """ VENDOR SPECIFIC 128-135
    """
    PXE_VENDOR_SPECIFIC_2 = 129
    PXE_VENDOR_SPECIFIC_3 = 130
    PXE_VENDOR_SPECIFIC_4 = 131
    PXE_VENDOR_SPECIFIC_5 = 132
    PXE_VENDOR_SPECIFIC_6 = 133
    PXE_VENDOR_SPECIFIC_7 = 134
    PXE_VENDOR_SPECIFIC_8 = 135
    PANA_AGENT = 136
    V4_LOST = 137
    CAPWAP_AC_V4 = 138
    IPV4_ADDRESS_MOS = 139
    IPV4_FQDN_MOS = 140
    SIP_UA_CONFIG_SERVICE_DOMAINS = 141
    IPV4_ADDRESS_ANDSF = 142
    V4_SZTP_REDIRECT = 143
    GEOLOC = 144
    FORCERENEW_NONCE_CAPABLE = 145
    RDNSS_SELECTION = 146
    V4_DOTS_RI = 147
    V4_DOTS_ADDRESS = 148
    # 149
    TFTP_SERVER_ADDRESS = 150
    """Can replace siaddr and also provide multiple addresses instead of just one. Only IP Address
    
    May also be use by ETHERBOOT

    GRUB configuration path name
    """
    STATUS_CODE = 151
    BASE_TIME = 152
    START_TIME_OF_STATE = 153
    QUERY_START_TIME = 154
    QUERY_END_TIME = 155
    DHCP_STATE = 156
    DATA_SOURCE = 157
    V4_PCP_SERVER = 158
    V4_PORTPARAMS = 159
    # 160
    MUD_URL_V4 = 161
    V4_DNR = 162
    # 163-174
    ETHERBOOT = 175
    IP_TELEPHONE = 176
    LEGACY_CCC = 177
    # 178-207
    PXE_LINUX_MAGIC = 208
    """magic string = F1:00:74:7E"""
    CONFIGURATION_FILE = 209
    PATH_PREFIX = 210
    REBOOT_TIME = 211
    GRD = 212
    V4_ACCESS_DOMAIN = 213
    # 214-219
    SUBNET_ALLOCATION = 220
    VSS = 221
    # 222-223
    # 224-254 PRIVATE USE
    MSFT_CLASSLESS_STATIC_ROUTE = 249
    WPAD = 252 
    END = 255
    """The end option marks the end of valid information in the vendor
   field.  Subsequent octets should be filled with pad options.

   The code for the end option is 255, and its length is 1 octet."""
