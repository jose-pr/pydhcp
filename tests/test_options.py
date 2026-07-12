import pytest
from pydhcp.options import DhcpOptions
from pydhcp.enum import DhcpOptionCode, DhcpMessageType
from pydhcp.optiontype import IPv4Address, String, Boolean

def test_options_set_get():
    opts = DhcpOptions()
    
    # Test setting enum / DhcpOptionType
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    assert opts.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPDISCOVER
    
    # Test setting raw bytes
    opts[DhcpOptionCode.ROUTER] = b"\xc0\xa8\x01\x01" # 192.168.1.1
    # Test decoding with type
    from pydhcp.netutils import IPv4
    assert opts.get(DhcpOptionCode.ROUTER, decode=IPv4Address) == IPv4("192.168.1.1")
    
    # Test missing / default
    assert opts.get(999, default="hello") == "hello"

def test_options_partial_encode():
    opts = DhcpOptions()
    opts[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    opts[DhcpOptionCode.HOSTNAME] = "test-host"
    
    encoded = opts.encode()
    assert len(encoded) > 0
    assert encoded[-1] == 255 # END mark
    
    # Decode back
    decoded_opts = DhcpOptions()
    decoded_opts.decode(memoryview(encoded))
    assert decoded_opts.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == DhcpMessageType.DHCPDISCOVER
    assert decoded_opts.get(DhcpOptionCode.HOSTNAME, decode=String) == "test-host"


def test_typed_registrations_and_aliases():
    assert DhcpOptionCode.TCP_KEEPALIVE_GARBAGE.name == "TCP_KEEPALIVE_GARBAGE"
    assert DhcpOptionCode.NNTP_SERVER.name == "NNTP_SERVER"
    assert DhcpOptionCode.RFC868_TIMESERVER.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.SWAP_SERVER.get_type() is IPv4Address
    assert DhcpOptionCode.NETBIOS_SCOPE.get_type() is String
    assert DhcpOptionCode.LOG_SERVER.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.SIP_SERVERS.get_type()._args_[0] is IPv4Address
    assert DhcpOptionCode.RAPID_COMMIT.get_type() is Boolean
    assert DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL.get_type() is Boolean
    assert DhcpOptionCode.TRAILER_ENCAPSULATION.get_type() is Boolean
    assert DhcpOptionCode.FORCERENEW_NONCE_CAPABLE.get_type() is Boolean
    assert DhcpOptionCode.MERIT_DUMP_FILE.get_type() is String
    assert DhcpOptionCode.ARP_TIMEOUT.get_type().__name__ == "U32"
    assert DhcpOptionCode.STATUS_CODE.get_type().__name__ == "U8"

    opts = DhcpOptions()
    opts[DhcpOptionCode.LOG_SERVER] = ["10.0.0.1", "10.0.0.2"]
    opts[DhcpOptionCode.RFC868_TIMESERVER] = ["10.0.0.4"]
    opts[DhcpOptionCode.IEN116_NAMESERVER] = ["10.0.0.5"]
    opts[DhcpOptionCode.SWAP_SERVER] = "10.0.0.6"
    opts[DhcpOptionCode.SIP_SERVERS] = ["10.0.0.3"]
    opts[DhcpOptionCode.IP_FORWARDING] = 1
    opts[DhcpOptionCode.RAPID_COMMIT] = True
    opts[DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL] = False
    opts[DhcpOptionCode.TRAILER_ENCAPSULATION] = 1
    opts[DhcpOptionCode.FORCERENEW_NONCE_CAPABLE] = 1
    assert isinstance(opts.get(DhcpOptionCode.LOG_SERVER)[0], IPv4Address)
    assert isinstance(opts.get(DhcpOptionCode.RFC868_TIMESERVER)[0], IPv4Address)
    assert isinstance(opts.get(DhcpOptionCode.IEN116_NAMESERVER)[0], IPv4Address)
    assert opts.get(DhcpOptionCode.SWAP_SERVER) == IPv4Address("10.0.0.6")
    assert isinstance(opts.get(DhcpOptionCode.SIP_SERVERS)[0], IPv4Address)
    assert opts.get(DhcpOptionCode.IP_FORWARDING) == Boolean(1)
    assert opts.get(DhcpOptionCode.RAPID_COMMIT) == Boolean(1)
    assert opts.get(DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL) == Boolean(0)
    assert opts.get(DhcpOptionCode.TRAILER_ENCAPSULATION) == Boolean(1)
    assert opts.get(DhcpOptionCode.FORCERENEW_NONCE_CAPABLE) == Boolean(1)

    opts[DhcpOptionCode.MERIT_DUMP_FILE] = "core.dump"
    assert opts.get(DhcpOptionCode.MERIT_DUMP_FILE, decode=String) == "core.dump"


def test_registered_option_code_round_trips():
    opts = DhcpOptions()
    opts[DhcpOptionCode.SIP_SERVERS] = ["192.0.2.10", "192.0.2.11"]
    opts[DhcpOptionCode.RFC868_TIMESERVER] = ["192.0.2.12"]
    opts[DhcpOptionCode.SWAP_SERVER] = "192.0.2.13"
    opts[DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL] = True
    opts[DhcpOptionCode.MERIT_DUMP_FILE] = "crash.dump"
    opts[DhcpOptionCode.STATUS_CODE] = 7

    encoded = opts.encode()
    decoded = DhcpOptions()
    decoded.decode(memoryview(encoded))

    assert decoded.get(DhcpOptionCode.SIP_SERVERS)[0] == IPv4Address("192.0.2.10")
    assert decoded.get(DhcpOptionCode.RFC868_TIMESERVER)[0] == IPv4Address("192.0.2.12")
    assert decoded.get(DhcpOptionCode.SWAP_SERVER) == IPv4Address("192.0.2.13")
    assert decoded.get(DhcpOptionCode.ALL_SUBNETS_ARE_LOCAL) == Boolean(1)
    assert decoded.get(DhcpOptionCode.MERIT_DUMP_FILE, decode=String) == "crash.dump"
    assert decoded.get(DhcpOptionCode.STATUS_CODE) == 7


def test_register_type_rejects_invalid_type():
    with pytest.raises(TypeError):
        DhcpOptionCode.LOG_SERVER.register_type(int)  # type: ignore[arg-type]
