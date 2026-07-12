import pytest
import pytest
from pydhcp.options import DhcpOptions
from pydhcp.enum import DhcpOptionCode, DhcpMessageType
from pydhcp.optiontype import IPv4Address, U8, String, Bytes, Boolean

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
    assert DhcpOptionCode.TCP_KEEPALICE_GARBAGE is DhcpOptionCode.TCP_KEEPALIVE_GARBAGE
    assert DhcpOptionCode.NNTP_SERVER.name == "NNTP_SERVER"
    assert DhcpOptionCode.NNTP_SREVER is DhcpOptionCode.NNTP_SERVER

    opts = DhcpOptions()
    opts[DhcpOptionCode.LOG_SERVER] = ["10.0.0.1", "10.0.0.2"]
    opts[DhcpOptionCode.IP_FORWARDING] = 1
    assert isinstance(opts.get(DhcpOptionCode.LOG_SERVER)[0], IPv4Address)
    assert opts.get(DhcpOptionCode.IP_FORWARDING) == Boolean(1)


def test_register_type_rejects_invalid_type():
    with pytest.raises(TypeError):
        DhcpOptionCode.LOG_SERVER.register_type(int)  # type: ignore[arg-type]
