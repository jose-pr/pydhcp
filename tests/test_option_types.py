import pytest
import logging
from pydhcp.optiontype import (
    IPv4Address,
    String,
    Boolean,
    U8,
    U16,
    U32,
    ClasslessRoute,
)
from pydhcp.netutils import IPv4
from ipaddress import ip_network

def test_ipv4address_option():
    # Test valid decode
    ip_bytes = b"\xc0\xa8\x01\x64" # 192.168.1.100
    addr, length = IPv4Address._dhcp_read(memoryview(ip_bytes))
    assert addr == IPv4("192.168.1.100")
    assert length == 4

    # Test encode
    buf = bytearray()
    wrote = addr._dhcp_write(buf)
    assert wrote == 4
    assert buf == ip_bytes


def test_string_option(caplog):
    # Standard string
    s = String("hello")
    buf = bytearray()
    s._dhcp_write(buf)
    assert buf == b"hello"

    # Decoding partition at null byte
    decoded, length = String._dhcp_read(memoryview(b"hello\x00world"))
    assert decoded == "hello"
    assert length == 11

    # UTF-8 decoding errors
    bad_bytes = b"\xff\xfe\xff"
    with caplog.at_level(logging.WARNING):
        decoded_bad, _ = String._dhcp_read(memoryview(bad_bytes))
    assert "Option contains invalid UTF-8" in caplog.text


def test_boolean_option():
    b_true = Boolean(True)
    assert int(b_true) == 1
    
    b_false = Boolean(False)
    assert int(b_false) == 0

    buf = bytearray()
    b_true._dhcp_write(buf)
    assert buf == b"\x01"

    decoded, _ = Boolean._dhcp_read(memoryview(b"\x00"))
    assert int(decoded) == 0


def test_fixed_length_integers():
    # U8 out of range / sign checks
    with pytest.raises(ValueError, match="Number is too big"):
        U8(256)
    with pytest.raises(ValueError, match="Value must not be signed"):
        U8(-1)

    u = U8(120)
    buf = bytearray()
    u._dhcp_write(buf)
    assert buf == b"\x78"

    # U16
    with pytest.raises(ValueError, match="Number is too big"):
        U16(65536)
    
    u16 = U16(1000)
    buf = bytearray()
    u16._dhcp_write(buf)
    assert buf == b"\x03\xe8"

    # U32
    with pytest.raises(ValueError, match="Number is too big"):
        U32(4294967296)

    u32 = U32(100000)
    buf = bytearray()
    u32._dhcp_write(buf)
    assert buf == b"\x00\x01\x86\xa0"


def test_classless_route_option():
    gateway = IPv4("192.168.1.1")
    network = ip_network("10.0.0.0/8")
    route = ClasslessRoute(gateway, network)
    
    buf = bytearray()
    wrote = route._dhcp_write(buf)
    # Prefixlen 8 -> last = 1. Write cidr (1 byte) + network (1 byte) + gateway (4 bytes) = 6 bytes
    assert wrote == 6
    assert buf[0] == 8 # cidr
    assert buf[1] == 10 # network address byte
    assert buf[2:6] == gateway.packed

    decoded, length = ClasslessRoute._dhcp_read(memoryview(buf))
    assert decoded.gateway == gateway
    assert decoded.network == network
    assert length == 6


def test_domain_list_option():
    from pydhcp.optiontype import DomainList
    # Encode list of domains
    dl = DomainList(["example.com", "sub.example.com"])
    buf = bytearray()
    dl._dhcp_write(buf)

    decoded, length = DomainList._dhcp_read(memoryview(buf))
    assert list(decoded) == ["example.com", "sub.example.com"]
    assert length == len(buf)


def test_client_identifier_option():
    from pydhcp.optiontype import ClientIdentifier
    with pytest.raises(ValueError):
        ClientIdentifier._dhcp_read(memoryview(b"\x01")) # Too short

    ci = ClientIdentifier(b"\x01\x00\x11\x22\x33\x44\x55")
    assert repr(ci).startswith("ETHERNET")
    assert str(ci) == "01:00:11:22:33:44:55"


def test_option_overload_option():
    from pydhcp.optiontype import OptionOverload
    oo = OptionOverload.BOTH
    buf = bytearray()
    oo._dhcp_write(buf)
    assert buf == b"\x03"

    decoded, length = OptionOverload._dhcp_read(memoryview(b"\x01"))
    assert decoded == OptionOverload.FILE
    assert length == 1

