import pytest
import logging
import json
from pydhcp.optiontype import (
    List,
    IPv4Address,
    String,
    Boolean,
    Bytes,
    U8,
    U16,
    U32,
    ClasslessRoute,
    PolicyFilter,
    StaticRoute,
    UserClass,
    TlvOption,
    VendorSpecificInformation,
    RelayAgentInformation,
    ViVendorSpecificInformationRecord,
    ViVendorSpecificInformation,
    RdnssSelection,
    UriList,
    I32,
    MoSIpv4AddressRecord,
    MoSFqdnRecord,
    MoSIpv4AddressList,
    MoSFqdnList,
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


def test_repr_and_json_value_shapes():
    route = ClasslessRoute(IPv4("192.168.1.1"), ip_network("10.0.0.0/8"))
    assert repr(route) == "ClasslessRoute(gateway=192.168.1.1, network=10.0.0.0/8)"
    assert repr(Boolean(True)) == "Boolean(True)"
    assert repr(U16(500)) == "U16(500)"

    ipv4 = IPv4Address("192.0.2.1")
    raw = Bytes(b"\x01\x02\x03")
    flag = Boolean(1)
    addrs = List[IPv4Address]([IPv4Address("192.0.2.1"), IPv4Address("198.51.100.2")])

    assert ipv4.__json__() == "192.0.2.1"
    assert raw.__json__() == "010203"
    assert flag.__json__() is True
    assert addrs.__json__() == ["192.0.2.1", "198.51.100.2"]
    assert route.__json__() == ["192.168.1.1", "10.0.0.0/8"]


def test_json_round_trip_shapes():
    ipv4 = IPv4Address("192.0.2.1")
    raw = Bytes(b"\x01\x02\x03")
    flag = Boolean(1)
    addrs = List[IPv4Address]([IPv4Address("192.0.2.1"), IPv4Address("198.51.100.2")])
    route = ClasslessRoute(IPv4("192.168.1.1"), ip_network("10.0.0.0/8"))

    assert type(ipv4)(json.loads(json.dumps(ipv4.__json__()))) == ipv4
    assert type(raw)(json.loads(json.dumps(raw.__json__()))) == raw
    assert type(flag)(json.loads(json.dumps(flag.__json__()))) == flag
    assert type(addrs)(json.loads(json.dumps(addrs.__json__()))) == addrs
    assert ClasslessRoute(*json.loads(json.dumps(route.__json__()))) == route


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

    assert repr(U8(1)) == "U8(1)"
    assert repr(U16(1)) == "U16(1)"
    assert repr(U32(1)) == "U32(1)"
    assert repr(I32(-1)) == "I32(-1)"


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
    assert decoded == route


def test_classless_route_truncated_and_invalid_prefix():
    with pytest.raises(ValueError, match="truncated"):
        ClasslessRoute._dhcp_read(memoryview(b"\x18\xc0\xa8\x01"))

    with pytest.raises(ValueError, match="exceeds 32"):
        ClasslessRoute._dhcp_read(memoryview(b"\x21\x00\x00\x00\x00\x00"))


def test_policy_filter_round_trip_and_truncation():
    value = PolicyFilter([
        ("192.0.2.1", "255.255.255.0"),
        ("198.51.100.1", "255.255.255.128"),
    ])
    buf = bytearray()
    assert value._dhcp_write(buf) == 16
    decoded, length = PolicyFilter._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == 16

    with pytest.raises(ValueError, match="truncated"):
        PolicyFilter._dhcp_read(memoryview(b"\x00" * 7))


def test_static_route_rejects_default_destination_and_round_trip():
    with pytest.raises(ValueError, match="default-route"):
        StaticRoute([("0.0.0.0", "192.0.2.1")])

    value = StaticRoute([
        ("192.0.2.0", "192.0.2.1"),
        ("198.51.100.0", "198.51.100.1"),
    ])
    buf = bytearray()
    assert value._dhcp_write(buf) == 16
    decoded, length = StaticRoute._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == 16


def test_user_class_round_trip_and_rejects_zero_length_entries():
    value = UserClass([b"alpha", b"\x00\xff\x10"])
    buf = bytearray()
    assert value._dhcp_write(buf) == 10
    assert buf == b"\x05alpha\x03\x00\xff\x10"
    decoded, length = UserClass._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == 10

    with pytest.raises(ValueError, match="non-empty"):
        UserClass([b""])

    with pytest.raises(ValueError, match="zero-length"):
        UserClass._dhcp_read(memoryview(b"\x00"))

    with pytest.raises(ValueError, match="truncated"):
        UserClass._dhcp_read(memoryview(b"\x05abc"))


def test_vendor_specific_information_preserves_opaque_bytes():
    payload = b"\x00\xff\x02vendor\x10"
    value = VendorSpecificInformation(payload)
    buf = bytearray()
    assert value._dhcp_write(buf) == len(payload)
    assert buf == payload
    decoded, length = VendorSpecificInformation._dhcp_read(memoryview(payload))
    assert decoded == value
    assert length == len(payload)

    relay = RelayAgentInformation([TlvOption(1, b"abc")])
    buf = bytearray()
    assert relay._dhcp_write(buf) == 5
    decoded, length = RelayAgentInformation._dhcp_read(memoryview(buf))
    assert decoded == relay
    assert length == 5

def test_vi_vendor_specific_information_uses_enterprise_records():
    value = ViVendorSpecificInformation(
        [
            (32473, b"alpha"),
            ViVendorSpecificInformationRecord(65537, b"\x00\xff"),
        ]
    )
    buf = bytearray()
    assert value._dhcp_write(buf) == 17
    assert buf == (
        (32473).to_bytes(4, "big")
        + b"\x05alpha"
        + (65537).to_bytes(4, "big")
        + b"\x02\x00\xff"
    )
    decoded, length = ViVendorSpecificInformation._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == 17
    assert decoded[0].enterprise_number == 32473
    assert decoded[0].value == b"alpha"
    assert decoded[1].enterprise_number == 65537
    assert decoded[1].value == b"\x00\xff"

    with pytest.raises(ValueError, match="truncated"):
        ViVendorSpecificInformation._dhcp_read(memoryview(b"\x00\x00\x00\x01"))

    with pytest.raises(ValueError, match="32 bits"):
        ViVendorSpecificInformationRecord(-1, b"a")._dhcp_encode()

    with pytest.raises(ValueError, match="32 bits"):
        ViVendorSpecificInformationRecord(0x1_0000_0000, b"a")._dhcp_encode()


def test_rdnss_selection_round_trip():
    value = RdnssSelection(1, "192.0.2.1", "192.0.2.2", ["example.com"])
    buf = bytearray()
    wrote = value._dhcp_write(buf)
    assert wrote == len(buf)
    decoded, length = RdnssSelection._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == len(buf)

    with pytest.raises(ValueError, match="truncated"):
        RdnssSelection._dhcp_read(memoryview(b"\x01\x02"))


def test_mos_ipv4_address_option_round_trip_and_preserves_unknown_codes():
    value = MoSIpv4AddressList([
        MoSIpv4AddressRecord(1, ["192.0.2.1", "192.0.2.2"]),
        (99, b"\x01\x02"),
    ])
    buf = bytearray()
    wrote = value._dhcp_write(buf)
    assert wrote == len(buf)
    decoded, length = MoSIpv4AddressList._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == len(buf)
    assert decoded[0].value == [IPv4Address("192.0.2.1"), IPv4Address("192.0.2.2")]
    assert decoded[1].code == 99
    assert decoded[1].value == b"\x01\x02"

    raw = bytes([1, 8]) + IPv4Address("198.51.100.1").packed + IPv4Address("198.51.100.2").packed
    decoded_raw, length = MoSIpv4AddressList._dhcp_read(memoryview(raw))
    assert decoded_raw == MoSIpv4AddressList([MoSIpv4AddressRecord(1, ["198.51.100.1", "198.51.100.2"])])
    assert length == len(raw)

    with pytest.raises(ValueError, match="truncated"):
        MoSIpv4AddressList._dhcp_read(memoryview(b"\x01\x05\x01\x02\x03"))


def test_mos_fqdn_option_round_trip_and_rejects_truncated_labels():
    value = MoSFqdnList([
        MoSFqdnRecord(1, ["alpha.example", "beta.example"]),
        (99, b"\x03raw"),
    ])
    buf = bytearray()
    wrote = value._dhcp_write(buf)
    assert wrote == len(buf)
    decoded, length = MoSFqdnList._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == len(buf)
    assert decoded[0].value == ["alpha.example", "beta.example"]
    assert decoded[1].code == 99
    assert decoded[1].value == b"\x03raw"

    raw = b"\x01\x0f\x05alpha\x07example\x00"
    decoded_raw, length = MoSFqdnList._dhcp_read(memoryview(raw))
    assert decoded_raw == MoSFqdnList([MoSFqdnRecord(1, ["alpha.example"])])
    assert length == len(raw)

    with pytest.raises(ValueError, match="truncated"):
        MoSFqdnList._dhcp_read(memoryview(b"\x01\x04\x03ab"))


def test_signed_i32_round_trip():
    value = I32(-1)
    buf = bytearray()
    assert value._dhcp_write(buf) == 4
    assert buf == b"\xff\xff\xff\xff"


def test_domain_list_option():
    from pydhcp.optiontype import DomainList
    # Encode list of domains
    dl = DomainList(["example.com", "sub.example.com"])
    buf = bytearray()
    dl._dhcp_write(buf)

    decoded, length = DomainList._dhcp_read(memoryview(buf))
    assert list(decoded) == ["example.com", "sub.example.com"]
    assert length == len(buf)

    single, single_length = DomainList._dhcp_read(memoryview(b"\x05alpha\x07example\x00"))
    assert list(single) == ["alpha.example"]
    assert single_length == 15


def test_uri_list_option_round_trip_and_truncation():
    value = UriList(["https://bootstrap.example/one", "https://bootstrap.example/two"])
    buf = bytearray()
    wrote = value._dhcp_write(buf)
    assert wrote == len(buf)

    decoded, length = UriList._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == len(buf)

    joined = (
        len(b"https://bootstrap.example/one").to_bytes(2, "big")
        + b"https://bootstrap.example/one"
        + len(b"https://bootstrap.example/two").to_bytes(2, "big")
        + b"https://bootstrap.example/two"
    )
    decoded_joined, joined_length = UriList._dhcp_read(memoryview(joined))
    assert decoded_joined == value
    assert joined_length == len(joined)

    with pytest.raises(ValueError, match="truncated"):
        UriList._dhcp_read(memoryview(b"\x00\x10short"))


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
