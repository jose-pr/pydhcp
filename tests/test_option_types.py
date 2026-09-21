import pytest
import logging
import json
from pydhcp.options.type import (
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
    ViVendorClassRecord,
    ViVendorClass,
    RdnssSelection,
    UriList,
    I32,
    MoSIpv4AddressRecord,
    MoSFqdnRecord,
    MoSIpv4AddressList,
    MoSFqdnList,
    CccOption,
    CccPrimaryDhcpServerAddress,
    CccSecondaryDhcpServerAddress,
    CccProvisioningServerAddress,
    CccProvisioningServerFqdn,
    CccKerberosRealmName,
    CccAsReqAsRepBackoffRetry,
    CccApReqApRepBackoffRetry,
    CccTicketGrantingServerUtilization,
    CccProvisioningTimer,
    CccSecurityTicketControl,
    CccKdcServerAddressList,
    CccPrimaryDhcpServerAddressSubOption,
    CccSecondaryDhcpServerAddressSubOption,
    CccProvisioningServerAddressSubOption,
    CccAsReqAsRepBackoffRetrySubOption,
    CccApReqApRepBackoffRetrySubOption,
    CccKerberosRealmNameSubOption,
    CccTicketGrantingServerUtilizationSubOption,
    CccProvisioningTimerSubOption,
    CccSecurityTicketControlSubOption,
    CccKdcServerAddressSubOption,
)
from pydhcp.network import IPv4
from ipaddress import ip_network


def test_ipv4address_option():
    # Test valid decode
    ip_bytes = b"\xc0\xa8\x01\x64"  # 192.168.1.100
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

    # UTF-8 decoding errors are warned about, and the octets are kept so the
    # value re-encodes to exactly what arrived.
    bad_bytes = b"\xff\xfe\xff"
    with caplog.at_level(logging.WARNING):
        decoded_bad, _ = String._dhcp_read(memoryview(bad_bytes))
    assert "not valid UTF-8" in caplog.text
    round_tripped = bytearray()
    decoded_bad._dhcp_write(round_tripped)
    assert bytes(round_tripped) == bad_bytes


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
    assert buf[0] == 8  # cidr
    assert buf[1] == 10  # network address byte
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
    value = PolicyFilter(
        [
            ("192.0.2.1", "255.255.255.0"),
            ("198.51.100.1", "255.255.255.128"),
        ]
    )
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

    value = StaticRoute(
        [
            ("192.0.2.0", "192.0.2.1"),
            ("198.51.100.0", "198.51.100.1"),
        ]
    )
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


def test_vi_vendor_class_uses_enterprise_records_with_opaque_items():
    value = ViVendorClass(
        [
            (32473, [b"docsis", b"eRouter"]),
            ViVendorClassRecord(65537, [b"usp", b"agent"]),
        ]
    )
    buf = bytearray()
    assert value._dhcp_write(buf) == 35
    decoded, length = ViVendorClass._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == 35
    assert decoded[0].enterprise_number == 32473
    assert decoded[0].value == UserClass([b"docsis", b"eRouter"])
    assert decoded[1].enterprise_number == 65537
    assert decoded[1].value == UserClass([b"usp", b"agent"])

    with pytest.raises(ValueError, match="truncated"):
        ViVendorClass._dhcp_read(memoryview(b"\x00\x00\x00\x01\x05\x03ab"))


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
    value = MoSIpv4AddressList(
        [
            MoSIpv4AddressRecord(1, ["192.0.2.1", "192.0.2.2"]),
            (99, b"\x01\x02"),
        ]
    )
    buf = bytearray()
    wrote = value._dhcp_write(buf)
    assert wrote == len(buf)
    decoded, length = MoSIpv4AddressList._dhcp_read(memoryview(buf))
    assert decoded == value
    assert length == len(buf)
    assert decoded[0].value == [IPv4Address("192.0.2.1"), IPv4Address("192.0.2.2")]
    assert decoded[1].code == 99
    assert decoded[1].value == b"\x01\x02"

    raw = (
        bytes([1, 8])
        + IPv4Address("198.51.100.1").packed
        + IPv4Address("198.51.100.2").packed
    )
    decoded_raw, length = MoSIpv4AddressList._dhcp_read(memoryview(raw))
    assert decoded_raw == MoSIpv4AddressList(
        [MoSIpv4AddressRecord(1, ["198.51.100.1", "198.51.100.2"])]
    )
    assert length == len(raw)

    with pytest.raises(ValueError, match="truncated"):
        MoSIpv4AddressList._dhcp_read(memoryview(b"\x01\x05\x01\x02\x03"))


def test_mos_fqdn_option_round_trip_and_rejects_truncated_labels():
    value = MoSFqdnList(
        [
            MoSFqdnRecord(1, ["alpha.example", "beta.example"]),
            (99, b"\x03raw"),
        ]
    )
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
    """I32 is two's complement and survives a round trip, both signs.

    The name said round trip and the body only ever encoded, so nothing read
    `\\xff\\xff\\xff\\xff` back -- a `_dhcp_read` that decoded it as the unsigned
    4294967295 (which is exactly what an unsigned codec does, and the reason
    this option type exists separately from U32) passed. -1 alone would also
    not have caught a decoder that simply negated, hence the bounds and a
    value with distinguishable octets.
    """
    for number in (-1, 0, 1, -2147483648, 2147483647, -305419896):
        value = I32(number)
        buf = bytearray()
        assert value._dhcp_write(buf) == 4, number
        decoded, length = I32._dhcp_read(memoryview(bytes(buf)))
        assert length == 4, number
        assert type(decoded) is I32, number
        assert decoded == number, (number, decoded)

    # The wire form itself, so the test pins two's complement rather than
    # whatever pair of functions happen to agree with each other.
    buf = bytearray()
    I32(-1)._dhcp_write(buf)
    assert bytes(buf) == b"\xff\xff\xff\xff"
    buf = bytearray()
    I32(-305419896)._dhcp_write(buf)
    assert bytes(buf) == b"\xed\xcb\xa9\x88"


def test_domain_list_option():
    from pydhcp.options.type import DomainList

    # Encode list of domains
    dl = DomainList(["example.com", "sub.example.com"])
    buf = bytearray()
    dl._dhcp_write(buf)

    decoded, length = DomainList._dhcp_read(memoryview(buf))
    assert list(decoded) == ["example.com", "sub.example.com"]
    assert length == len(buf)

    single, single_length = DomainList._dhcp_read(
        memoryview(b"\x05alpha\x07example\x00")
    )
    assert list(single) == ["alpha.example"]
    assert single_length == 15


def test_domain_list_survives_domain_after_pointer_terminated_domain():
    # Regression test: a domain following one that ends in a compression
    # pointer (rather than a literal 0x00) must not be silently dropped.
    from pydhcp.options.type import DomainList

    dl = DomainList(["0", "0.0", "0"])
    buf = bytearray()
    dl._dhcp_write(buf)

    decoded, length = DomainList._dhcp_read(memoryview(buf))
    assert list(decoded) == ["0", "0.0", "0"]
    assert length == len(buf)


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
    from pydhcp.options.type import ClientIdentifier

    with pytest.raises(ValueError):
        ClientIdentifier._dhcp_read(memoryview(b"\x01"))  # Too short

    ci = ClientIdentifier(b"\x01\x00\x11\x22\x33\x44\x55")
    assert repr(ci).startswith("ETHERNET")
    assert str(ci) == "01:00:11:22:33:44:55"


def test_option_overload_option():
    from pydhcp.options.type import OptionOverload

    oo = OptionOverload.BOTH
    buf = bytearray()
    oo._dhcp_write(buf)
    assert buf == b"\x03"

    decoded, length = OptionOverload._dhcp_read(memoryview(b"\x01"))
    assert decoded == OptionOverload.FILE
    assert length == 1


def test_ccc_payload_round_trips_and_unknown_records():
    primary = CccPrimaryDhcpServerAddress("192.0.2.1")
    secondary = CccSecondaryDhcpServerAddress("192.0.2.2")
    provisioning_ipv4 = CccProvisioningServerAddress(("ipv4", "192.0.2.3"))
    provisioning_fqdn = CccProvisioningServerAddress(
        ("fqdn", CccProvisioningServerFqdn("tsp.example"))
    )
    as_retry = CccAsReqAsRepBackoffRetry(1, 2, 3)
    ap_retry = CccApReqApRepBackoffRetry(4, 5, 6)
    realm = CccKerberosRealmName("EXAMPLE.COM")
    tgs = CccTicketGrantingServerUtilization(True)
    timer = CccProvisioningTimer(7)
    control = CccSecurityTicketControl(3)
    kdc = CccKdcServerAddressList(["192.0.2.10", "192.0.2.11"])

    for value in [
        primary,
        secondary,
        provisioning_ipv4.value,
        provisioning_fqdn.value,
        as_retry,
        ap_retry,
        realm,
        tgs,
        timer,
        control,
        kdc,
    ]:
        buf = bytearray()
        wrote = value._dhcp_write(buf)
        decoded, length = type(value)._dhcp_read(memoryview(buf))
        assert decoded == value
        assert length == wrote

    buf = bytearray()
    provisioning_ipv4._dhcp_write(buf)
    decoded_ipv4, length = CccProvisioningServerAddress._dhcp_read(memoryview(buf))
    assert decoded_ipv4 == provisioning_ipv4
    assert length == len(buf)

    buf = bytearray()
    provisioning_fqdn._dhcp_write(buf)
    decoded_fqdn, length = CccProvisioningServerAddress._dhcp_read(memoryview(buf))
    assert decoded_fqdn == provisioning_fqdn
    assert length == len(buf)

    with pytest.raises(ValueError, match="reserved bits"):
        CccSecurityTicketControl(0x0004)._dhcp_write(bytearray())


def test_ccc_option_container_preserves_unknown_records():
    option = CccOption(
        [
            CccPrimaryDhcpServerAddressSubOption(1, "192.0.2.1"),
            CccSecondaryDhcpServerAddressSubOption(2, "192.0.2.2"),
            CccProvisioningServerAddressSubOption(3, ("fqdn", "tsp.example")),
            CccAsReqAsRepBackoffRetrySubOption(4, (1, 2, 3)),
            CccApReqApRepBackoffRetrySubOption(5, (4, 5, 6)),
            CccKerberosRealmNameSubOption(6, "EXAMPLE.COM"),
            CccTicketGrantingServerUtilizationSubOption(7, True),
            CccProvisioningTimerSubOption(8, 9),
            CccSecurityTicketControlSubOption(9, 3),
            CccKdcServerAddressSubOption(10, ["192.0.2.10", "192.0.2.11"]),
            (99, b"\x01\x02\x03"),
        ]
    )

    buf = bytearray()
    wrote = option._dhcp_write(buf)
    decoded, length = CccOption._dhcp_read(memoryview(buf))

    assert decoded == option
    assert length == wrote
    assert decoded[-1].code == 99
    assert decoded[-1].value == b"\x01\x02\x03"


# --- DomainList hostile input (RFC 1035 compression pointers) ---


@pytest.mark.parametrize(
    "payload,label",
    [
        (b"\x01a\xc0\x00", "self-referential pointer"),
        (b"\xc0\x02\xc0\x00", "two-pointer cycle"),
        (b"\x01a\xc0\x02\xc0\x02", "pointer to itself mid-buffer"),
    ],
)
def test_domainlist_rejects_compression_pointer_cycles(payload, label):
    """A pointer loop must be a decode error, not a RecursionError.

    RecursionError is not a ValueError, so it escapes the codec's error contract
    and reaches the listener's receive loop.
    """
    from pydhcp.options.type import DomainList

    with pytest.raises(ValueError):
        DomainList._dhcp_read(memoryview(bytearray(payload)))


def test_domainlist_decode_is_linear_in_payload_size():
    """Decoding must not be quadratic: packets are decoded on the receive path, so
    O(n^2) here is an unauthenticated CPU-exhaustion vector (max_packet_size
    defaults to 65535)."""
    import time

    from pydhcp.options.type import DomainList

    def elapsed(size):
        payload = bytearray(b"\x01a\x00" * (size // 3))
        start = time.perf_counter()
        DomainList._dhcp_read(memoryview(payload))
        return time.perf_counter() - start

    elapsed(3000)  # warm up, so import/JIT costs do not land in the measurement
    small = elapsed(6000)
    large = elapsed(24000)

    # 4x the input must not cost anything like 16x the time. A generous bound:
    # quadratic would be ~16x, linear ~4x. This machine is noisy, so allow 8x.
    assert large < max(
        small * 8, 0.05
    ), f"decode looks super-linear: {small:.4f}s for 6000B vs {large:.4f}s for 24000B"


def test_domainlist_still_follows_backward_pointers():
    """The cycle guard must not break legitimate RFC 1035 compression."""
    from pydhcp.options.type import DomainList

    # "example.com" at offset 0, then "sub" + pointer back to "example.com".
    payload = bytearray(b"\x07example\x03com\x00\x03sub\xc0\x00")
    decoded, length = DomainList._dhcp_read(memoryview(payload))

    assert list(decoded) == ["example.com", "sub.example.com"]
    assert length == len(payload)


# --- RFC 4702 client FQDN (81), RFC 3361 SIP servers (120), RFC 2937 search (117) ---


def test_client_fqdn_decodes_the_form_windows_clients_send():
    """Flags/RCODE1/RCODE2 then an ASCII name, flags = 0.

    Registered as a plain String this decoded to the EMPTY STRING -- String
    splits at the first NUL -- so a server reading option 81 for DDNS saw no
    name at all, with no error to notice.
    """
    from pydhcp.options.type import ClientFqdn

    wire = bytes([0x00, 0x00, 0x00]) + b"DESKTOP-K7N2A91"
    decoded = ClientFqdn._dhcp_decode(bytearray(wire))

    assert decoded.name == "DESKTOP-K7N2A91"
    assert decoded.flags == 0 and not decoded.encoded
    assert bytes(decoded._dhcp_encode()) == wire


def test_client_fqdn_round_trips_the_canonical_encoded_form():
    """E bit set means RFC 1035 wire format (RFC 4702 s2.1)."""
    from pydhcp.options.type import ClientFqdn

    value = ClientFqdn(
        "pc-lab7.example.com", flags=ClientFqdn.FLAG_E | ClientFqdn.FLAG_S
    )
    wire = bytes(value._dhcp_encode())

    assert wire[:3] == bytes([0x05, 0x00, 0x00])
    assert wire[3:] == bytes([7]) + b"pc-lab7" + bytes([7]) + b"example" + bytes(
        [3]
    ) + b"com" + bytes([0])
    assert ClientFqdn._dhcp_decode(bytearray(wire)) == value


def test_client_fqdn_rejects_malformed_input():
    from pydhcp.options.type import ClientFqdn
    import pytest as _pytest

    with _pytest.raises(ValueError):
        ClientFqdn._dhcp_decode(bytearray([0x00, 0x00]))  # shorter than 3
    with _pytest.raises(ValueError):
        ClientFqdn._dhcp_decode(bytearray([0xF0, 0x00, 0x00]))  # reserved bits set
    with _pytest.raises(ValueError):
        # E bit set, but a compression pointer, which RFC 4702 s3.1 forbids
        ClientFqdn._dhcp_decode(bytearray([0x04, 0x00, 0x00, 0xC0, 0x00]))


def test_sip_servers_carries_the_encoding_octet():
    """RFC 3361 s3.1: enc 1 is an address list, and its length must be a
    multiple of 4 plus one. Without the octet, a phone reads the first address
    byte as the encoding and rejects the option."""
    from pydhcp.options.type import SipServers

    value = SipServers(["192.0.2.1", "192.0.2.2"])
    wire = bytes(value._dhcp_encode())

    assert wire[0] == SipServers.ENCODING_ADDRESS
    assert len(wire) % 4 == 1
    assert SipServers._dhcp_decode(bytearray(wire)) == value
    assert value.__json__() == {
        "encoding": "address",
        "values": ["192.0.2.1", "192.0.2.2"],
    }


def test_sip_servers_domain_encoding():
    from pydhcp.options.type import SipServers

    value = SipServers(["sip.example.com"], SipServers.ENCODING_DOMAIN)
    wire = bytes(value._dhcp_encode())

    assert wire[0] == SipServers.ENCODING_DOMAIN
    assert SipServers._dhcp_decode(bytearray(wire)) == value
    # Inference picks domain encoding for something that is not an address.
    assert SipServers(["sip.example.com"]).encoding == SipServers.ENCODING_DOMAIN


def test_sip_servers_rejects_bad_encodings_and_lengths():
    from pydhcp.options.type import SipServers
    import pytest as _pytest

    with _pytest.raises(ValueError):
        SipServers._dhcp_decode(bytearray())  # no encoding octet
    with _pytest.raises(ValueError):
        SipServers._dhcp_decode(bytearray([0x0A, 0x01, 0x02]))  # reserved encoding
    with _pytest.raises(ValueError):
        SipServers._dhcp_decode(
            bytearray([0x01, 0xC0, 0x00, 0x02])
        )  # not a multiple of 4


def test_name_service_search_is_a_list_of_option_codes():
    """RFC 2937 s3: 16-bit name service option codes, not domain names."""
    from pydhcp.options import DhcpOptions, DhcpOptionCode

    options = DhcpOptions()
    options[DhcpOptionCode.NAME_SERVICE_SEARCH] = [6, 44]

    assert bytes(
        options.get(DhcpOptionCode.NAME_SERVICE_SEARCH, decode=False)
    ) == bytes([0x00, 0x06, 0x00, 0x2C])
    assert options.get(DhcpOptionCode.NAME_SERVICE_SEARCH) == [6, 44]


# --- The shared uncompressed-name helpers (options/type/domain.py) ---
#
# These lived in three copies that had drifted: only one rejected a compression
# pointer, only one enforced RFC 1035's 255-octet name limit. The same malformed
# input was accepted, rejected or silently misread depending on which option it
# arrived in.


def test_domain_helper_round_trips():
    from pydhcp.options.type.domain import decode_domain_name, encode_domain_name

    wire = encode_domain_name("sip.example.com")
    assert wire == bytes([3]) + b"sip" + bytes([7]) + b"example" + bytes(
        [3]
    ) + b"com" + bytes([0])
    assert decode_domain_name(memoryview(bytearray(wire))) == (
        "sip.example.com",
        len(wire),
    )


def test_domain_helper_rejects_compression_pointers():
    """Read as a length, 0xC0 means "the next 192 octets are a label", which
    either overruns a short option or silently yields a wrong name from a long
    one. RFC 4702 s3.1, RFC 3361 s3.1 and RFC 3495 all forbid compression here."""
    import pytest as _pytest

    from pydhcp.options.type.domain import decode_domain_name

    payload = bytes([0x03]) + b"lab" + bytes([0xC0, 0x00])
    with _pytest.raises(ValueError, match="compression pointer"):
        decode_domain_name(memoryview(bytearray(payload)))


def test_domain_helper_enforces_the_rfc1035_limits():
    import pytest as _pytest

    from pydhcp.options.type.domain import encode_domain_name

    with _pytest.raises(ValueError, match="63 octets"):
        encode_domain_name("a" * 64)
    with _pytest.raises(ValueError, match="255 octets"):
        encode_domain_name(".".join(["abcdefgh"] * 40))
    with _pytest.raises(ValueError, match="empty labels"):
        encode_domain_name("lab..example")


def test_domain_helper_root_name_is_opt_in():
    """RFC 4702 lets a client send option 81 with no name, but for most options
    an empty name is a caller mistake -- and these codecs rejected it before."""
    import pytest as _pytest

    from pydhcp.options.type.domain import encode_domain_name

    assert encode_domain_name("", allow_root=True) == bytes([0])
    with _pytest.raises(ValueError, match="must not be empty"):
        encode_domain_name("")


def test_ccc_and_mos_inherit_the_shared_checks():
    """Convergence has to reach the callers, or it is just a fourth copy."""
    import pytest as _pytest

    from pydhcp.options.type.ccc import (
        _decode_no_compression_domain,
        _encode_no_compression_domain,
    )
    from pydhcp.options.type import MoSFqdnList, MoSFqdnRecord

    pointer = memoryview(bytearray(bytes([0x03]) + b"lab" + bytes([0xC0, 0x00])))
    with _pytest.raises(ValueError, match="compression pointer"):
        _decode_no_compression_domain(pointer)
    with _pytest.raises(ValueError, match="255 octets"):
        _encode_no_compression_domain(".".join(["abcdefgh"] * 40))
    # MoS validates by encoding, so the same limits apply on construction.
    with _pytest.raises(ValueError, match="255 octets"):
        MoSFqdnRecord(1, [".".join(["abcdefgh"] * 40)])
    # and the ordinary case still works
    record = MoSFqdnRecord(1, ["alpha.example"])
    assert list(MoSFqdnList([record])) == [record]


# --- the search list obeys the same name rules as every other option ---


def test_domainlist_enforces_the_shared_rfc1035_limits() -> None:
    """The compressed encoder has its own algorithm, not its own rules.

    A length octet is six bits of length plus two flag bits, so a label of 64+
    octets writes a prefix that sets the compression-pointer flags: DomainList
    accepted such a label, emitted 0x40 (or 0xC0, an actual pointer) as its
    length, and its own decoder then rejected what it had just written. The
    limits now come from the same helper the uncompressed codecs use.
    """
    from pydhcp.options.type import DomainList

    for label_len in (64, 192):
        with pytest.raises(ValueError, match="63 octets"):
            DomainList(["a" * label_len + ".example.com"])._dhcp_write(bytearray())

    with pytest.raises(ValueError, match="255 octets"):
        DomainList([".".join(["label"] * 50)])._dhcp_write(bytearray())

    # The longest legal label is still accepted and still round-trips.
    longest = "x" * 63 + ".example.com"
    buf = bytearray()
    DomainList([longest])._dhcp_write(buf)
    decoded, _ = DomainList._dhcp_read(memoryview(bytes(buf)))
    assert list(decoded) == [longest]


def test_domainlist_root_entry_round_trips() -> None:
    """A root name is one zero octet, not an empty label plus a terminator.

    Writing both made it decode as *two* names, so a search list containing the
    root gained an entry on every encode/decode cycle.
    """
    from pydhcp.options.type import DomainList

    for case in ([""], ["example.com", ""]):
        buf = bytearray()
        DomainList(case)._dhcp_write(buf)
        decoded, _ = DomainList._dhcp_read(memoryview(bytes(buf)))
        assert list(decoded) == case, f"{case!r} did not survive a round trip"

    buf = bytearray()
    DomainList([""])._dhcp_write(buf)
    assert bytes(buf) == b"\x00"


# --- codecs matched to the wire forms their RFCs actually define ---


@pytest.mark.parametrize(
    "code,payload,expected",
    [
        # RFC 4388 s6.1: Len n (multiple of 4), Address 1 ... Address n
        (92, bytes.fromhex("c0000201c0000202"), ["192.0.2.1", "192.0.2.2"]),
        # RFC 6704 s3.1.2: one octet per supported algorithm
        (145, bytes.fromhex("0102"), [1, 2]),
        # RFC 7291 s4: (List-Length, addresses) entries, one per PCP server
        (158, bytes.fromhex("04c0000201"), [["192.0.2.1"]]),
        (
            158,
            bytes.fromhex("08c0000201c000020204c0000203"),
            [["192.0.2.1", "192.0.2.2"], ["192.0.2.3"]],
        ),
    ],
)
def test_rfc_wire_forms_decode_and_round_trip(code, payload, expected):
    """Each of these raised on its own RFC's wire form, so the packet was lost.

    A raise in a codec is not local: the receive path resolves every option
    before the packet reaches a handler, so one unparseable option dropped the
    whole message.
    """
    from pydhcp.options import DhcpOptionCode

    codec = DhcpOptionCode(code).get_type()
    value = codec._dhcp_decode(payload)

    def plain(item):
        # str() on a scalar codec gives its repr (U8(1)), so compare by value.
        if isinstance(item, list):
            return [plain(sub) for sub in item]
        return int(item) if isinstance(item, int) else str(item)

    assert [plain(v) for v in value] == [plain(e) for e in expected]
    assert value._dhcp_encode() == payload, "re-encode is not byte-identical"


def test_status_code_carries_its_optional_message():
    """RFC 6926 s6.2.2: a status octet, then an optional UTF-8 message.

    Registered as a bare U8, a reply carrying the message was the wrong size
    and could not be decoded at all.
    """
    from pydhcp.options import DhcpOptionCode
    from pydhcp.options.type import StatusCode

    codec = DhcpOptionCode(151).get_type()
    assert codec is StatusCode

    with_message = codec._dhcp_decode(b"\x01busy")
    assert with_message.code == 1 and with_message.message == "busy"
    assert with_message._dhcp_encode() == b"\x01busy"

    # the message is optional, and its absence is not an error
    bare = codec._dhcp_decode(b"\x00")
    assert bare.code == 0 and bare.message == ""
    assert bare._dhcp_encode() == b"\x00"

    assert StatusCode(2, "no binding").__json__() == {
        "code": 2,
        "message": "no binding",
    }
    with pytest.raises(ValueError):
        StatusCode(256)


def test_dns_name_options_are_label_sequences_not_dotted_text():
    """Options 147 (RFC 8973 s5.2) and 213 (RFC 5986 s3.2) carry RFC 1035 labels.

    As `String` they decoded to the raw label bytes rather than to a name, and
    emitted dotted text a conforming receiver cannot parse.
    """
    from pydhcp.options import DhcpOptionCode
    from pydhcp.options.type import DomainName

    wire = b"\x07example\x03com\x00"
    for code in (147, 213):
        codec = DhcpOptionCode(code).get_type()
        assert codec is DomainName
        assert str(codec._dhcp_decode(wire)) == "example.com"
        assert DomainName("example.com")._dhcp_encode() == wire

    # the shared name rules apply here too
    with pytest.raises(ValueError, match="63 octets"):
        DomainName("x" * 64 + ".example.com")._dhcp_encode()


def test_vendor_class_identifier_keeps_binary_payloads():
    """RFC 2132 s9.13 calls option 60 a string of n octets, not NUL-terminated.

    `String` partitions at the first NUL, so the binary identifiers some
    embedded and CPE firmware sends decoded to the empty string and a server
    had nothing left to match on.
    """
    from pydhcp.options import DhcpOptionCode
    from pydhcp.options.type import OctetString

    codec = DhcpOptionCode(60).get_type()
    assert codec is OctetString

    binary = bytes.fromhex("00000de9fffe")
    assert codec._dhcp_decode(binary)._dhcp_encode() == binary

    # the ordinary ASCII case is unchanged
    assert str(codec._dhcp_decode(b"MSFT 5.0")) == "MSFT 5.0"
    assert codec._dhcp_decode(b"MSFT 5.0")._dhcp_encode() == b"MSFT 5.0"


# --- a subscripted generic must be the same class every time ---


def test_generic_subscription_is_cached():
    """`List[X] is List[X]` was False: the cache never hit.

    The key was normalised to a tuple only on the miss path, so the lookup
    asked for `X` while the store had written `(X,)`. Every subscription built
    a fresh class, and two class objects for one type make identity and
    issubclass checks unreliable.
    """
    assert List[IPv4Address] is List[IPv4Address]
    assert List[U8] is List[U8]
    assert List[U8] is not List[IPv4Address]
    assert List[IPv4Address]._args_ == (IPv4Address,)


def test_two_generic_classes_do_not_share_a_cache():
    """`__concrete__` lived on the metaclass, keyed only by the arguments.

    Invisible while the cache never hit -- and fixing the lookup alone would
    have exposed it, serving one class's subscription from another's entry.
    """
    from pydhcp._utils import GenericMeta

    class Other(list, metaclass=GenericMeta):
        pass

    assert Other[U8] is not List[U8]
    assert Other[U8] is Other[U8]
    # each class owns its cache; a subscripted class does not write into its base
    assert "__concrete__" in Other.__dict__
    assert "__concrete__" not in List[U8].__dict__


def test_record_codecs_are_hashable_and_lists_are_not():
    """A codec that defined `__eq__` and no `__hash__` was silently unhashable.

    Python sets `__hash__ = None` for such a class, so `set(...)` or a dict key
    over decoded option values worked or raised `TypeError` depending purely on
    which option the caller happened to touch -- `Bytes`, `String`,
    `IPv4Address` and the integer codecs were hashable through their bases while
    ten record types were not. List codecs are a different case: they are
    genuinely mutable, so `list.__hash__ is None` is correct for them and this
    test asserts that too, to keep a future "fix" from making them hashable.
    """
    import pydhcp.options.type as _type

    records = []
    lists = []
    for name in _type.__all__:
        obj = getattr(_type, name)
        if not isinstance(obj, type):
            continue
        (lists if issubclass(obj, list) else records).append(name)

    assert [n for n in records if getattr(_type, n).__hash__ is None] == []
    assert [n for n in lists if getattr(_type, n).__hash__ is not None] == []


def test_hash_agrees_with_eq_for_records_holding_a_list_payload():
    """The cases a naive `hash((a, b))` would have raised on.

    `ViVendorClassRecord.value` is a `UserClass` and a MoS record's value is a
    label/address list -- both `list` subclasses, and both compared element-wise
    by the `__eq__` beside the hash.
    """
    a = ViVendorClassRecord(3561, [b"alpha", b"beta"])
    b = ViVendorClassRecord(3561, [b"alpha", b"beta"])
    assert a == b and hash(a) == hash(b)
    assert len({a, b}) == 1

    c = MoSFqdnRecord(1, ["alpha.example"])
    d = MoSFqdnRecord(1, ["alpha.example"])
    assert c == d and hash(c) == hash(d)
    assert len({c, d}) == 1

    e = ClasslessRoute("10.0.0.1", "192.0.2.0/24")
    assert len({e, ClasslessRoute("10.0.0.1", "192.0.2.0/24")}) == 1
