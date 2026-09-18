import pytest
from datetime import datetime, timedelta
from pydhcp.packet.message import DhcpMessage
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4
from pydhcp.options import DhcpOptions
from pydhcp.server import DhcpServer, DhcpLease
from pydhcp.options.type import U16, U32, String
from math import inf as _inf


def build_dhcp_packet(htype=1, cookie=b"\x63\x82\x53\x63") -> bytearray:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER.value]
    )

    msg = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET if htype == 1 else htype,
        hlen=6,
        hops=0,
        xid=0x3903F326,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        sname="",
        file="",
        options=options,
    )

    # We manually override the htype representation during packing if needed,
    # or just encode first and overwrite the specific fields.
    encoded = msg.encode()
    if htype != 1:
        encoded[1] = htype
    if cookie != b"\x63\x82\x53\x63":
        encoded[236:240] = cookie
    return encoded


def test_lease_expiration_total_seconds():
    """Bug 3: Verify lease TTL calculation uses total_seconds() instead of seconds."""
    server = DhcpServer()
    # Create lease expiring in 1 hour 1 minute
    lease = DhcpLease(
        IPv4("192.168.1.100"),
        datetime.now() + timedelta(hours=1, minutes=1, seconds=1),
        DhcpOptions(),
    )
    resp = server._create_response(
        DhcpMessage(
            op=OpCode.BOOTREQUEST,
            htype=HardwareAddressType.ETHERNET,
            hlen=6,
            hops=0,
            xid=1,
            secs=timedelta(seconds=0),
            flags=Flags.UNICAST,
            ciaddr=IPv4("0.0.0.0"),
            yiaddr=IPv4("0.0.0.0"),
            siaddr=IPv4("0.0.0.0"),
            giaddr=IPv4("0.0.0.0"),
            chaddr=b"\x00\x11\x22\x33\x44\x55",
            sname="",
            file="",
            options=DhcpOptions(),
        ),
        lease,
        IPv4("192.168.1.1"),
        DhcpMessageType.DHCPOFFER,
    )
    # Expiration should be ~3661 seconds, definitely greater than 600
    expires = resp.options.get(DhcpOptionCode.IP_ADDRESS_LEASE_TIME)
    assert expires is not None
    assert 3650 < expires <= 3662


def test_unnamed_htype_is_preserved_not_rewritten():
    """Bug 1: an unknown hardware type must not crash -- and must not be rewritten.

    It used to become ETHERNET, which a relay then forwarded: RFC 1542 s4.1.2
    has a relay alter giaddr and hops and nothing else, so an IPoIB client
    (RFC 4390, htype 32) reached the server as htype 1. The derived client
    identifier is built from this value too, so that changed as well.
    """
    data = build_dhcp_packet(htype=255)
    msg = DhcpMessage.decode(data)

    assert msg.htype == 255
    assert msg.htype.label() == "HTYPE_255"
    assert bytes(msg.encode())[1] == 255, "htype was rewritten on re-encode"

    # A type that now has a name resolves to it rather than a pseudo-member.
    assert DhcpMessage.decode(build_dhcp_packet(htype=32)).htype is (
        HardwareAddressType.INFINIBAND
    )


def test_bad_magic_cookie_raises_value_error():
    """Bug 2: Invalid magic cookie raises ValueError with context."""
    data = build_dhcp_packet(cookie=b"\x00\x00\x00\x00")
    with pytest.raises(ValueError, match="Invalid magic cookie"):
        DhcpMessage.decode(data)


def test_u16_overflow_validation():
    """Bug 7: U16 raises ValueError on overflow during dhcp_write."""
    with pytest.raises(ValueError, match="Number is too big"):
        u = U16(65536)
        u._dhcp_write(bytearray())


def test_u32_validation_on_encode():
    """Bug 7: U32 validation passes for valid bounds and raises for invalid."""
    u = U32(4294967295)
    buf = bytearray()
    u._dhcp_write(buf)
    assert len(buf) == 4

    u_invalid = int.__new__(U32, 4294967296)
    with pytest.raises(ValueError):
        u_invalid._dhcp_write(bytearray())


def test_string_invalid_utf8():
    """Bug 8: String decoding handles invalid UTF-8 without losing the packet.

    It also must not lose the *octets*: replacing them made a relay re-encode a
    different hostname or boot filename than it received. They are preserved on
    the value and shown as U+FFFD only where it is rendered.
    """
    data = memoryview(b"\xff\xfe\x00padding")
    s, length = String._dhcp_read(data)
    assert isinstance(s, str)
    assert len(s) > 0

    # the wire bytes survive a round trip
    buf = bytearray()
    s._dhcp_write(buf)
    assert bytes(buf) == b"\xff\xfe"

    # and the rendered form is safe to print or serialize
    assert "\ufffd" in s.__json__()
    s.__json__().encode("utf-8")
