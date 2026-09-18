import logging
import pytest
from datetime import timedelta
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.packet.message import DhcpMessage
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4
from pydhcp.options import DhcpOptions


def test_message_encode_decode():
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER.value]
    )
    options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray([1, 0, 17, 34, 51, 68, 85])
    options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = bytearray([1, 3, 6, 15])

    msg = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
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

    encoded = msg.encode()
    assert len(encoded) >= 240

    decoded = DhcpMessage.decode(encoded)
    assert decoded.op == OpCode.BOOTREQUEST
    assert decoded.xid == 0x3903F326
    assert decoded.chaddr.startswith(b"\x00\x11\x22\x33\x44\x55")
    assert (
        decoded.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE)
        == DhcpMessageType.DHCPDISCOVER
    )


def test_message_edge_cases():
    # Message with sname and file populated
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPOFFER.value]
    )
    msg = DhcpMessage(
        op=OpCode.BOOTREPLY,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=1,
        xid=0x11112222,
        secs=timedelta(seconds=5),
        flags=Flags.BROADCAST,
        ciaddr=IPv4("192.168.1.5"),
        yiaddr=IPv4("192.168.1.10"),
        siaddr=IPv4("192.168.1.1"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        sname="my-server-name",
        file="boot-file-path",
        options=options,
    )
    encoded = msg.encode()
    decoded = DhcpMessage.decode(encoded)
    assert decoded.sname.startswith("my-server-name")
    assert decoded.file.startswith("boot-file-path")
    assert decoded.hops == 1
    assert decoded.secs == timedelta(seconds=5)
    assert decoded.flags == Flags.BROADCAST
    assert decoded.ciaddr == IPv4("192.168.1.5")
    assert decoded.yiaddr == IPv4("192.168.1.10")
    assert decoded.siaddr == IPv4("192.168.1.1")

    # String representations
    log_str = msg.log_str(IPv4("192.168.1.1"), IPv4("192.168.1.10"))
    assert "XID=11112222" in log_str


# --- Packet logging must never cost a packet its handler or its reply ---
#
# The listener calls msg.log() before handle(), and the server calls it before
# transport.send(), so anything that raises here is a silent packet drop.


def _discover_with(code, payload):
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER.value]
    )
    options[code] = bytearray(payload)
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x11223344,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=bytearray(b"\x00\x11\x22\x33\x44\x55"),
        sname="",
        file="",
        options=options,
    )


@pytest.mark.parametrize(
    "code,payload,label",
    [
        (224, b"\x01\x02\x03", "site-specific code with no enum member (RFC 3942)"),
        (DhcpOptionCode.ROUTER, b"\x01\x02", "truncated ROUTER payload"),
        (DhcpOptionCode.RAPID_COMMIT, b"", "zero-length RAPID_COMMIT (RFC 4039)"),
    ],
)
def test_dumps_tolerates_undecodable_options(code, payload, label):
    """dumps() must degrade per option to hex, the way to_mapping() already does.

    93 of 254 option codes are not enum members, including 28 in the private-use
    range, so raising here means a client sending any of them gets no service.
    """
    message = _discover_with(code, payload)

    dumped = message.dumps()

    assert "DHCPDISCOVER" in dumped
    assert str(int(code)) in dumped


def test_log_is_lazy_and_never_raises(caplog):
    """log() must do no formatting work when the level is disabled, and must not
    propagate a formatting failure to its caller."""
    message = _discover_with(224, b"\x01\x02\x03")

    calls = []
    original_dumps = type(message).dumps

    def counting_dumps(self, *args, **kwargs):
        calls.append(1)
        return original_dumps(self, *args, **kwargs)

    type(message).dumps = counting_dumps
    try:
        with caplog.at_level(logging.WARNING, logger="pydhcp"):
            message.log("src", "dst", logging.DEBUG)
        assert calls == [], "dumps() ran even though DEBUG was disabled"

        with caplog.at_level(logging.DEBUG, logger="pydhcp"):
            message.log("src", "dst", logging.DEBUG)
        assert calls == [1], "dumps() did not run when DEBUG was enabled"
    finally:
        type(message).dumps = original_dumps


def test_encode_clears_a_stale_option_overload():
    """A decoded overloaded packet carries its sender's option 52.

    Re-encoding it (a relay forwarding a PXE reply) must not keep the marker:
    decode moves the real sname/file out of the overloaded fields, so a stale 52
    tells the receiver to parse literal text as options.
    """
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPACK.value]
    )
    options[DhcpOptionCode.OPTION_OVERLOAD] = bytearray([3])
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    message.options = options
    message.sname = "10.0.0.5"
    message.file = "pxelinux.0"

    wire = bytes(message.encode())
    decoded = DhcpMessage.decode(bytearray(wire))

    assert DhcpOptionCode.OPTION_OVERLOAD not in decoded.options
    assert decoded.sname == "10.0.0.5"
    assert decoded.file == "pxelinux.0"


def test_encode_raises_rather_than_dropping_options_that_do_not_fit():
    """Encoding more options than the packet can hold must raise, not truncate.

    This reaches the up-front size check. The matching guard after the sname
    field is packed is defensive: no input was found that reaches it once the
    size accounting is correct, but leftover was previously discarded there
    without inspection.
    """
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPACK.value]
    )
    for index in range(12):
        options[200 + index] = bytearray(b"X" * 250)
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    message.options = options

    with pytest.raises(OverflowError):
        message.encode(576)


def test_decode_tolerates_non_utf8_sname_and_file():
    """RFC 2131 says NVT ASCII, but senders put other encodings there. Rejecting
    the field threw away the whole packet, message type and client id included."""
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER.value]
    )
    message = _discover_with(DhcpOptionCode.SERVER_IDENTIFIER, b"\x0a\x00\x00\x01")
    wire = bytearray(message.encode())
    # Splice latin-1 bytes into the sname (offset 44) and file (offset 108) fields.
    wire[44:52] = b"caf\xe9-srv"
    wire[108:116] = b"b\xfcte.cfg"

    decoded = DhcpMessage.decode(wire)

    assert decoded.options.get(DhcpOptionCode.DHCP_MESSAGE_TYPE) == (
        DhcpMessageType.DHCPDISCOVER
    )
    assert decoded.sname and decoded.file
