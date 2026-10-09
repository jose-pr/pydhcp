"""The filter keys of DHCP: `op`, `msg_type`, `xid`, `client_id`, `chaddr` and `option.NAME`.

pktcap's filter grammar over the registry `capture_dissector()` builds. Each test
compiles an expression and applies it to a frame dissected from the octets of a
message, so what a key means is what a frame holds, not what a helper computes.
"""

from __future__ import annotations

import pytest

pktcap = pytest.importorskip("pktcap")

from helpers import build_request
from ipaddress import IPv4Address as IPv4
from pydhcp import DHCPMessage, DHCPOptions
from pydhcp.capture import capture_dissector
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPFlags, DHCPMessageType

CHADDR = b"\x00\x11\x22\x33\x44\x55"
# A hardware address with hex letters in it, so a case-insensitive comparison is
# actually exercised; this is the address `pydhcp interfaces` was measured
# printing as `68-F7-D8-E5-1E-83`.
ALPHA_CHADDR = bytes.fromhex("68f7d8e51e83")


def compile_filter(text):
    """pktcap's filter over the registry that knows DHCP, as a predicate of a frame."""
    registry = capture_dissector().registry
    return pktcap.compile_capture_filter(text, pktcap.frame_filter_for(registry))


def _message(
    message_type: DHCPMessageType = DHCPMessageType.DHCPDISCOVER,
    chaddr: bytes = CHADDR,
) -> DHCPMessage:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = message_type
    options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytearray(b"\x01" + chaddr)
    return build_request(
        options=options, xid=0x1234ABCD, flags=DHCPFlags.BROADCAST, chaddr=chaddr
    )


def _event(message: "DHCPMessage | None" = None) -> "pktcap.DissectedFrame":
    """The frame of a message sent by 192.0.2.55:68 to 192.0.2.1:67."""
    datagram = pktcap.CapturedDatagram(
        1784032215.0,
        ("192.0.2.55", 68),
        ("192.0.2.1", 67),
        bytes((message or _message()).encode()),
    )
    return capture_dissector().dissect(pktcap.datagram_frame(datagram))


@pytest.mark.parametrize(
    "filter_text",
    [
        None,
        "",
        "op=BOOTREQUEST",
        "msg_type=DHCPDISCOVER and sport=68",
        "xid=0x1234ABCD",
        "client_id=01:00:11:22:33:44:55",
        "chaddr=00:11:22:33:44:55",
        "src=192.0.2.55 and dst=192.0.2.1",
        "option.DHCP_MESSAGE_TYPE=DHCPDISCOVER",
        "option.53=DHCPDISCOVER",
    ],
)
def test_the_filter_accepts_supported_expressions(filter_text) -> None:
    assert compile_filter(filter_text)(_event())


@pytest.mark.parametrize(
    "filter_text",
    [
        "msg_type=DHCPREQUEST",
        "sport=67",
        "option.DHCP_MESSAGE_TYPE=DHCPREQUEST",
    ],
)
def test_the_filter_rejects_non_matching_events(filter_text: str) -> None:
    assert not compile_filter(filter_text)(_event())


@pytest.mark.parametrize(
    "filter_text",
    [
        "msg_type",
        "=DHCPDISCOVER",
        "foo=bar",
        "option.NOT_A_REAL_OPTION=1",
        "msg_type=DHCPDISCOVER or xid=1",
    ],
)
def test_the_filter_rejects_malformed_expressions(filter_text: str) -> None:
    with pytest.raises(ValueError):
        compile_filter(filter_text)


@pytest.mark.parametrize("joiner", ["and", "AND", "And"])
def test_the_filter_joins_clauses_in_any_case(joiner: str) -> None:
    """An uppercase `AND` used to be swallowed into the preceding value.

    Measured before this: `src=192.0.2.55 AND msg_type=DHCPDISCOVER` compiled to
    a single `src=` clause whose value was the whole remainder, so the capture
    matched nothing and exited 0 -- the same output as a quiet segment.
    """
    event = _event()

    assert compile_filter(f"src=192.0.2.55 {joiner} msg_type=DHCPDISCOVER")(event)
    # the second clause is really evaluated, not just parsed away
    assert not compile_filter(f"src=192.0.2.55 {joiner} msg_type=DHCPREQUEST")(event)


@pytest.mark.parametrize("joiner", ["or", "OR", "Or"])
def test_the_filter_rejects_or_in_any_case(joiner: str) -> None:
    with pytest.raises(ValueError, match="'and' only"):
        compile_filter(f"msg_type=DHCPDISCOVER {joiner} msg_type=DHCPOFFER")


@pytest.mark.parametrize(
    "filter_text",
    [
        "xid=zz",
        "xid=0xnope",
        "sport=abc",
        "dport=six",
        "src=not.an.ip",
        "dst=192.0.2.300",
    ],
)
def test_the_filter_rejects_bad_values_at_compile_time(
    filter_text: str,
) -> None:
    """A bad value is one startup error, not one per packet.

    These used to compile and then raise from inside the listener's per-packet
    handler for every packet on the segment (or, for `src`/`dst`, to silently
    match nothing).
    """
    with pytest.raises(ValueError):
        compile_filter(filter_text)


@pytest.mark.parametrize(
    "filter_text",
    [
        f"xid={0x1234ABCD}",
        "xid=0x1234abcd",
        "sport=68",
        "src=192.0.2.55",
        "dst=192.0.2.1",
    ],
)
def test_the_filter_accepts_well_formed_values(filter_text: str) -> None:
    assert compile_filter(filter_text)(_event())


@pytest.mark.parametrize(
    "value",
    [
        "68-F7-D8-E5-1E-83",  # exactly what `pydhcp interfaces` prints
        "68:F7:D8:E5:1E:83",
        "68:f7:d8:e5:1e:83",
        "68f7.d8e5.1e83",
        "68f7d8e51e83",
    ],
)
def test_chaddr_filter_ignores_separator_and_case(value: str) -> None:
    """Copy-pasting a MAC out of `pydhcp interfaces` has to work.

    The comparison was colon-form-only, which is the one form that command does
    not print -- so the pasted filter matched nothing, silently.
    """
    event = _event(_message(chaddr=ALPHA_CHADDR))

    assert compile_filter(f"chaddr={value}")(event)


@pytest.mark.parametrize(
    "value",
    [
        "01-68-F7-D8-E5-1E-83",
        "01:68:F7:D8:E5:1E:83",
        "01:68:f7:d8:e5:1e:83",
        "0168f7d8e51e83",
    ],
)
def test_client_id_filter_ignores_separator_and_case(value: str) -> None:
    event = _event(_message(chaddr=ALPHA_CHADDR))

    assert compile_filter(f"client_id={value}")(event)


def test_hardware_address_filters_still_reject_other_addresses() -> None:
    event = _event(_message(chaddr=ALPHA_CHADDR))

    assert not compile_filter("chaddr=68-F7-D8-E5-1E-84")(event)
    assert not compile_filter("client_id=01-68-F7-D8-E5-1E-84")(event)


# -- what a value may be: one that no packet could match is refused at compile time ----


@pytest.mark.parametrize(
    "filter_text",
    [
        "msg_type=DISCOVER",  # the name is DHCPDISCOVER
        "msg_type=256",
        "msg_type=0x100",
        "msg_type=TYPE_999",
        "op=REQUEST",  # the names are BOOTREQUEST and BOOTREPLY
        "op=300",
        "client_id=not-hex",
        "client_id=01:zz",
        "client_id=abc",  # an odd number of digits is no octets
        "client_id=" + "ab" * 256,  # an option holds 255 octets at most
        "chaddr=zz:zz",
        "chaddr=0:",
        "chaddr=" + "ab" * 17,  # `hlen` is 16 at most
        "xid=0x100000000",
        "xid=-1",
        "sport=70000",
        "dport=-1",
        "option.999=x",
        "option.0=x",
        "option.255=x",
        "msg_type=,",
    ],
)
def test_a_value_no_packet_could_match_is_refused_when_compiled(
    filter_text: str,
) -> None:
    with pytest.raises(pktcap.CaptureFilterError):
        compile_filter(filter_text)


def test_the_refusal_of_a_name_lists_the_names() -> None:
    with pytest.raises(ValueError) as refused:
        compile_filter("msg_type=DISCOVER")
    assert "DHCPDISCOVER" in str(refused.value) and "DHCPNAK" in str(refused.value)
    with pytest.raises(ValueError, match="BOOTREPLY"):
        compile_filter("op=REQUEST")


@pytest.mark.parametrize(
    "filter_text",
    [
        "msg_type=dhcpdiscover",
        "msg_type=DhcpDiscover",
        "msg_type=1",
        "msg_type=0x01",
        "op=bootrequest",
        "op=1",
        "op=0x1",
    ],
)
def test_a_name_in_any_case_or_a_number_selects_the_message(filter_text: str) -> None:
    assert compile_filter(filter_text)(_event())


@pytest.mark.parametrize(
    "filter_text", ["msg_type=2", "msg_type=dhcpoffer", "op=2", "op=bootreply"]
)
def test_a_name_or_number_of_another_value_selects_nothing(filter_text: str) -> None:
    assert not compile_filter(filter_text)(_event())


def test_an_unnamed_message_type_is_selected_by_its_number_or_its_label() -> None:
    event = _event(_message(DHCPMessageType(99)))

    assert compile_filter("msg_type=99")(event)
    assert compile_filter("msg_type=TYPE_99")(event)
    assert not compile_filter("msg_type=TYPE_98")(event)
    assert not compile_filter("msg_type=UNKNOWN")(event)


def test_a_message_with_no_type_is_selected_as_unknown_and_by_no_number() -> None:
    event = _event(build_request(message_type=None))

    assert compile_filter("msg_type=UNKNOWN")(event)
    assert compile_filter("msg_type!=DHCPDISCOVER")(event)
    assert not compile_filter("msg_type=DHCPDISCOVER")(event)
    assert not compile_filter("msg_type=0")(event)


def test_a_clause_negated_selects_everything_the_clause_does_not() -> None:
    discover, offer = _event(), _event(_message(DHCPMessageType.DHCPOFFER))
    not_offer = compile_filter("msg_type!=DHCPOFFER")

    assert not_offer(discover) and not not_offer(offer)
    both = compile_filter("msg_type!=DHCPOFFER and src=192.0.2.55")
    assert both(discover) and not both(offer)


def test_a_comma_means_any_of_for_every_key_but_an_option() -> None:
    discover, offer = _event(), _event(_message(DHCPMessageType.DHCPOFFER))
    for text in (
        "msg_type=DHCPDISCOVER,DHCPREQUEST",
        "msg_type=dhcpack, 1",
        "op=BOOTREPLY,BOOTREQUEST",
        "xid=1,0x1234ABCD",
        "client_id=ff:ff,01:00:11:22:33:44:55",
        "chaddr=aa:bb:cc:dd:ee:ff,00-11-22-33-44-55",
        "src=192.0.2.1,192.0.2.55",
        "sport=67,68",
        "dst=192.0.2.9,192.0.2.1",
    ):
        assert compile_filter(text)(discover), text
    assert not compile_filter("msg_type=DHCPACK,DHCPREQUEST")(discover)
    assert compile_filter("msg_type=DHCPDISCOVER,DHCPOFFER")(offer)
    assert not compile_filter("src=192.0.2.1,192.0.2.2")(discover)
    assert not compile_filter("msg_type!=DHCPDISCOVER,DHCPOFFER")(offer)


def test_the_text_of_an_option_is_compared_whole_with_its_commas() -> None:
    message = _message()
    message.options[DHCPOptionCode.HOSTNAME] = "a,b"
    event = _event(message)

    assert compile_filter("option.HOSTNAME=a,b")(event)
    assert compile_filter("option.12=a,b")(event)
    assert not compile_filter("option.HOSTNAME=a")(event)


@pytest.mark.parametrize(
    "filter_text",
    ["msg_type=DHCPDISCOVER and", "option.12=x and", "and", "src=192.0.2.55 and "],
)
def test_a_filter_ending_in_and_is_refused(filter_text: str) -> None:
    """`option.12=x and` used to compile, with the word `and` as part of the value."""
    with pytest.raises(pktcap.CaptureFilterError):
        compile_filter(filter_text)


def test_a_filter_names_the_clause_it_refuses() -> None:
    with pytest.raises(pktcap.CaptureFilterError, match="msg_type=DISCOVER"):
        compile_filter("src=192.0.2.55 and msg_type=DISCOVER")
