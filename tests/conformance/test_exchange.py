"""The reader, the builder and the comparison the conformance suite stands on.

``exchange`` reads the wire with ``struct`` alone. Ground truth here is the recorded
octets of real peers (the transcripts): what dnsmasq put in an OFFER is read back
as dnsmasq put it, and the same OFFER from this library differs from it in the
ways the two transcripts show.
"""

from __future__ import annotations

import json

import pytest

import exchange

ROLES = {"server", "relay", "client"}
TOPOLOGIES = {"single", "relayed"}


def _transcript(name):
    path = exchange.TRANSCRIPTS / name / "transcript.json"
    return json.loads(path.read_text(encoding="utf-8"))["datagrams"]


def _first(name, sender, kind):
    for datagram in _transcript(name):
        payload = bytes.fromhex(datagram["payload"])
        if datagram["sender"] == sender and exchange.message_type(payload) == kind:
            return payload, datagram["dst"]
    raise AssertionError((name, sender, kind))


def test_the_dnsmasq_offer_reads_as_dnsmasq_sent_it():
    payload, _ = _first("dnsmasq_pydhcp_client_dora", "dnsmasq", "OFFER")

    seen = exchange.read(payload)

    assert seen["xid"] == "e1027a15"
    assert seen["yiaddr"] == "10.99.0.110"
    assert seen["siaddr"] == "10.99.0.1"
    assert [code for code, _ in seen["options"]] == [53, 54, 51, 58, 59, 1, 28, 3]
    assert len(payload) == 300


def test_the_two_offers_differ_where_the_transcripts_show_they_do():
    reference = [_first("dnsmasq_pydhcp_client_dora", "dnsmasq", "OFFER")]
    ours = [_first("dhclient_sync_server_dora", "pydhcp-server", "OFFER")]

    aspects = {d.aspect for d in exchange.differences(reference, ours)}

    assert {
        "option-order",
        "option-absent:58",
        "option-absent:59",
        "field:siaddr",
    } <= aspects


def test_a_reply_that_is_the_reference_has_no_difference():
    payload = _first("dnsmasq_pydhcp_client_dora", "dnsmasq", "OFFER")

    assert exchange.differences([payload], [payload]) == []


def test_a_missing_reply_is_a_count_not_an_absence_of_difference():
    payload = _first("dnsmasq_pydhcp_client_dora", "dnsmasq", "OFFER")

    found = exchange.differences([payload], [])

    assert [(d.reply, d.aspect, d.reference, d.ours) for d in found] == [
        (None, "count", "1", "0")
    ]


def test_not_compared_leaves_out_exactly_the_aspects_it_names():
    reference = [_first("dnsmasq_pydhcp_client_dora", "dnsmasq", "OFFER")]
    ours = [_first("dhclient_sync_server_dora", "pydhcp-server", "OFFER")]
    everything = {d.aspect for d in exchange.differences(reference, ours)}

    left = {
        d.aspect
        for d in exchange.differences(reference, ours, ["field:xid", "option-absent:*"])
    }

    assert everything - left == {
        a for a in everything if a == "field:xid" or a.startswith("option-absent:")
    }
    assert "field:xid" in everything and "option-order" in left


def _message(**fields):
    base = {
        "type": "OFFER",
        "reply": True,
        "xid": "1001a001",
        "chaddr": "02:00:00:99:00:02",
        "yiaddr": "10.99.0.100",
    }
    base.update(fields)
    return exchange.build(base)


def test_a_built_message_is_padded_to_300_and_reads_back_field_by_field():
    payload = _message(
        flags=32768,
        siaddr="10.99.0.1",
        lease=300,
        server_id="10.99.0.1",
        options=[[1, "ffffff00"]],
    )

    seen = exchange.read(payload)

    assert len(payload) == 300 and payload[236:240] == bytes([99, 130, 83, 99])
    assert (seen["op"], seen["xid"], seen["flags"], seen["yiaddr"], seen["siaddr"]) == (
        "2",
        "1001a001",
        "8000",
        "10.99.0.100",
        "10.99.0.1",
    )
    assert seen["chaddr"].startswith("020000990002") and seen["hlen"] == "6"
    assert seen["options"] == [
        (53, "02"),
        (54, "0a630001"),
        (51, "0000012c"),
        (1, "ffffff00"),
    ]


def test_padding_is_what_follows_end():
    payload = _message()

    seen = exchange.read(payload)

    assert len(seen["after_end"]) // 2 == 300 - (240 + 3 + 1)


def test_a_message_longer_than_300_is_not_cut():
    payload = _message(options=[[43, "aa" * 250], [60, "bb" * 40]])

    assert len(payload) > 300 and len(exchange.read(payload)["options"]) == 3


def test_option_52_is_refused_rather_than_read_around():
    with pytest.raises(ValueError):
        exchange.read(_message(options=[[52, "01"]]))


def test_a_truncated_option_is_refused():
    payload = bytearray(_message())
    payload[240:] = bytes([53, 9, 2])

    with pytest.raises(ValueError):
        exchange.read(bytes(payload))


def test_the_text_of_option_56_compares_for_presence_only():
    one = _message(options=[[56, "6e6f"]])
    other = _message(options=[[56, "7965732c20736f"]])
    without = _message()

    assert (
        exchange.differences(
            [(one, "a:1")], [(other, "a:1")], ["padding", "option-order"]
        )
        == []
    )
    assert [
        d.aspect for d in exchange.differences([(one, "a:1")], [(without, "a:1")])
    ] == ["option-absent:56"]


def test_one_differing_octet_of_an_option_is_an_option_value():
    one = _message(options=[[1, "ffffff00"]])
    other = _message(options=[[1, "ffff0000"]])

    found = exchange.differences([(one, "a:1")], [(other, "a:1")])

    assert [(d.aspect, d.reference, d.ours) for d in found] == [
        ("option-value:1", "ffffff00", "ffff0000")
    ]


def test_the_destination_is_compared():
    payload = _message()

    found = exchange.differences(
        [(payload, "255.255.255.255:68")], [(payload, "10.99.0.100:68")]
    )

    assert [(d.aspect, d.reference, d.ours) for d in found] == [
        ("destination", "255.255.255.255:68", "10.99.0.100:68")
    ]


def test_a_reply_answers_with_the_identity_of_its_request():
    request = exchange.build(
        {
            "type": "DISCOVER",
            "xid": "deadbeef",
            "chaddr": "02:00:00:99:00:03",
            "flags": 32768,
            "giaddr": "10.99.0.1",
            "hops": 2,
        }
    )

    reply = exchange.read(
        exchange.answer(
            request, {"type": "OFFER", "xid": "00000000", "yiaddr": "10.99.0.100"}
        )
    )

    assert (
        reply["op"],
        reply["xid"],
        reply["flags"],
        reply["giaddr"],
        reply["hops"],
    ) == ("2", "deadbeef", "8000", "10.99.0.1", "2")
    assert reply["chaddr"][:12] == "020000990003" and reply["yiaddr"] == "10.99.0.100"


def test_the_summary_says_the_type_and_the_options():
    payload, _ = _first("dnsmasq_pydhcp_client_dora", "dnsmasq", "OFFER")

    text = exchange.summary(payload)

    assert (
        text.startswith("OFFER xid=e1027a15 yiaddr=10.99.0.110")
        and "options[53 54 51 58 59 1 28 3]" in text
    )


def test_the_case_directory_holds_nothing_but_cases():
    names = {p.name for p in exchange.CASES.iterdir()}

    assert names == {p.name for p in exchange.cases()}
    assert len(names) >= 15


def _messages(case):
    for step in case["steps"]:
        if "message" in step:
            yield step["message"]
    for reply in case["config"].get("replies", {}).values():
        yield dict(reply, reply=True, xid="00000001", chaddr="02:00:00:99:00:02")


@pytest.mark.parametrize("directory", exchange.cases(), ids=lambda d: d.name)
def test_a_case_loads_and_every_message_in_it_builds(directory):
    case = exchange.load(directory)

    assert (
        case["description"] and case["role"] in ROLES and case["topology"] in TOPOLOGIES
    )
    assert directory.name.startswith(case["role"] + "-")
    for message in _messages(case):
        payload = exchange.build(message)
        assert len(payload) >= 300
        assert exchange.read(payload)["options"]


@pytest.mark.parametrize("directory", exchange.cases(), ids=lambda d: d.name)
def test_a_case_names_its_steps_once_and_gives_every_left_out_aspect_a_reason(
    directory,
):
    case = exchange.load(directory)
    names = [step["name"] for step in case["steps"]]

    assert len(names) == len(set(names))
    for entry in case["not_compared"]:
        assert (
            set(entry) == {"aspect", "step", "why"}
            and entry["why"]
            and entry["step"] in names
        )
