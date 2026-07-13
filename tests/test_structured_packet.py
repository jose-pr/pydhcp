from __future__ import annotations

import pytest
from datetime import timedelta

from pydhcp import DhcpMessage, DhcpOptions
from pydhcp.enum import OpCode, HardwareAddressType, Flags, DhcpOptionCode, DhcpMessageType
from pydhcp.netutils import IPv4
from pydhcp.structured import dump_message, load_mapping, load_message
from pydhcp import structured


def _sample_packet() -> DhcpMessage:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x12345678,
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


@pytest.mark.parametrize("format_name", ["json", "yaml", "toml", "ini"])
def test_packet_structured_round_trip_for_each_format(format_name: str) -> None:
    if format_name == "toml" and (
        structured._tomllib is None or structured._tomli_w is None
    ):
        pytest.skip("TOML packet round trip requires optional TOML dependencies")

    packet = _sample_packet()

    text = dump_message(packet, format_name)
    restored = load_message(text, format_name)

    assert restored.to_mapping() == packet.to_mapping()
    assert restored.encode() == packet.encode()

    if format_name == "ini":
        assert "[message]" in text
        assert "[options]" in text


def test_toml_decode_without_reader_reports_not_implemented(monkeypatch) -> None:
    monkeypatch.setattr(structured, "_tomllib", None)

    with pytest.raises(NotImplementedError, match="INI format as a stdlib fallback"):
        load_mapping("[message]\nop = 'BOOTREQUEST'\n", "toml")


def test_toml_encode_without_writer_reports_not_implemented(monkeypatch) -> None:
    packet = _sample_packet()
    monkeypatch.setattr(structured, "_tomli_w", None)

    with pytest.raises(NotImplementedError, match="INI format as a stdlib fallback"):
        dump_message(packet, "toml")
