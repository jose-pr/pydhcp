"""The pktcap plugin: the keys it registers, what each selects, and what it leaves alone.

The capture holds every message type and the odd messages a filter meets (no option 53, an
unnamed type, no client identity, a 16-octet hardware address, a hostname that is not UTF-8).
Ground truth is the octets written into it, never the plugin's own conversions.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import typing as _ty
import uuid

import pktcap
import pytest

import pydhcp.capture
from capture_input import datagrams
from pydhcp import DHCPMessage
from pydhcp.capture import DHCPLayer, dissect_dhcp, pktcap_plugin
from pydhcp.options import DHCPOptionCode

CLIENT, SERVER = ("0.0.0.0", 68), ("192.0.2.1", 67)
STRANGER = ("192.0.2.77", 9999)


def _edited(index: int, change: "_ty.Callable[[DHCPMessage], None]") -> bytes:
    message = DHCPMessage.decode(datagrams()[index])
    change(message)
    return bytes(message.encode())


def _typed(number: int) -> "_ty.Callable[[DHCPMessage], None]":
    def change(message: DHCPMessage) -> None:
        message.options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = bytes([number])

    return change


def _untyped(message: DHCPMessage) -> None:
    del message.options[DHCPOptionCode.DHCP_MESSAGE_TYPE]


def _anonymous(message: DHCPMessage) -> None:
    message.hlen = 0
    message.chaddr = b""
    if DHCPOptionCode.CLIENT_IDENTIFIER in message.options:
        del message.options[DHCPOptionCode.CLIENT_IDENTIFIER]


def _long_hardware_address(message: DHCPMessage) -> None:
    message.hlen = 16
    message.chaddr = bytes(range(1, 17))


def _hostname_not_text(message: DHCPMessage) -> None:
    message.options[DHCPOptionCode.HOSTNAME] = b"\xff\xfeab"


def _xid(number: int) -> "_ty.Callable[[DHCPMessage], None]":
    def change(message: DHCPMessage) -> None:
        message.xid = number

    return change


def _corpus() -> "list[bytes]":
    """The 53 recorded messages (every one a DISCOVER, OFFER, REQUEST or ACK), then the rest."""
    extra = [_edited(0, _typed(number)) for number in (4, 6, 7, 8, 99)]
    extra += [
        _edited(0, _untyped),
        _edited(1, _untyped),
        _edited(0, _anonymous),
        _edited(0, _long_hardware_address),
        _edited(0, _hostname_not_text),
        _edited(2, _xid(0)),
        _edited(3, _xid(0xFFFFFFFF)),
    ]
    return datagrams() + extra


DATAGRAMS = _corpus()


def _option(data: bytes, wanted: int) -> "_ty.Optional[int]":
    """The first octet of option `wanted`, walked from the octets after the magic cookie."""
    at = 240
    while at < len(data) and data[at] != 255:
        if data[at] == 0:
            at += 1
            continue
        if data[at] == wanted:
            return data[at + 2]
        at += 2 + data[at + 1]
    return None


def _write(path: pathlib.Path, payloads: "_ty.Sequence[bytes]") -> None:
    with pktcap.PcapWriter(path) as writer:
        for index, payload in enumerate(payloads):
            source, destination = (
                (CLIENT, SERVER) if payload[0] == 1 else (SERVER, CLIENT)
            )
            writer.write(1_700_000_000.0 + index, source, destination, payload)


@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    path = tmp_path_factory.mktemp("plugin") / "every_type.pcap"
    _write(path, DATAGRAMS)
    return path


def _registry() -> pktcap.DissectorRegistry:
    registry = pktcap.DissectorRegistry()
    pktcap_plugin(registry)
    return registry


def _frame_selection(
    capture: pathlib.Path, text: str, registry: pktcap.DissectorRegistry
) -> "list[int]":
    wanted = pktcap.compile_capture_filter(text, pktcap.frame_filter_for(registry))
    frames = pktcap.read_dissected(
        str(capture), dissector=pktcap.FrameDissector(registry)
    )
    return [i for i, frame in enumerate(frames) if wanted(frame)]


# -- what a call registers -----------------------------------------------------------------


def test_the_plugin_declares_the_layer_with_its_six_keys_and_the_dissector_on_both_ports() -> (
    None
):
    registry = _registry()
    assert registry.layers() == {"dhcp": DHCPLayer}
    assert registry.get("udp", 67) is dissect_dhcp
    assert registry.get("udp", 68) is dissect_dhcp
    keys = pktcap.frame_filter_keys(registry)
    for key in ("op", "msg_type", "xid", "client_id", "chaddr", "option"):
        assert key in keys
        assert "dhcp." + key in keys
    # pktcap's own keys, or the library's own trace's: not registered under the DHCP layer.
    for key in ("src_port", "dst_port", "interface"):
        assert key not in keys and "dhcp." + key not in keys
        with pytest.raises(pktcap.CaptureFilterError):
            pktcap.compile_capture_filter(key + "=1", pktcap.frame_filter_for(registry))


def test_the_plugin_is_loaded_by_the_module_name_and_changes_only_the_registry_it_is_given() -> (
    None
):
    registry = pktcap.DissectorRegistry()
    default_before = pktcap.default_registry().selectors()
    (loaded,) = pktcap.load_plugins(registry, "pydhcp.capture")
    assert loaded.name == "pydhcp.capture"
    assert loaded.layers == ("dhcp",)
    assert ("udp", 67) in loaded.selectors and ("udp", 68) in loaded.selectors
    assert pktcap.default_registry().selectors() == default_before
    assert "dhcp" not in pktcap.default_registry().layers()


@pytest.mark.parametrize("taken", [67, 68])
def test_a_dissector_port_that_is_taken_registers_nothing_not_even_the_layer(
    taken: int,
) -> None:
    registry = pktcap.DissectorRegistry()

    def other(data: bytes) -> pktcap.Dissected:  # pragma: no cover - never called
        raise ValueError

    registry.register("udp", taken, other)
    with pytest.raises(ValueError):
        pktcap_plugin(registry)
    assert registry.layers() == {}
    assert registry.get("udp", taken) is other
    assert registry.get("udp", 135 - taken) is None


def test_a_layer_name_that_is_taken_is_the_error_and_the_other_layer_stays() -> None:
    registry = pktcap.DissectorRegistry()

    class DhcpLayer:
        pass

    registry.register_layer(DhcpLayer, name="dhcp")
    with pytest.raises(ValueError):
        pktcap_plugin(registry)
    assert registry.layers() == {"dhcp": DhcpLayer}
    assert registry.get("udp", 67) is None and registry.get("udp", 68) is None


def test_a_second_call_on_one_registry_is_refused_and_leaves_the_first_in_place() -> (
    None
):
    registry = _registry()
    with pytest.raises(ValueError):
        pktcap_plugin(registry)
    assert registry.layers() == {"dhcp": DHCPLayer}
    assert registry.get("udp", 67) is dissect_dhcp


# -- the two filters agree -----------------------------------------------------------------

#: Spellings of the first message's identifiers, then values of the fixed corpus.
_FIRST = DHCPMessage.decode(DATAGRAMS[0])
_XID = _FIRST.xid
_CLIENT_ID = dissect_dhcp(DATAGRAMS[0]).layer.client_id
_CHADDR = _FIRST.chaddr.hex(":")
_DIGITS = _CLIENT_ID.replace(":", "")

AGREE = [
    "op=BOOTREQUEST",
    "op=bootreply",
    "op=BootRequest",
    "op=1",
    "op=2",
    "op=0x1",
    "op=0",
    "op=3",
    "op=255",
    "op=BOOTREQUEST,BOOTREPLY",
    "op=1,2",
    "op!=BOOTREQUEST",
    "op!=1,2",
    "msg_type=DHCPDISCOVER",
    "msg_type=dhcpoffer",
    "msg_type=DhcpAck",
    "msg_type=DHCPDECLINE,DHCPNAK",
    "msg_type=DHCPRELEASE",
    "msg_type=DHCPINFORM",
    "msg_type=1",
    "msg_type=6",
    "msg_type=0x08",
    "msg_type=99",
    "msg_type=0",
    "msg_type=255",
    "msg_type=UNKNOWN",
    "msg_type=unknown",
    "msg_type=TYPE_99",
    "msg_type=type_99",
    "msg_type=TYPE_5",
    "msg_type=TYPE_0",
    "msg_type=DHCPDISCOVER,UNKNOWN,TYPE_99",
    "msg_type!=DHCPDISCOVER",
    "msg_type!=UNKNOWN",
    "msg_type!=DHCPDISCOVER,DHCPOFFER,DHCPREQUEST,DHCPACK",
    f"xid={_XID}",
    f"xid={_XID:#x}",
    f"xid={_XID:#X}",
    f"xid={_XID:#o}",
    f"xid={_XID:#b}",
    f"xid={_XID + 1}",
    "xid=0",
    "xid=0x0",
    "xid=0xFFFFFFFF",
    "xid=4294967295",
    f"xid=0,{_XID},4294967295",
    f"xid!={_XID}",
    f"client_id={_CLIENT_ID}",
    f"client_id={_CLIENT_ID.lower()}",
    f"client_id={_CLIENT_ID.replace(':', '-')}",
    f"client_id={_CLIENT_ID.replace(':', '')}",
    "client_id=" + ".".join(_DIGITS[i : i + 4] for i in range(0, len(_DIGITS), 4)),
    f"client_id={_CLIENT_ID},01:02",
    f"client_id!={_CLIENT_ID}",
    "client_id=00",
    f"chaddr={_CHADDR}",
    f"chaddr={_CHADDR.upper()}",
    f"chaddr={_CHADDR.replace(':', '-')}",
    f"chaddr={_CHADDR.replace(':', '')}",
    "chaddr=0102030405060708090a0b0c0d0e0f10",
    "chaddr=01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10",
    f"chaddr={_CHADDR},0102030405060708090a0b0c0d0e0f10",
    f"chaddr!={_CHADDR}",
    "chaddr=ff",
    "option.HOSTNAME=lab-client",
    "option.12=lab-client",
    "option.HOSTNAME=��ab",
    "option.12=��ab",
    "option.HOSTNAME!=lab-client",
    "option.HOSTNAME=Lab-Client",
    "option.15=example.org",
    "option.3=['10.99.0.1']",
    "option.3=['192.0.2.1', '192.0.2.2']",
    "option.3='10.99.0.1'",
    "option.51=300",
    "option.51=0x12c",
    "option.60=udhcp 1.37.0",
    "option.43=0102ff",
    "option.200=deadbeef",
    "option.61=01020000990002",
    "option.55=[1, 3, 6, 12, 15, 28, 42]",
    "option.55=[1, 3]",
    "option.82=[[1, '6c61622d63697263756974'], [2, '6c61622d72656c6179']]",
    "option.121=[['192.0.2.1', '10.0.0.0/8']]",
    "option.DHCP_MESSAGE_TYPE=DHCPDISCOVER",
    "option.53=DHCPREQUEST",
    "option.53=dhcprequest",
    "option.53!=DHCPREQUEST",
    "option.SERVER_IDENTIFIER=10.99.0.1",
    "option.54=10.98.0.2",
    "option.DOMAIN_NAME=nosuchvalue",
    "option.201=x",
    "option.254=x",
    "op=BOOTREQUEST and msg_type=DHCPDISCOVER",
    "op=BOOTREPLY and msg_type!=DHCPACK",
    f"xid={_XID} and client_id={_CLIENT_ID} and chaddr={_CHADDR}",
]

REFUSED = [
    "op=nosuch",
    "op=256",
    "op=-1",
    "op=0x100",
    "op=1.5",
    "op=BOOTREQUEST,nosuch",
    "op=,",
    "msg_type=DISCOVER",
    "msg_type=256",
    "msg_type=TYPE_256",
    "msg_type=TYPE_",
    "msg_type=DHCPDISCOVER,bogus",
    "xid=x",
    "xid=-1",
    "xid=0x100000000",
    "xid=4294967296",
    "xid=010",
    "xid=1.5",
    "client_id=xyz",
    "client_id=UNKNOWN",
    "client_id=001",
    "client_id=0",
    "client_id=" + "00" * 256,
    "chaddr=zz",
    "chaddr=001",
    "chaddr=" + "00" * 17,
    "option.NOSUCH=1",
    "option.hostname=x",
    "option.0=x",
    "option.255=x",
    "option.-1=x",
]

EXPECTED_EMPTY = [
    "op=0",
    "op=3",
    "op=255",
    "op!=1,2",
    "msg_type=0",
    "msg_type=255",
    "msg_type=TYPE_0",
    f"xid={_XID + 1}",
    "client_id=00",
    "chaddr=ff",
    "option.HOSTNAME=Lab-Client",
    "option.3='10.99.0.1'",
    "option.51=0x12c",
    "option.55=[1, 3]",
    "option.53=dhcprequest",
    "option.DOMAIN_NAME=nosuchvalue",
    "option.201=x",
    "option.254=x",
]


#: The indices in `DATAGRAMS` each row of `AGREE` selects: fixed from an independent
#: reading of the same messages (the filter over decoded messages that this table was
#: first checked against), so a change in what a key means shows here.
# fmt: off
SELECTED = {
    'op=BOOTREQUEST': [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 25, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 52, 53, 54, 55, 56, 57, 58, 60, 61, 62, 63],
    'op=bootreply': [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 50, 51, 59, 64],
    'op=BootRequest': [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 25, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 52, 53, 54, 55, 56, 57, 58, 60, 61, 62, 63],
    'op=1': [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 25, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 52, 53, 54, 55, 56, 57, 58, 60, 61, 62, 63],
    'op=2': [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 50, 51, 59, 64],
    'op=0x1': [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 25, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 52, 53, 54, 55, 56, 57, 58, 60, 61, 62, 63],
    'op=0': [],
    'op=3': [],
    'op=255': [],
    'op=BOOTREQUEST,BOOTREPLY': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64],
    'op=1,2': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64],
    'op!=BOOTREQUEST': [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 50, 51, 59, 64],
    'op!=1,2': [],
    'msg_type=DHCPDISCOVER': [0, 4, 8, 12, 16, 20, 24, 25, 26, 30, 34, 38, 42, 46, 52, 60, 61, 62],
    'msg_type=dhcpoffer': [1, 5, 9, 13, 17, 21, 27, 31, 35, 39, 43, 47, 50, 51],
    'msg_type=DhcpAck': [3, 7, 11, 15, 19, 23, 29, 33, 37, 41, 45, 49, 64],
    'msg_type=DHCPDECLINE,DHCPNAK': [53, 54],
    'msg_type=DHCPRELEASE': [55],
    'msg_type=DHCPINFORM': [56],
    'msg_type=1': [0, 4, 8, 12, 16, 20, 24, 25, 26, 30, 34, 38, 42, 46, 52, 60, 61, 62],
    'msg_type=6': [54],
    'msg_type=0x08': [56],
    'msg_type=99': [57],
    'msg_type=0': [],
    'msg_type=255': [],
    'msg_type=UNKNOWN': [58, 59],
    'msg_type=unknown': [58, 59],
    'msg_type=TYPE_99': [57],
    'msg_type=type_99': [57],
    'msg_type=TYPE_5': [3, 7, 11, 15, 19, 23, 29, 33, 37, 41, 45, 49, 64],
    'msg_type=TYPE_0': [],
    'msg_type=DHCPDISCOVER,UNKNOWN,TYPE_99': [0, 4, 8, 12, 16, 20, 24, 25, 26, 30, 34, 38, 42, 46, 52, 57, 58, 59, 60, 61, 62],
    'msg_type!=DHCPDISCOVER': [1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15, 17, 18, 19, 21, 22, 23, 27, 28, 29, 31, 32, 33, 35, 36, 37, 39, 40, 41, 43, 44, 45, 47, 48, 49, 50, 51, 53, 54, 55, 56, 57, 58, 59, 63, 64],
    'msg_type!=UNKNOWN': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 60, 61, 62, 63, 64],
    'msg_type!=DHCPDISCOVER,DHCPOFFER,DHCPREQUEST,DHCPACK': [53, 54, 55, 56, 57, 58, 59],
    'xid=2310861594': [0, 1, 2, 3, 4, 5, 6, 7, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62],
    'xid=0x89bcf31a': [0, 1, 2, 3, 4, 5, 6, 7, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62],
    'xid=0X89BCF31A': [0, 1, 2, 3, 4, 5, 6, 7, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62],
    'xid=0o21157171432': [0, 1, 2, 3, 4, 5, 6, 7, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62],
    'xid=0b10001001101111001111001100011010': [0, 1, 2, 3, 4, 5, 6, 7, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62],
    'xid=2310861595': [],
    'xid=0': [63],
    'xid=0x0': [63],
    'xid=0xFFFFFFFF': [64],
    'xid=4294967295': [64],
    'xid=0,2310861594,4294967295': [0, 1, 2, 3, 4, 5, 6, 7, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64],
    'xid!=2310861594': [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 63, 64],
    'client_id=01:02:00:00:99:00:02': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 53, 54, 55, 56, 57, 58, 59, 62, 63, 64],
    'client_id=01-02-00-00-99-00-02': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 53, 54, 55, 56, 57, 58, 59, 62, 63, 64],
    'client_id=01020000990002': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 53, 54, 55, 56, 57, 58, 59, 62, 63, 64],
    'client_id=0102.0000.9900.02': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 53, 54, 55, 56, 57, 58, 59, 62, 63, 64],
    'client_id=01:02:00:00:99:00:02,01:02': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 53, 54, 55, 56, 57, 58, 59, 62, 63, 64],
    'client_id!=01:02:00:00:99:00:02': [34, 35, 36, 37, 50, 51, 52, 60, 61],
    'client_id=00': [],
    'chaddr=02:00:00:99:00:02': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 52, 53, 54, 55, 56, 57, 58, 59, 62, 63, 64],
    'chaddr=02-00-00-99-00-02': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 52, 53, 54, 55, 56, 57, 58, 59, 62, 63, 64],
    'chaddr=020000990002': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 52, 53, 54, 55, 56, 57, 58, 59, 62, 63, 64],
    'chaddr=0102030405060708090a0b0c0d0e0f10': [61],
    'chaddr=01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10': [61],
    'chaddr=02:00:00:99:00:02,0102030405060708090a0b0c0d0e0f10': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64],
    'chaddr!=02:00:00:99:00:02': [34, 35, 36, 37, 50, 51, 60, 61],
    'chaddr=ff': [],
    'option.HOSTNAME=lab-client': [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 25, 26, 28, 29, 30, 32, 33, 38, 40, 42, 44, 46, 48, 52, 53, 54, 55, 56, 57, 58, 60, 61, 63],
    'option.12=lab-client': [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 25, 26, 28, 29, 30, 32, 33, 38, 40, 42, 44, 46, 48, 52, 53, 54, 55, 56, 57, 58, 60, 61, 63],
    'option.HOSTNAME=��ab': [62],
    'option.12=��ab': [62],
    'option.HOSTNAME!=lab-client': [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 27, 31, 34, 35, 36, 37, 39, 41, 43, 45, 47, 49, 50, 51, 59, 62, 64],
    'option.HOSTNAME=Lab-Client': [],
    'option.15=example.org': [51],
    "option.3=['10.99.0.1']": [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 59, 64],
    "option.3=['192.0.2.1', '192.0.2.2']": [51],
    "option.3='10.99.0.1'": [],
    'option.51=300': [27, 29, 31, 33, 35, 37],
    'option.51=0x12c': [],
    'option.60=udhcp 1.37.0': [38, 40, 42, 44, 46, 48],
    'option.43=0102ff': [51],
    'option.200=deadbeef': [51],
    'option.61=01020000990002': [38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49],
    'option.55=[1, 3, 6, 12, 15, 28, 42]': [38, 40, 42, 44],
    'option.55=[1, 3]': [],
    "option.82=[[1, '6c61622d63697263756974'], [2, '6c61622d72656c6179']]": [4, 5, 6, 7, 16, 17, 18, 19, 30, 31, 32, 33, 42, 43, 44, 45],
    "option.121=[['192.0.2.1', '10.0.0.0/8']]": [51],
    'option.DHCP_MESSAGE_TYPE=DHCPDISCOVER': [0, 4, 8, 12, 16, 20, 24, 25, 26, 30, 34, 38, 42, 46, 52, 60, 61, 62],
    'option.53=DHCPREQUEST': [2, 6, 10, 14, 18, 22, 28, 32, 36, 40, 44, 48, 63],
    'option.53=dhcprequest': [],
    'option.53!=DHCPREQUEST': [0, 1, 3, 4, 5, 7, 8, 9, 11, 12, 13, 15, 16, 17, 19, 20, 21, 23, 24, 25, 26, 27, 29, 30, 31, 33, 34, 35, 37, 38, 39, 41, 42, 43, 45, 46, 47, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 64],
    'option.SERVER_IDENTIFIER=10.99.0.1': [9, 10, 11, 21, 22, 23, 35, 36, 37, 47, 48, 49],
    'option.54=10.98.0.2': [1, 2, 3, 5, 6, 7, 13, 14, 15, 17, 18, 19, 27, 28, 29, 31, 32, 33, 39, 40, 41, 43, 44, 45, 59, 63, 64],
    'option.DOMAIN_NAME=nosuchvalue': [],
    'option.201=x': [],
    'option.254=x': [],
    'op=BOOTREQUEST and msg_type=DHCPDISCOVER': [0, 4, 8, 12, 16, 20, 24, 25, 26, 30, 34, 38, 42, 46, 52, 60, 61, 62],
    'op=BOOTREPLY and msg_type!=DHCPACK': [1, 5, 9, 13, 17, 21, 27, 31, 35, 39, 43, 47, 50, 51, 59],
    'xid=2310861594 and client_id=01:02:00:00:99:00:02 and chaddr=02:00:00:99:00:02': [0, 1, 2, 3, 4, 5, 6, 7, 53, 54, 55, 56, 57, 58, 59, 62],
}
DOTTED_OP_REPLY = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 50, 51, 59, 64]
# fmt: on


@pytest.mark.parametrize("text", AGREE)
def test_a_key_selects_the_messages_it_selected_when_the_table_was_fixed(
    capture: pathlib.Path, text: str
) -> None:
    assert _frame_selection(capture, text, _registry()) == SELECTED[text]


def test_the_table_selects_something_for_most_rows_so_it_is_not_a_table_of_nothing() -> (
    None
):
    empty = [text for text in AGREE if not SELECTED[text]]
    assert empty == EXPECTED_EMPTY
    assert len(empty) < len(AGREE) // 4


@pytest.mark.parametrize(
    ("text", "wanted"),
    [
        ("msg_type=DHCPDISCOVER", lambda d: _option(d, 53) == 1),
        ("msg_type=DHCPNAK", lambda d: _option(d, 53) == 6),
        ("msg_type=TYPE_99", lambda d: _option(d, 53) == 99),
        ("msg_type=UNKNOWN", lambda d: _option(d, 53) is None),
        ("msg_type!=UNKNOWN", lambda d: _option(d, 53) is not None),
        ("op=BOOTREPLY", lambda d: d[0] == 2),
        ("xid=0", lambda d: d[4:8] == bytes(4)),
        ("xid=0xFFFFFFFF", lambda d: d[4:8] == b"\xff" * 4),
        (
            "chaddr=0102030405060708090a0b0c0d0e0f10",
            lambda d: d[28:44] == bytes(range(1, 17)),
        ),
    ],
)
def test_the_selection_is_what_the_octets_say(
    capture: pathlib.Path, text: str, wanted: "_ty.Callable[[bytes], bool]"
) -> None:
    expected = [i for i, data in enumerate(DATAGRAMS) if wanted(data)]
    assert _frame_selection(capture, text, _registry()) == expected


@pytest.mark.parametrize("text", REFUSED)
def test_a_value_no_message_could_match_is_refused_when_the_filter_is_compiled(
    text: str,
) -> None:
    with pytest.raises(pktcap.CaptureFilterError):
        pktcap.compile_capture_filter(text, pktcap.frame_filter_for(_registry()))


def test_the_bare_option_key_names_no_option_and_is_refused() -> None:
    with pytest.raises(pktcap.CaptureFilterError) as caught:
        pktcap.compile_capture_filter("option=12", pktcap.frame_filter_for(_registry()))
    assert "option.HOSTNAME" in str(caught.value)


def test_the_keys_are_reached_by_the_layer_name_too(capture: pathlib.Path) -> None:
    registry = _registry()
    for bare, dotted in [
        ("op=BOOTREPLY", "dhcp.op=BOOTREPLY"),
        ("msg_type=DHCPNAK", "dhcp.msg_type=DHCPNAK"),
        ("option.HOSTNAME=client-7", "dhcp.option.HOSTNAME=client-7"),
        ("option.12=client-7", "DHCP.option.12=client-7"),
    ]:
        selected = _frame_selection(capture, bare, registry)
        assert _frame_selection(capture, dotted, registry) == selected


def test_a_frame_with_no_dhcp_layer_fails_a_clause_and_holds_its_negation(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "mixed.pcap"
    with pktcap.PcapWriter(path) as writer:
        writer.write(1.0, CLIENT, STRANGER, b"hello")
        writer.write(2.0, CLIENT, SERVER, DATAGRAMS[0])
    registry = _registry()
    assert _frame_selection(path, "op=BOOTREQUEST", registry) == [1]
    assert _frame_selection(path, "op!=BOOTREQUEST", registry) == [0]
    assert _frame_selection(path, "msg_type!=DHCPOFFER", registry) == [0, 1]
    assert _frame_selection(path, "option.HOSTNAME!=x", registry) == [0, 1]


# -- importing leaves everything alone -----------------------------------------------------

_FRESH = """
import pktcap
default = pktcap.default_registry()
selectors, layers = default.selectors(), default.layers()
import pydhcp.capture
assert callable(pydhcp.capture.pktcap_plugin)
assert default.selectors() == selectors and default.layers() == layers, "registered on import"
assert default.get("udp", 67) is None and default.get("udp", 68) is None
assert "dhcp" not in default.layers()
print("ok")
"""


def test_importing_the_capture_package_registers_nothing_in_pktcaps_registry() -> None:
    out = subprocess.run(
        [sys.executable, "-c", _FRESH], capture_output=True, text=True, timeout=120
    )
    assert (out.returncode, out.stdout.strip(), out.stderr) == (0, "ok", "")


def test_the_hook_is_public_in_the_capture_module() -> None:
    assert "pktcap_plugin" in pydhcp.capture.__all__


# -- a second layer with the same key ------------------------------------------------------


def test_a_second_layer_with_an_op_key_makes_the_bare_key_ambiguous_and_the_dotted_one_work(
    capture: pathlib.Path,
) -> None:
    class OtherLayer(_ty.NamedTuple):
        op: int

    registry = _registry()
    registry.register_layer(
        OtherLayer, keys={"op": lambda clause: (lambda layer: False)}
    )
    with pytest.raises(pktcap.CaptureFilterError) as caught:
        pktcap.compile_capture_filter("op=1", pktcap.frame_filter_for(registry))
    assert "dhcp.op" in str(caught.value) and "other.op" in str(caught.value)
    assert _frame_selection(capture, "dhcp.op=BOOTREPLY", registry) == (DOTTED_OP_REPLY)


# -- pktcap's own command ------------------------------------------------------------------

_OTHER = """
from typing import NamedTuple


class OtherLayer(NamedTuple):
    op: int


def pktcap_plugin(registry):
    registry.register_layer(OtherLayer, keys={"op": lambda clause: (lambda layer: False)})
"""


def _pktcap(
    arguments: "list[str]", environment: "dict[str, str]", cwd: pathlib.Path
) -> "subprocess.CompletedProcess[str]":
    env = {k: v for k, v in os.environ.items() if not k.startswith("PKTCAP_")}
    env.update(environment, PKTCAP_CONFIG="none", PYTHONIOENCODING="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "pktcap", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        cwd=str(cwd),
        timeout=120,
    )


@pytest.fixture
def need_command() -> None:
    pytest.importorskip("duho")


def _records(out: "subprocess.CompletedProcess[str]") -> "list[dict[str, _ty.Any]]":
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def test_pktcap_convert_with_the_plugin_named_writes_the_discovers_alone(
    need_command: None, capture: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    out = _pktcap(
        ["convert", "-i", str(capture), "-f", "msg_type=DHCPDISCOVER"],
        {"PKTCAP_LOAD": "pydhcp.capture"},
        tmp_path,
    )
    assert out.returncode == 0, out.stderr
    records = _records(out)
    expected = [i for i, data in enumerate(DATAGRAMS) if _option(data, 53) == 1]
    assert len(records) == len(expected) > 0
    kinds = []
    for record in records:
        layers = {layer["layer"]: layer for layer in record["layers"]}
        kinds.append(layers["dhcp"]["message_type"])
    assert set(kinds) == {"DHCPDISCOVER"}


def test_pktcap_convert_refuses_a_message_type_name_that_is_not_one_with_status_2(
    need_command: None, capture: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    out = _pktcap(
        ["convert", "-i", str(capture), "-f", "msg_type=DISCOVER"],
        {"PKTCAP_LOAD": "pydhcp.capture"},
        tmp_path,
    )
    assert out.returncode == 2 and "DISCOVER" in out.stderr and out.stdout == ""


def test_without_the_plugin_named_the_key_is_unknown_to_pktcap(
    need_command: None, capture: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    out = _pktcap(
        ["convert", "-i", str(capture), "-f", "msg_type=DHCPDISCOVER"], {}, tmp_path
    )
    assert out.returncode == 2 and "msg_type" in out.stderr and out.stdout == ""


def test_with_another_op_key_loaded_the_bare_key_is_status_2_naming_both_and_the_dotted_key_works(
    need_command: None, capture: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    name = "other_demo_" + uuid.uuid4().hex[:10]
    directory = tmp_path / "plugins"
    directory.mkdir()
    (directory / (name + ".py")).write_bytes(_OTHER.encode("utf-8"))
    environment = {
        "PKTCAP_LOAD": "pydhcp.capture," + name,
        "PYTHONPATH": str(directory),
    }
    bare = _pktcap(["convert", "-i", str(capture), "-f", "op=1"], environment, tmp_path)
    assert bare.returncode == 2
    assert "dhcp.op" in bare.stderr and "other.op" in bare.stderr
    dotted = _pktcap(
        ["convert", "-i", str(capture), "-f", "dhcp.op=BOOTREPLY"],
        environment,
        tmp_path,
    )
    assert dotted.returncode == 0, dotted.stderr
    assert len(_records(dotted)) == len([d for d in DATAGRAMS if d[0] == 2])


def test_pktcap_plugins_lists_the_keys_and_the_layer(
    need_command: None, tmp_path: pathlib.Path
) -> None:
    out = _pktcap(["plugins"], {"PKTCAP_LOAD": "pydhcp.capture"}, tmp_path)
    assert out.returncode == 0, out.stderr
    lines = out.stdout.splitlines()
    keys = next(line for line in lines if line.strip().startswith("keys:"))
    words = keys.replace(",", " ").split()
    assert all(
        word in words for word in ("op", "msg_type", "xid", "client_id", "chaddr")
    )
    assert "dhcp" in next(line for line in lines if line.strip().startswith("layers:"))
    assert any(
        "pydhcp.capture" in line and "udp 67" in line and "layer dhcp" in line
        for line in lines
    )
