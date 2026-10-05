"""Replay of what stock DHCP software and pydhcp sent each other on a real wire.

Each directory under `cases/` is one exchange recorded by the tests in
`tests/interop` (ISC dhclient, BusyBox udhcpc and dnsmasq against pydhcp's
server, relay and client, over veth pairs in network namespaces). Replaying
needs no peer and no privilege, so it runs everywhere: the RFC stays the
authority, and a case is evidence of what a stock peer sends and accepts.

Every datagram must decode. A datagram that pydhcp sent must encode again to
the same octets: what the library puts on the wire is what it reads back.
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import typing as _ty

import pytest

from pydhcp import DhcpMessage

CASE_FILES = sorted((pathlib.Path(__file__).parent / "cases").glob("*/case.json"))
#: The IP datagram size `DhcpMessage.encode` is given: the RFC 2131 s2 minimum
#: unless the recorded message was larger.
MIN_DATAGRAM = 576
IP_UDP_OVERHEAD = 28


def _load(path: pathlib.Path) -> _ty.Dict[str, _ty.Any]:
    return _ty.cast(
        _ty.Dict[str, _ty.Any], json.loads(path.read_text(encoding="utf-8"))
    )


def _datagrams() -> _ty.List[_ty.Tuple[str, int, _ty.Dict[str, _ty.Any]]]:
    found = []
    for path in CASE_FILES:
        for index, datagram in enumerate(_load(path)["datagrams"]):
            found.append((path.parent.name, index, datagram))
    return found


def test_there_are_recorded_cases():
    assert len(CASE_FILES) >= 3


@pytest.mark.parametrize("path", CASE_FILES, ids=lambda p: p.parent.name)
def test_a_case_says_what_it_records(path):
    case = _load(path)
    assert case["description"] and case["peer"] and case["datagrams"]
    for datagram in case["datagrams"]:
        assert set(datagram) == {"segment", "sender", "src", "dst", "payload"}


@pytest.mark.parametrize(
    "name, index, datagram",
    _datagrams(),
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_every_recorded_datagram_decodes(name, index, datagram):
    DhcpMessage.decode(bytes.fromhex(datagram["payload"]))


@pytest.mark.parametrize(
    "name, index, datagram",
    [d for d in _datagrams() if d[2]["sender"].startswith("pydhcp")],
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_what_pydhcp_sent_encodes_to_the_same_octets(name, index, datagram):
    wire = bytes.fromhex(datagram["payload"])
    message = DhcpMessage.decode(wire)

    again = message.encode(max(MIN_DATAGRAM, len(wire) + IP_UDP_OVERHEAD))

    assert bytes(again) == wire


@pytest.mark.parametrize(
    "name, index, datagram",
    _datagrams(),
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_a_case_holds_nothing_from_the_machine_that_recorded_it(name, index, datagram):
    """Private addresses and locally administered hardware addresses only."""
    for end in (datagram["src"], datagram["dst"]):
        address = ipaddress.ip_address(end.rsplit(":", 1)[0])
        assert address.is_private or address == ipaddress.ip_address(
            "255.255.255.255"
        ), end
    message = DhcpMessage.decode(bytes.fromhex(datagram["payload"]))
    # Bit 1 of the first octet marks a locally administered address.
    assert message.chaddr[0] & 0x02, message.chaddr.hex()
