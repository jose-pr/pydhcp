"""The asynchronous capture hearing a real client.

A wildcard-bound asynchronous socket once received nothing on Linux while every
test in the suite passed; only a real client's broadcast showed it. The
capture must record what dhclient sends, and what it reports as the
destination must be where the datagram was sent (the limited broadcast, for a
client with no address).
"""

from __future__ import annotations

import json

import pytest

from ._peers import dhclient
from ._topo import ROLES_SINGLE, single
from .conftest import need, peer_version, record_case


def _records(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _wait_records(path, count, timeout):
    import time

    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if len(_records(path)) >= count:
            break
        time.sleep(0.1)
    return _records(path)


def test_capture_alone_hears_every_discover_of_an_unanswered_client(lab):
    need("dhclient")
    net = single(lab)
    tap = lab.tap(net.cli, "cv0", "client-segment")
    out = lab.work / "capture.jsonl"
    capture = lab.python(net.srv, "capture.py", str(out), name="capture")
    assert capture.wait_for_text("capturing"), capture.text()

    dhclient(lab, net.cli, "cv0", timeout_seconds=12)
    records = _wait_records(out, 2, 12)

    discovers = [r for r in records if r["type"] == "DHCPDISCOVER"]
    assert len(discovers) >= 2, records
    assert len({r["xid"] for r in discovers}) == 1

    record_case(
        "dhclient_unanswered_discover",
        "dhclient with no address and no server on the segment retransmits "
        "DISCOVER; a capture on the wildcard hears each one",
        peer_version("dhclient", "--version"),
        {"client-segment": tap},
        ROLES_SINGLE,
    )


def test_a_capture_beside_a_server_is_refused_the_port_not_shared(lab):
    need("dhclient")
    net = single(lab)
    server = lab.python(net.srv, "pool_server.py", name="server")
    assert server.wait_for_text("serving"), server.text()
    out = lab.work / "capture.jsonl"
    capture = lab.python(net.srv, "capture.py", str(out), name="capture")

    assert capture.popen.wait(15) != 0
    assert "already in use" in capture.text()


@pytest.mark.xfail(
    strict=True,
    reason="the capture reports the receiving interface's address as the "
    "destination of a datagram that was broadcast",
)
def test_capture_reports_the_destination_the_datagram_was_sent_to(lab):
    need("dhclient")
    net = single(lab)
    out = lab.work / "capture.jsonl"
    capture = lab.python(net.srv, "capture.py", str(out), name="capture")
    assert capture.wait_for_text("capturing"), capture.text()

    dhclient(lab, net.cli, "cv0", timeout_seconds=12)
    records = _wait_records(out, 1, 12)

    assert records, "nothing was captured"
    assert {r["destination"] for r in records} == {"255.255.255.255"}
