"""A listener told to serve one interface, on a host with two.

One wildcard socket hears a broadcast from every segment; the listener serves the
named interface and drops what arrives on the other before decoding, and counts
it. Judged by the offers each segment's wire carries and by the server's counters.
"""

from __future__ import annotations

import json
import time

import pytest

from ._topo import two_homed

CHADDR_A = "020000000a01"
CHADDR_B = "020000000b01"


def _offers(tap):
    return [f for f in tap.frames() if f.sport == 67 and f.type_name() == "DHCPOFFER"]


@pytest.mark.parametrize("flavour", ["sync", "async"])
@pytest.mark.parametrize("listen", ["sa:67", "02:00:00:03:00:01"], ids=["name", "mac"])
def test_a_listener_on_one_interface_answers_that_segment_and_not_the_other(
    lab, flavour, listen
):
    net = two_homed(lab)
    tap_a = lab.tap(net.a, "a0", "segment-a")
    tap_b = lab.tap(net.b, "b0", "segment-b")
    status = lab.work / "server.json"
    arguments = ["--listen", listen, "--status", str(status)]
    if flavour == "async":
        arguments.append("--async")
    server = lab.python(net.srv, "pool_server.py", *arguments, name="server")
    assert server.wait_for_text("serving"), server.text()

    lab.python_wait(net.a, "emit.py", "discover", "--chaddr", CHADDR_A)
    assert tap_a.wait_for(lambda frames: any(f.sport == 67 for f in frames), 5)
    lab.python_wait(net.b, "emit.py", "discover", "--chaddr", CHADDR_B)
    # Nothing is expected on B; give an answer the time it would take.
    time.sleep(1.5)

    assert len(_offers(tap_a)) == 1
    assert _offers(tap_a)[0].src_ip == "10.203.0.1"
    assert _offers(tap_b) == [], "the other segment was answered"

    server.stop()
    counters = json.loads(status.read_text(encoding="utf-8"))
    assert counters["packets_dropped_other_interface"] == 1, counters
    assert counters["packets_received"] == 1, counters


def test_the_wildcard_answers_both_segments(lab):
    """The control: with no interface named, the same two requests are both answered."""
    net = two_homed(lab)
    tap_a = lab.tap(net.a, "a0", "segment-a")
    tap_b = lab.tap(net.b, "b0", "segment-b")
    status = lab.work / "server.json"
    server = lab.python(
        net.srv, "pool_server.py", "--status", str(status), name="server"
    )
    assert server.wait_for_text("serving"), server.text()

    lab.python_wait(net.a, "emit.py", "discover", "--chaddr", CHADDR_A)
    lab.python_wait(net.b, "emit.py", "discover", "--chaddr", CHADDR_B)
    assert tap_a.wait_for(lambda frames: any(f.sport == 67 for f in frames), 5)
    assert tap_b.wait_for(lambda frames: any(f.sport == 67 for f in frames), 5)

    assert len(_offers(tap_a)) == 1 and len(_offers(tap_b)) == 1
    server.stop()
    counters = json.loads(status.read_text(encoding="utf-8"))
    assert counters["packets_dropped_other_interface"] == 0, counters
    assert counters["packets_received"] == 2, counters
