"""What a client does when the server refuses it or answers an INIT-REBOOT late.

RFC 2131 s3.2 and s4.3.2: a client that restarts with a lease it believes valid
broadcasts a DHCPREQUEST naming its old address (no server identifier) and
expects an answer within a second or two; a server that finds the address wrong
for the client's network answers DHCPNAK. RFC 6842: the server returns the
client identifier option in a reply only if the client sent one.
"""

from __future__ import annotations

import pytest

from pydhcp.options import DHCPOptionCode

from ._peers import dhclient
from ._topo import single
from .conftest import need

FOREIGN_LEASE = """lease {
  interface "cv0";
  fixed-address 10.77.0.5;
  option subnet-mask 255.255.255.0;
  option routers 10.77.0.1;
  option dhcp-lease-time 600;
  option dhcp-message-type 5;
  option dhcp-server-identifier 10.77.0.1;
  renew 0 2037/1/1 00:00:00;
  rebind 0 2037/1/1 00:00:00;
  expire 0 2037/1/1 00:00:00;
}
"""


def _known_client_asks_for_a_foreign_address(lab):
    """A client the server holds a binding for restarts holding a lease from
    another network. dhclient sends no client identifier. Returns what crossed
    the client's segment after the restart and the restarted client."""
    need("dhclient")
    net = single(lab)
    tap = lab.tap(net.cli, "cv0", "client-segment")
    server = lab.python(net.srv, "pool_server.py", name="server")
    assert server.wait_for_text("serving"), server.text()

    first = dhclient(lab, net.cli, "cv0", name="dhclient-first")
    assert first.wait_bound(30) is not None, first.proc.text()
    first.proc.stop()
    lab.run(net.cli, [lab.ip, "addr", "flush", "dev", "cv0"])
    before = len(tap.frames())

    second = dhclient(
        lab,
        net.cli,
        "cv0",
        name="dhclient-foreign",
        lease_file=FOREIGN_LEASE,
        reboot_seconds=5,
    )
    second.wait_bound(30)
    return tap.frames()[before:], second


def test_a_nak_to_a_client_that_sent_no_client_identifier_is_accepted(lab):
    frames, client = _known_client_asks_for_a_foreign_address(lab)

    requests = [f for f in frames if f.sport == 68]
    assert requests[0].type_name() == "DHCPREQUEST"
    assert DHCPOptionCode.CLIENT_IDENTIFIER not in requests[0].message().options
    assert [f for f in frames if f.type_name() == "DHCPNAK"], [
        f.type_name() for f in frames
    ]
    # The peer took the refusal as one: it logged it and started over.
    assert "DHCPNAK" in client.proc.text(), client.proc.text()
    assert client.leases(), client.proc.text()


@pytest.mark.xfail(
    strict=True,
    reason="a NAK to a client that sent no client identifier carries one",
)
def test_a_nak_carries_no_client_identifier_the_client_did_not_send(lab):
    frames, _client = _known_client_asks_for_a_foreign_address(lab)

    naks = [f for f in frames if f.type_name() == "DHCPNAK"]
    assert naks, [f.type_name() for f in frames]
    assert DHCPOptionCode.CLIENT_IDENTIFIER not in naks[0].message().options


def _reboot(lab, *server_args):
    """A client obtains a lease, restarts holding it, and asks again
    (INIT-REBOOT). Returns the restarted client and what it sent."""
    need("dhclient")
    net = single(lab)
    tap = lab.tap(net.cli, "cv0", "client-segment")
    server = lab.python(net.srv, "pool_server.py", *server_args, name="server")
    assert server.wait_for_text("serving"), server.text()

    first = dhclient(lab, net.cli, "cv0", name="dhclient-first")
    assert first.wait_bound(30) is not None, first.proc.text()
    first.proc.stop()
    lease_text = (first.out / "dhclient.leases").read_text()
    assert "lease {" in lease_text, lease_text
    lab.run(net.cli, [lab.ip, "addr", "flush", "dev", "cv0"])
    before = len(tap.frames())

    # The wait a rebooting client gives the server before it falls back to
    # DISCOVER is five seconds here.
    second = dhclient(
        lab,
        net.cli,
        "cv0",
        name="dhclient-reboot",
        lease_file=lease_text,
        reboot_seconds=5,
    )
    lease = second.wait_bound(30)
    assert lease is not None, second.proc.text()
    sent = [f.type_name() for f in tap.frames()[before:] if f.sport == 68]
    return lease, second, sent


def test_a_rebooting_client_is_answered_by_a_server_that_keeps_leases_in_its_backend(
    lab,
):
    lease, second, sent = _reboot(lab)

    assert sent[0] == "DHCPREQUEST", sent
    assert lease.reason == "REBOOT", (lease.reason, sent)
    assert second.bound_after < 3.0, second.bound_after
    assert "DHCPDISCOVER" not in sent


@pytest.mark.xfail(
    strict=True,
    reason="a server that answers through acquire_lease alone never answers an "
    "INIT-REBOOT request",
)
def test_a_rebooting_client_is_answered_by_a_server_that_answers_through_acquire_lease_alone(
    lab,
):
    lease, second, sent = _reboot(lab, "--private-store")

    detail = (lease.reason, sent, f"{second.bound_after:.1f}s")
    assert lease.reason == "REBOOT", detail
    assert second.bound_after < 3.0, detail
