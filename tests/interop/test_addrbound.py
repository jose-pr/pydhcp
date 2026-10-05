"""A listener bound to an address hears no broadcast on Linux; the wildcard does.

A datagram sent to 255.255.255.255 or to the subnet broadcast address is
delivered by Linux only to sockets bound to the wildcard (or to that broadcast
address); a socket bound to the host's own address hears the unicast and
nothing else. The library documents this and warns once; this is the check
that the behaviour is what is documented, on a real segment.
"""

from __future__ import annotations

import json

from ._topo import single


def test_an_address_bound_listener_hears_no_broadcast_and_the_wildcard_hears_all(lab):
    net = single(lab, client_addr="10.99.0.2/24")
    listener = lab.python(
        net.srv, "addrbound_listen.py", net.server_ip, "16800", "4", name="listeners"
    )
    assert listener.wait_for_text("ready"), listener.text()

    lab.python_wait(
        net.cli,
        "emit.py",
        "kinds",
        "--src",
        "10.99.0.2",
        "--src-port",
        "0",
        "--dst",
        net.server_ip,
        "--dst-port",
        "16800",
        "--subnet-broadcast",
        "10.99.0.255",
    )
    assert listener.popen.wait(15) == 0, listener.text()
    heard = json.loads(listener.text().strip().splitlines()[-1])

    assert heard["wildcard"] == {
        "limited_broadcast": 3,
        "subnet_broadcast": 3,
        "unicast": 3,
    }
    assert heard["address"] == {"unicast": 3}
