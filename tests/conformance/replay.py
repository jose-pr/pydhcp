"""This library's answers to the conformance cases, with no socket, and the comparison with the goldens.

``play(directory, driver)`` drives the role cores with the datagrams a case spells
(through ``handle`` for a server or a relay, through ``DHCPClient`` with its sends
and its clock replaced for a client) and returns, per step, the datagrams this
library sent as ``(payload, "address:port")``. ``compare`` sets that against the
golden and returns every difference outside the aspects the case leaves out.

Run as a script it prints one JSON line per difference:

    python tests/conformance/replay.py [--driver async] [CASE ...]
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import queue
import sys
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

import netimps

import exchange
from pydhcp import (
    AsyncDHCPRelay,
    AsyncDHCPServer,
    DHCPClient,
    DHCPMessage,
    DHCPOptions,
    DHCPRelay,
    DHCPRequestContext,
    DHCPServer,
    InMemoryLeaseBackend,
    NetworkInterface,
    SocketAddress,
)
from pydhcp.exceptions import DHCPTimeoutError
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType

# private: the allocator reads the host's adapters through this name, and the relay its own
# private: names for netimps; replaying holds the host constant by replacing them where read
from pydhcp.relay import _core as relay_core
from pydhcp.server import _policy

Sent = List[exchange.Datagram]
LIMITED_BROADCAST = "255.255.255.255"
DRIVERS = ("sync", "async")


def _golden(directory: pathlib.Path) -> Dict[str, Any]:
    return dict(json.loads((directory / "golden.json").read_text(encoding="utf-8")))


def _sends(transport: mock.Mock) -> Sent:
    return [
        (bytes(call.args[0]), "%s:%d" % (call.args[1], call.kwargs["port"]))
        for call in transport.send.call_args_list
    ]


def _context(
    step: Dict[str, Any], interface: NetworkInterface, transport: mock.Mock
) -> DHCPRequestContext:
    destination = ipaddress.IPv4Address(step.get("dst", LIMITED_BROADCAST))
    return DHCPRequestContext(
        transport=transport,
        interface=interface,
        client=SocketAddress(step.get("src", "0.0.0.0"), step.get("sport", 68)),
        client_mac=bytes.fromhex(step["message"]["chaddr"].replace(":", "")),
        destination=destination,
        is_unicast=str(destination) != LIMITED_BROADCAST,
    )


# -- the server -----------------------------------------------------------------------


def _pool(base: type, config: Dict[str, Any]) -> type:
    """A server that allocates by the `acquire_lease` contract: the static address, else the range."""
    network = ipaddress.IPv4Network("0.0.0.0/%s" % config["mask"])

    class Comparison(base):  # type: ignore
        def get_lease_seconds(self, msg: DHCPMessage) -> float:
            return float(config["lease_seconds"])

        def _options(self, address: ipaddress.IPv4Address) -> DHCPOptions:
            options = DHCPOptions()
            options[DHCPOptionCode.SUBNET_MASK] = network.netmask
            options[DHCPOptionCode.BROADCAST_ADDRESS] = ipaddress.IPv4Network(
                "%s/%s" % (address, network.netmask), strict=False
            ).broadcast_address
            options[DHCPOptionCode.ROUTER] = [ipaddress.IPv4Address(config["router"])]
            return options

        def get_inform_options(self, server_id, msg):  # type: ignore
            return self._options(msg.ciaddr)

        def _candidates(self, msg: DHCPMessage) -> List[ipaddress.IPv4Address]:
            mac = ":".join("%02x" % octet for octet in msg.chaddr[:6])
            if mac in config["hosts"]:
                return [ipaddress.IPv4Address(config["hosts"][mac])]
            if not config["range"]:
                return []
            first, last = (ipaddress.IPv4Address(a) for a in config["range"])
            return [ipaddress.IPv4Address(n) for n in range(int(first), int(last) + 1)]

        def acquire_lease(self, client_id, server_id, msg, *, commit=True):  # type: ignore
            backend = self.lease_backend
            seconds = self.get_lease_seconds(msg)
            held = backend.lookup(client_id)
            if held is not None:
                if not commit:
                    return held
                return (
                    backend.commit(client_id, seconds)
                    if held.offered
                    else backend.renew(client_id, seconds)
                )
            kind = msg.options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
            if kind is not DHCPMessageType.DHCPDISCOVER:
                return None
            for address in self._candidates(msg):
                lease = backend.offer(
                    client_id, address, self.OFFER_HOLD_SECONDS, self._options(address)
                )
                if lease is not None:
                    return lease
            return None

    return Comparison


def _play_server(case: Dict[str, Any], driver: str) -> List[Sent]:
    config = case["config"]
    served = ipaddress.IPv4Interface("%s/%d" % (config["server"], config["prefix"]))
    interface = NetworkInterface("sv0", served)
    base = AsyncDHCPServer if driver == "async" else DHCPServer
    server = _pool(base, config)(lease_backend=InMemoryLeaseBackend())
    played: List[Sent] = []
    # private: the host's adapters, held to the one interface the case names
    with mock.patch.object(
        _policy,
        "_servable_interface",
        lambda server_id: interface if server_id == served.ip else None,
    ):
        for step in case["steps"]:
            transport = mock.Mock(send=mock.Mock(return_value=1))
            message = DHCPMessage.decode(exchange.build(step["message"]))
            server.handle(message, _context(step, interface, transport))
            played.append(_sends(transport))
    return played


# -- the relay ------------------------------------------------------------------------


def _play_relay(case: Dict[str, Any], driver: str) -> List[Sent]:
    config = case["config"]
    base = AsyncDHCPRelay if driver == "async" else DHCPRelay
    relay = base(listen=("127.0.0.1", 6767), server_addresses=[config["server"]])
    client_side = NetworkInterface(
        "ra0", ipaddress.IPv4Interface("%s/24" % config["local"])
    )
    server_side = NetworkInterface("rs0", ipaddress.IPv4Interface("10.98.0.1/24"))
    holds = {
        config["local"]: netimps.Interface(
            name="ra0", index=3, ips=[client_side.ip_interface]
        )
    }
    played: List[Sent] = []
    # private: the relay's own name for netimps, replaced to stand for a host with these two addresses
    with (
        mock.patch.object(
            relay_core._netimps,
            "get_interface",
            lambda address, **_k: holds.get(str(address)),
        ),
        mock.patch.object(
            relay_core._netimps,
            "is_local_address",
            lambda address, **_k: str(address) in (*holds, "10.98.0.1"),
        ),
    ):
        for step in case["steps"]:
            transport = mock.Mock(send=mock.Mock(return_value=1))
            message = DHCPMessage.decode(exchange.build(step["message"]))
            relay.handle(message, _context(step, client_side, transport))
            sent = _sends(transport)
            forwarded = [
                data for data, where in sent if where.startswith(config["server"] + ":")
            ]
            reply = (
                config["replies"].get(exchange.message_type(forwarded[0]))
                if forwarded
                else None
            )
            if reply is not None:
                answered = {
                    "src": config["server"],
                    "sport": 67,
                    "message": {"chaddr": step["message"]["chaddr"]},
                }
                relay.handle(
                    DHCPMessage.decode(exchange.answer(forwarded[0], reply)),
                    _context(answered, server_side, transport),
                )
                sent = _sends(transport)
            played.append(sent)
    return played


# -- the client -----------------------------------------------------------------------


class _Scripted(DHCPClient):
    """A client with no socket and no clock: what it sends is kept, a scripted server answers it."""

    def __init__(self, replies: Dict[str, Any]) -> None:
        super().__init__(listen=("127.0.0.1", 0))
        self.replies = replies
        self.sent: Sent = []

    def _monotonic(self) -> float:
        return 1000.0

    def send(  # type: ignore[override]
        self, message: DHCPMessage, *, dst: Any = LIMITED_BROADCAST, port: int = 67
    ) -> int:
        data = self._encode(message)
        self.sent.append((data, "%s:%d" % (dst, port)))
        self._pending_keys.add(self._pending_key(message))
        reply = self.replies.get(exchange.message_type(data))
        if reply is not None:
            self.handle(DHCPMessage.decode(exchange.answer(data, reply)), None)
        return len(data)

    def _wait_for(self, waiter, msg_type, timeout, server=None):  # type: ignore[no-untyped-def]
        while True:
            try:
                message, _context = waiter.get_nowait()
            except queue.Empty:
                return None
            taken = self._take(message, msg_type, server, self._monotonic())
            if taken is not None:
                return taken


def _play_client(case: Dict[str, Any], golden: Dict[str, Any]) -> List[Sent]:
    config = case["config"]
    chaddr = bytes.fromhex(config["chaddr"].replace(":", ""))
    prl = [DHCPOptionCode(code) for code in config["prl"]]
    xids = [
        int(e["payload"][8:16], 16)
        for e in golden["exchange"]
        if e["sender"] == "client"
    ]
    client = _Scripted(config["replies"])
    for call in case["pydhcp"]:
        xid = xids[len(client.sent)] if len(client.sent) < len(xids) else None
        args = dict(call["args"])
        if call["call"] == "dora":
            try:
                client.dora(
                    chaddr,
                    xid=xid,
                    parameter_request_list=prl,
                    timeout=1.0,
                    retries=0,
                    **args,
                )
            except DHCPTimeoutError:
                pass
            continue
        if call["call"] == "build_request":
            args["parameter_request_list"] = prl
        built = getattr(client, call["call"])(chaddr, xid=xid, **args)
        # private: the encoding `send` puts on the wire, of a message a builder made
        client.sent.append((client._encode(built), ""))
    return [[sent] for sent in client.sent]


def play(directory: pathlib.Path, driver: Optional[str] = None) -> List[Sent]:
    """What this library sent for each step of the case, as ``(payload, "address:port")``.

    ``driver`` is ``sync`` (the default) or ``async``: the twin of the thread-based class that
    owns the same core. A client case is played by ``DHCPClient`` alone.
    """
    case = exchange.load(directory)
    driver = driver or "sync"
    if case["role"] == "server":
        return _play_server(case, driver)
    if case["role"] == "relay":
        return _play_relay(case, driver)
    return _play_client(case, _golden(directory))


def _reference(directory: pathlib.Path) -> Dict[str, List[Sent]]:
    """The golden's datagrams of the role under comparison, by step name."""
    case = exchange.load(directory)
    kept: Dict[str, List[Sent]] = {step["name"]: [] for step in case["steps"]}
    for entry in _golden(directory)["exchange"]:
        if entry["sender"] == case["role"]:
            kept[entry["step"]].append((bytes.fromhex(entry["payload"]), entry["dst"]))
    return kept


def compare(
    directory: pathlib.Path, driver: Optional[str] = None
) -> List[Tuple[str, exchange.Difference]]:
    """Every difference between the golden and this library, as ``(step, difference)``.

    The aspects a case's ``not_compared`` names for a step are left out.
    """
    case = exchange.load(directory)
    reference = _reference(directory)
    ours = play(directory, driver)
    found = []
    for index, step in enumerate(case["steps"]):
        name = step["name"]
        left_out = [e["aspect"] for e in case["not_compared"] if e["step"] == name]
        mine = ours[index] if index < len(ours) else []
        found += [
            (name, d) for d in exchange.differences(reference[name], mine, left_out)
        ]
    return found


def main(argv: List[str]) -> int:
    driver = argv[argv.index("--driver") + 1] if "--driver" in argv else None
    names = [
        a
        for i, a in enumerate(argv)
        if not a.startswith("--") and (i == 0 or argv[i - 1] != "--driver")
    ]
    for directory in exchange.cases():
        if names and directory.name not in names:
            continue
        for step, difference in compare(directory, driver):
            print(
                json.dumps(
                    {
                        "case": directory.name,
                        "step": step,
                        "reply": difference.reply,
                        "aspect": difference.aspect,
                        "reference": difference.reference,
                        "ours": difference.ours,
                    }
                )
            )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
