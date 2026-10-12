"""How the listeners use `netimps.parse_listen`.

The grammar is netimps' and its own suite pins it: this file pins what is
pydhcp's, which is the default ports of each class, the IPv4 family, the one
refusal of its own, that a constructor performs no I/O, and what `bind()` does
with the interfaces a specification names.
"""

from __future__ import annotations

import ipaddress
import socket
import typing as ty

import netimps
import pytest

from pydhcp import AsyncDHCPClient, DHCPClient
from pydhcp.listener import AsyncDHCPListener, DHCPListener
from pydhcp.relay import AsyncDHCPRelay, DHCPRelay
from pydhcp.server import AsyncDHCPServer, DHCPServer

#: class -> the ports a binding with no port of its own gets.
DEFAULT_PORTS: "list[tuple[type, tuple[int, ...]]]" = [
    (DHCPListener, (67, 68)),
    (AsyncDHCPListener, (67, 68)),
    (DHCPServer, (67,)),
    (AsyncDHCPServer, (67,)),
    (DHCPRelay, (67,)),
    (AsyncDHCPRelay, (67,)),
    (DHCPClient, (68,)),
    (AsyncDHCPClient, (68,)),
]

LISTENERS = [cls for cls, _ports in DEFAULT_PORTS]


def _build(cls: type, **kwargs: ty.Any) -> ty.Any:
    if cls is DHCPRelay or cls is AsyncDHCPRelay:
        kwargs.setdefault("server_addresses", ["192.0.2.1"])
    return cls(**kwargs)


@pytest.mark.parametrize(
    "cls, ports", DEFAULT_PORTS, ids=lambda v: getattr(v, "__name__", str(v))
)
def test_a_binding_without_a_port_gets_the_default_ports_of_its_class(
    cls: type, ports: "tuple[int, ...]"
) -> None:
    for listen in (None, "*", "127.0.0.1"):
        # private: the parsed listen specification: `bound_addresses` is empty until the bind
        found = _build(cls, listen=listen)._listen
        assert [entry.port for entry in found] == list(ports)


def test_a_port_written_in_the_binding_replaces_the_defaults() -> None:
    # private: the parsed listen specification: `bound_addresses` is empty until the bind
    found = DHCPListener(listen="127.0.0.1:6767,127.0.0.2")._listen
    assert [(str(entry.address), entry.port) for entry in found] == [
        ("127.0.0.1", 6767),
        ("127.0.0.2", 67),
        ("127.0.0.2", 68),
    ]


@pytest.mark.parametrize("cls", LISTENERS, ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    "listen",
    [
        "::1",
        "[::1]:6767",
        "fe80::1%eth0",
        ("fe80::1", 6767),
        ipaddress.IPv6Address("::1"),
    ],
    ids=repr,
)
def test_an_ipv6_address_is_refused_as_a_value_error_of_netimps(
    cls: type, listen: ty.Any
) -> None:
    """Text and an `IPv6Address` object are refused the same way: DHCPv4 listens
    on IPv4 only."""
    with pytest.raises(netimps.NetimpsValueError) as raised:
        _build(cls, listen=listen)
    assert isinstance(raised.value, ValueError)
    assert not isinstance(raised.value, ipaddress.AddressValueError)


@pytest.mark.parametrize("cls", LISTENERS, ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    "listen, error",
    [
        ("", netimps.NetimpsValueError),
        ([], netimps.NetimpsValueError),
        (("127.0.0.1", []), netimps.NetimpsValueError),
        ("127.0.0.1:70000", netimps.NetimpsValueError),
        ("127.0.0.1:+6767", netimps.NetimpsValueError),
        ("[127.0.0.1]:6767", netimps.NetimpsValueError),
        (("*:6767", 6868), netimps.NetimpsValueError),
        ("eth/1", netimps.NetimpsValueError),
        (True, TypeError),
        (6767, TypeError),
        (("127.0.0.1", True), TypeError),
        (b"127.0.0.1", TypeError),
    ],
    ids=repr,
)
def test_every_constructor_refuses_what_netimps_refuses(
    cls: type, listen: ty.Any, error: type
) -> None:
    with pytest.raises(error):
        _build(cls, listen=listen)


@pytest.mark.parametrize("cls", LISTENERS, ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    "listen",
    ["eth1:6767", ("aa:bb:cc:dd:ee:ff", 6767), "aa-bb-cc-dd-ee-ff", "Wi-Fi 2:6767"],
    ids=repr,
)
def test_a_constructor_asks_the_host_nothing(
    cls: type, listen: ty.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whether the interface exists is checked by `bind()`."""

    def refuse(*args: ty.Any, **kwargs: ty.Any) -> ty.NoReturn:
        raise AssertionError("the constructor asked the host about its adapters")

    monkeypatch.setattr(netimps, "iter_interfaces", refuse)
    monkeypatch.setattr(netimps, "get_interfaces", refuse)
    monkeypatch.setattr(netimps, "iter_addresses", refuse)
    monkeypatch.setattr(socket, "socket", refuse)
    # private: the parsed listen specification: `bound_addresses` is empty until the bind
    assert _build(cls, listen=listen)._listen[0].interfaces


@pytest.mark.parametrize("cls", LISTENERS, ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    "listen", ["eth1", "eth1:6767,eth2:6767", ("aa:bb:cc:dd:ee:ff", 6767)], ids=repr
)
def test_an_interface_cannot_be_combined_with_one_socket_per_address(
    cls: type, listen: ty.Any
) -> None:
    with pytest.raises(ValueError, match="per_interface cannot be combined"):
        _build(cls, listen=listen, per_interface=True)


@pytest.mark.parametrize("listen", ["eth1:6767,*:6767", "*:6767,eth1:6767"])
def test_a_wildcard_named_plainly_beside_an_interface_is_no_interface_binding(
    listen: str,
) -> None:
    DHCPListener(listen=listen, per_interface=True)


# -- what the forms bind -------------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [("127.0.0.1", "0"), ["127.0.0.1", 0], ("127.0.0.1", ["0"]), "127.0.0.1:0"],
    ids=repr,
)
def test_a_pair_binds_one_socket_on_that_port(spec: ty.Any) -> None:
    listener = DHCPListener(listen=spec)
    listener.bind()
    try:
        assert len(listener.bound_addresses) == 1
        assert str(listener.bound_addresses[0].ip) == "127.0.0.1"
    finally:
        listener.close()


def test_a_refused_spec_binds_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    made: "list[object]" = []
    real = socket.socket

    class Counting(real):
        def __init__(self, *args: ty.Any, **kwargs: ty.Any) -> None:
            made.append(args)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(socket, "socket", Counting)
    # A spec that is accepted opens a socket through the counter, so a count of
    # none below is the specs' doing and not a counter that nothing reaches.
    accepted = DHCPListener(listen="127.0.0.1:0")
    accepted.bind()
    accepted.close()
    assert made
    made.clear()

    for spec in [("127.0.0.1", True), "", ["127.0.0.1", 6767.5]]:
        with pytest.raises((TypeError, ValueError)):
            DHCPListener(listen=spec).bind()
    assert made == []


# -- an interface ----------------------------------------------------------------


def test_an_unknown_interface_is_refused_by_bind_and_binds_nothing() -> None:
    listener = DHCPListener(listen="no-such-adapter-7:0")
    with pytest.raises(
        netimps.NetimpsValueError, match="no interface matches 'no-such-adapter-7'"
    ):
        listener.bind()
    # private: the OS socket: its options and closed state have no public view
    assert listener._sockets == [] and listener.bound_addresses == ()


def test_a_host_name_is_an_adapter_name_and_is_never_resolved() -> None:
    """`localhost` resolves, and that is not what `listen` asks: the name is
    looked for among the adapters, and the refusal says what a name is."""
    if any(a.name == "localhost" for a in netimps.get_interfaces()):
        pytest.skip("this host has an adapter named localhost")
    listener = DHCPListener(listen="localhost:0")
    with pytest.raises(netimps.NetimpsValueError, match="host name is never resolved"):
        listener.bind()
    # private: the OS socket: its options and closed state have no public view
    assert listener._sockets == []


def test_an_interface_is_found_by_name_by_mac_and_as_an_object() -> None:
    adapter = _an_adapter()
    by_name = DHCPListener(listen=f"{adapter.name}:0")
    by_object = DHCPListener(listen=(adapter, 0))
    for listener in (by_name, by_object):
        listener.bind()
        try:
            # private: the OS socket: its options and closed state have no public view
            (socket_,) = listener._sockets
            # private: the endpoint a socket is received through: no public view
            served = listener._endpoints[socket_].interfaces
            assert adapter.index in {i.index for i in served}
            assert str(listener.bound_addresses[0].ip) == "0.0.0.0"
        finally:
            listener.close()
    if adapter.mac is not None:
        by_mac = DHCPListener(listen=(adapter.mac, 0))
        by_mac.bind()
        try:
            (socket_,) = by_mac._sockets
            assert adapter.index in {
                i.index for i in by_mac._endpoints[socket_].interfaces
            }
        finally:
            by_mac.close()


def _an_adapter() -> netimps.Interface:
    """An adapter with an index, a MAC, an IPv4 address and a name `listen` can
    spell: none of the characters that mean a port, a network or a MAC."""
    for adapter in netimps.get_interfaces():
        if (
            adapter.index
            and adapter.mac is not None
            and adapter.ipv4
            and ":" not in adapter.name
            and "/" not in adapter.name
            and netimps.MACAddress.try_parse(adapter.name) is None
        ):
            return adapter
    pytest.skip("this host has no adapter with a MAC, an IPv4 address and a plain name")
