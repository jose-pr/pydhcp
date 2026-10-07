"""Listening on one interface: one wildcard socket, and what arrives elsewhere is dropped.

A socket bound to an address hears no broadcast on most platforms, so serving one
interface means hearing them all and ignoring the rest, before decoding, with a
count.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import typing as ty

import netimps
import pytest
from driving import LOOPS

from helpers import build_request
from pydhcp import AsyncDHCPListener, DHCPListener

# the arrival record is not public
from pydhcp.listener._receive import _Arrival
from pydhcp import SocketAddress
from ipaddress import IPv4Address as IPv4


def _loopback() -> netimps.Interface:
    found = netimps.get_interface("127.0.0.1")
    assert found is not None and found.index
    return found


def _another_adapter() -> netimps.Interface:
    """An adapter with an IPv4 address that is not the loopback."""
    for adapter in netimps.get_interfaces():
        if (
            adapter.index
            and not adapter.is_loopback
            and adapter.ipv4
            and adapter.index != _loopback().index
            and ":" not in adapter.name
            and netimps.MACAddress.try_parse(adapter.name) is None
        ):
            return adapter
    pytest.skip("this host has no second adapter with an IPv4 address")


def _arrival(ifindex: ty.Optional[int]) -> _Arrival:
    return _Arrival(b"x" * 20, SocketAddress(IPv4("192.0.2.5"), 68), ifindex)


@pytest.mark.parametrize("driver", [DHCPListener, AsyncDHCPListener])
def test_a_limited_socket_admits_only_its_interfaces_and_counts_the_rest(
    driver: type,
) -> None:
    listener = driver(listen=(_loopback(), 0))
    listener.bind()
    try:
        # private: the OS socket: its options and closed state have no public view
        (sock,) = listener._sockets
        # private: the interface allow-list a listener builds: no public view
        allowed = listener._allowed[sock]
        assert allowed == frozenset({_loopback().index})

        # private: the receive path's admission check, driven without a socket
        assert listener._admits(_arrival(_loopback().index), sock)
        assert listener.metrics.packets_dropped_other_interface == 0
        assert not listener._admits(_arrival(_loopback().index + 100), sock)
        assert not listener._admits(_arrival(None), sock)
        assert listener.metrics.packets_dropped_other_interface == 2
    finally:
        if driver is DHCPListener:
            listener.close()
        else:
            asyncio.run(listener.aclose())


def test_an_unlimited_socket_admits_everything() -> None:
    listener = DHCPListener(listen=("*", 0))
    listener.bind()
    try:
        # private: the OS socket: its options and closed state have no public view
        (sock,) = listener._sockets
        # private: the interface allow-list a listener builds: no public view
        assert listener._allowed == {}
        # private: the receive path's admission check, driven without a socket
        assert listener._admits(_arrival(12345), sock)
        assert listener.metrics.packets_dropped_other_interface == 0
    finally:
        listener.close()


def test_the_wildcard_named_plainly_beside_an_interface_has_no_limit() -> None:
    listener = DHCPListener(listen="*:0,lo:0")
    # private: the limiter's table: its bound is the subject
    assert listener._limits == {}


def test_a_drop_is_logged_once_through_the_limiter(caplog) -> None:
    import logging

    listener = DHCPListener(listen=(_loopback(), 0))
    listener.bind()
    try:
        # private: the OS socket: its options and closed state have no public view
        (sock,) = listener._sockets
        with caplog.at_level(logging.DEBUG, logger="pydhcp"):
            for _ in range(50):
                # private: the receive path's admission check, driven without a socket
                listener._admits(_arrival(_loopback().index + 100), sock)
        lines = [
            r
            for r in caplog.records
            if "Dropping a datagram that arrived" in r.getMessage()
        ]
        # Only the first of a flood is written; the exact total is the counter.
        assert len(lines) == 1
        assert listener.metrics.packets_dropped_other_interface == 50
    finally:
        listener.close()


# -- on real sockets ---------------------------------------------------------------


def _send_over_loopback(port: int) -> None:
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(build_request().encode(), ("127.0.0.1", port))
    finally:
        sender.close()


class _Counting(DHCPListener):
    def __init__(self, *args: ty.Any, **kwargs: ty.Any) -> None:
        super().__init__(*args, **kwargs)
        self.handled: list = []

    def handle(self, msg: ty.Any, context: ty.Any) -> None:
        self.handled.append(context.ifindex)


class _AsyncCounting(AsyncDHCPListener):
    def __init__(self, *args: ty.Any, **kwargs: ty.Any) -> None:
        super().__init__(*args, **kwargs)
        self.handled: list = []

    def handle(self, msg: ty.Any, context: ty.Any) -> None:
        self.handled.append(context.ifindex)


def _settle(listener: ty.Any, handled_at_least: int, quiet: float = 0.4) -> None:
    """Wait for a handled datagram, or for a quiet period when none is due."""
    end = time.monotonic() + (3 if handled_at_least else quiet)
    while time.monotonic() < end:
        if len(listener.handled) >= handled_at_least and handled_at_least:
            return
        time.sleep(0.02)


def _serve_sync(
    spec: ty.Any, handled_at_least: int, device_binding: bool = True
) -> _Counting:
    listener = _Counting(listen=spec, poll_interval=0.05)
    listener.USE_DEVICE_BINDING = device_binding
    listener.bind()
    port = listener.bound_addresses[0].port
    thread = threading.Thread(target=listener.serve_forever, daemon=True)
    thread.start()
    try:
        _send_over_loopback(port)
        _settle(listener, handled_at_least)
    finally:
        listener.shutdown()
        thread.join(5)
        listener.close()
    return listener


def _serve_async(
    spec: ty.Any, handled_at_least: int, loop_type: type, device_binding: bool = True
) -> ty.Any:
    listener = _AsyncCounting(listen=spec)
    listener.USE_DEVICE_BINDING = device_binding

    async def scenario() -> None:
        await listener.start()
        try:
            _send_over_loopback(listener.bound_addresses[0].port)
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _settle, listener, handled_at_least)
        finally:
            await listener.aclose()

    loop = loop_type()
    try:
        loop.run_until_complete(scenario())
    finally:
        loop.close()
    return listener


def _drops(device_binding: bool) -> int:
    """What a listener on another adapter counts of a loopback datagram: with the
    socket bound to its device the kernel delivers none (Linux), otherwise the
    allow-list counts it."""
    return 0 if device_binding and netimps.has_device_binding() else 1


@pytest.mark.parametrize("device_binding", [True, False], ids=["device", "filter"])
def test_the_sync_listener_serves_its_interface_and_drops_the_others(
    device_binding: bool,
) -> None:
    mine = _serve_sync((_loopback(), 0), 1, device_binding)
    assert mine.handled == [_loopback().index]
    assert mine.metrics.packets_dropped_other_interface == 0

    other = _serve_sync((_another_adapter(), 0), 0, device_binding)
    assert other.handled == []
    assert other.metrics.packets_dropped_other_interface == _drops(device_binding)
    assert other.metrics.packets_received == 0, "a dropped datagram was decoded"


@pytest.mark.parametrize("device_binding", [True, False], ids=["device", "filter"])
@pytest.mark.parametrize("loop_type", LOOPS, ids=lambda loop: loop.__name__)
def test_the_async_listener_serves_its_interface_and_drops_the_others(
    loop_type: type, device_binding: bool
) -> None:
    mine = _serve_async((_loopback(), 0), 1, loop_type, device_binding)
    assert mine.handled == [_loopback().index]
    assert mine.metrics.packets_dropped_other_interface == 0

    other = _serve_async((_another_adapter(), 0), 0, loop_type, device_binding)
    assert other.handled == []
    assert other.metrics.packets_dropped_other_interface == _drops(device_binding)
    assert other.metrics.packets_received == 0


def test_the_wildcard_beside_an_interface_hears_every_interface() -> None:
    listener = _serve_sync(["*:0", (_another_adapter(), 0)], handled_at_least=1)
    assert listener.handled == [_loopback().index]


# -- binding the socket to the device ----------------------------------------------


class _Netimps:
    """Stands in for `netimps.bind`: records `device=`, and where the host cannot
    bind to a device it passes the call on without one. `refuse` is raised in
    place of a bind that names a device."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        refuse: ty.Any = None,
        always: bool = False,
    ):
        self.devices: list = []
        self.calls = 0
        self.resolved = 0
        self._refuse = refuse
        self._always = always
        self._bind = netimps.bind
        self._iter = netimps.iter_interfaces
        monkeypatch.setattr(netimps, "bind", self.bind)
        monkeypatch.setattr(netimps, "iter_interfaces", self.iter_interfaces)
        monkeypatch.setattr(netimps, "has_device_binding", lambda: True)

    def bind(self, *args: ty.Any, **kwargs: ty.Any) -> socket.socket:
        self.calls += 1
        device = kwargs.pop("device", None)
        self.devices.append(device)
        if self._refuse is not None and (device is not None or self._always):
            raise self._refuse
        return self._bind(*args, **kwargs)

    def iter_interfaces(self, *args: ty.Any, **kwargs: ty.Any) -> ty.Any:
        self.resolved += 1
        return self._iter(*args, **kwargs)


def test_nothing_is_bound_to_a_device_where_the_host_has_no_such_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list = []
    real = netimps.bind

    def spy(*args: ty.Any, **kwargs: ty.Any) -> socket.socket:
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(netimps, "bind", spy)
    monkeypatch.setattr(netimps, "has_device_binding", lambda: False)
    listener = DHCPListener(listen=(_loopback(), 0))
    listener.bind()
    try:
        assert seen and all(kwargs.get("device") is None for kwargs in seen)
        # private: the OS socket: its options and closed state have no public view
        (sock,) = listener._sockets
        # private: the interface allow-list a listener builds: no public view
        assert listener._allowed[sock] == frozenset({_loopback().index})
    finally:
        listener.close()


@pytest.mark.parametrize("driver", [DHCPListener, AsyncDHCPListener])
def test_a_socket_is_bound_to_the_adapter_the_grammar_resolved(
    driver: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _Netimps(monkeypatch)
    listener = driver(listen=(_loopback(), 0))
    listener.bind()
    try:
        (device,) = fake.devices
        assert isinstance(device, netimps.Interface)
        assert device.index == _loopback().index
        # The adapter was looked up once, for the allow-list and the device alike.
        assert fake.resolved == 1
        # The allow-list stays as a second check.
        (sock,) = listener._sockets
        # private: the receive path's admission check, driven without a socket
        assert not listener._admits(_arrival(_loopback().index + 100), sock)
        assert listener.metrics.packets_dropped_other_interface == 1
    finally:
        if driver is DHCPListener:
            listener.close()
        else:
            asyncio.run(listener.aclose())


def test_the_class_attribute_forces_the_filter_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Netimps(monkeypatch)

    class Filtering(DHCPListener):
        USE_DEVICE_BINDING = False

    listener = Filtering(listen=(_loopback(), 0))
    listener.bind()
    try:
        assert fake.devices == [None]
    finally:
        listener.close()


def test_a_socket_serving_several_adapters_is_not_bound_to_one_of_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Netimps(monkeypatch)
    listener = DHCPListener(listen=[(_loopback(), 0), (_another_adapter(), 0)])
    listener.bind()
    try:
        assert fake.devices == [None]
        # private: the OS socket: its options and closed state have no public view
        (sock,) = listener._sockets
        # private: the interface allow-list a listener builds: no public view
        assert len(listener._allowed[sock]) == 2
    finally:
        listener.close()


def test_a_plain_wildcard_and_an_address_are_not_bound_to_a_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Netimps(monkeypatch)
    listener = DHCPListener(listen=["*:0", "127.0.0.1:0"])
    listener.bind()
    try:
        assert fake.devices and all(device is None for device in fake.devices)
    finally:
        listener.close()


@pytest.mark.parametrize(
    "refusal",
    [
        netimps.DeviceBindingUnsupportedError(92, "no device binding"),
        PermissionError(1, "Operation not permitted"),
    ],
    ids=["unsupported", "permission"],
)
def test_a_refused_device_binding_falls_back_to_the_filter_and_says_so_once(
    refusal: OSError, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Refused: the same socket is bound without the device, so it hears what the
    allow-list admits and the filter does the rest. Failing the bind would leave
    a listener that hears nothing it was asked to hear."""
    import logging

    fake = _Netimps(monkeypatch, refuse=refusal)
    listener = DHCPListener(listen=(_loopback(), 0))
    with caplog.at_level(logging.INFO, logger="pydhcp"):
        listener.bind()
    try:
        assert len(fake.devices) == 2 and fake.devices[0] is not None
        assert fake.devices[1] is None
        # private: the OS socket: its options and closed state have no public view
        (sock,) = listener._sockets
        # private: the interface allow-list a listener builds: no public view
        assert listener._allowed[sock] == frozenset({_loopback().index})
        # private: the receive path's admission check, driven without a socket
        assert listener._admits(_arrival(_loopback().index), sock)
        assert not listener._admits(_arrival(_loopback().index + 100), sock)
        assert listener.metrics.packets_dropped_other_interface == 1
        said = [r for r in caplog.records if "device" in r.getMessage()]
        assert len(said) == 1, [r.getMessage() for r in caplog.records]
    finally:
        listener.close()


def test_a_bind_that_fails_for_another_reason_is_not_mistaken_for_a_refused_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    taken = netimps.AddressInUseError(98, "Address already in use")
    fake = _Netimps(monkeypatch, refuse=taken, always=True)
    listener = DHCPListener(listen=(_loopback(), 0))
    with pytest.raises(netimps.AddressInUseError):
        listener.bind()
    # private: the OS socket: its options and closed state have no public view
    assert listener._sockets == [] and listener.bound_addresses == ()
    # Not a refusal of the device: no second attempt, the error is the caller's.
    assert len(fake.devices) == 1 and fake.calls == 1
