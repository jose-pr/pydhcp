"""The two listeners are siblings over one private core.

The core holds configuration, binding and the handling of one datagram; each
driver adds only how datagrams are read and how serving starts and stops.
"""

from __future__ import annotations

import ipaddress
import logging

import pytest

# private: the unit under test is not exported from a public module
from pydhcp import _constants as constants

# private: the unit under test is not re-exported from a public module
from pydhcp._network import SocketAddress
from pydhcp.listener import AsyncDHCPListener, DHCPListener
from pydhcp.listener._core import _ListenerCore

DRIVERS = [DHCPListener, AsyncDHCPListener]


def test_the_drivers_are_siblings_over_the_core() -> None:
    assert issubclass(DHCPListener, _ListenerCore)
    assert issubclass(AsyncDHCPListener, _ListenerCore)
    assert not issubclass(AsyncDHCPListener, DHCPListener)
    assert not issubclass(DHCPListener, AsyncDHCPListener)


@pytest.mark.parametrize("driver", DRIVERS)
def test_binding_and_dispatch_are_the_cores_own(driver: type) -> None:
    for name in ("bind", "bound_addresses", "_dispatch", "handle", "_close_sockets"):
        assert getattr(driver, name) is getattr(_ListenerCore, name), name


@pytest.mark.parametrize("driver", DRIVERS)
def test_max_packet_size_has_one_default_that_is_the_largest_datagram(
    driver: type,
) -> None:
    """`None` and 0 both mean the constant, so the receive buffer asked of the
    socket is the same on both drivers: one octet over it, to tell a datagram
    that fills the limit from one that exceeds it."""
    # private: the receive limit as stored
    assert driver(listen=("127.0.0.1", 0))._max_packet_size == (
        constants.UDP_MAX_PACKET_SIZE
    )
    assert driver(listen=("127.0.0.1", 0), max_packet_size=0)._max_packet_size == (
        constants.UDP_MAX_PACKET_SIZE
    )
    assert driver(listen=("127.0.0.1", 0), max_packet_size=576)._max_packet_size == 576


def test_the_async_listener_has_no_counters_beside_the_metrics() -> None:
    listener = AsyncDHCPListener(listen=("127.0.0.1", 0))
    assert not hasattr(listener, "packets_dropped_truncated")
    assert not hasattr(listener, "packets_dropped_error")
    assert listener.metrics.packets_dropped_truncated == 0


@pytest.mark.parametrize("driver", DRIVERS)
def test_constructing_with_per_interface_enumerates_nothing(
    driver: type, enumerations
) -> None:
    listener = driver(listen="*", per_interface=True)
    assert len(enumerations) == 0
    # private: the parsed listen spec: `bound_addresses` is empty until the bind
    assert listener._listen == [SocketAddress(ipaddress.IPv4Address("0.0.0.0"), 67)] + [
        SocketAddress(ipaddress.IPv4Address("0.0.0.0"), 68)
    ]


@pytest.mark.parametrize("driver", DRIVERS)
def test_the_wildcard_is_expanded_when_binding(driver: type, enumerations) -> None:
    listener = driver(listen=("0.0.0.0", 0), per_interface=True)
    assert len(enumerations) == 0
    listener.bind()
    try:
        assert len(enumerations) >= 1
        bound = {a.ip for a in listener.bound_addresses}
        assert bound and ipaddress.IPv4Address("0.0.0.0") not in bound
    finally:
        # private: the release path, called directly
        listener._close_sockets()
    assert listener.bound_addresses == ()


@pytest.mark.parametrize("driver", DRIVERS)
def test_an_undecodable_datagram_is_counted_and_warned_the_same(
    driver: type, caplog: pytest.LogCaptureFixture
) -> None:
    listener = driver(listen=("127.0.0.1", 0))
    client = SocketAddress(ipaddress.IPv4Address("192.0.2.9"), 68)
    # private: the name is looked up in the module that reads it, so the host or the clock can be stood for
    with caplog.at_level(logging.WARNING, logger="pydhcp.listener._core"):
        # private: drives one datagram through the receive path without a socket
        listener._dispatch(b"\x01\x02", client, None)  # type: ignore[arg-type]
    assert listener.metrics.packets_dropped_error == 1
    assert listener.metrics.packets_received == 0
    assert [r.levelno for r in caplog.records] == [logging.WARNING]
    assert "192.0.2.9" in caplog.records[0].getMessage()
