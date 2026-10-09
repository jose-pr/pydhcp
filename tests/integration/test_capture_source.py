"""`sniff_dhcp` and `asniff_dhcp`: DHCP messages arriving at sockets, as dissected frames.

The ground truth is the platform's: a datagram sent to a loopback port comes back as a
frame, and a port is free again exactly when the source has closed its socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import socket
import typing as _ty

import pytest

pktcap = pytest.importorskip("pktcap")

from cli_process import free_port
from helpers import build_request
from pydhcp import DHCPMessage
from pydhcp.capture import DHCPLayer, asniff_dhcp, sniff_dhcp
from pydhcp.packet import DHCPMessageType


def _send(port: int, data: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
        out.sendto(data, ("127.0.0.1", port))


def _discover() -> DHCPMessage:
    return build_request(
        DHCPMessageType.DHCPDISCOVER, xid=0x1A52B52E, chaddr=b"\x02\x00\x00\x99\x00\x02"
    )


def _port_is_free(port: int) -> bool:
    """Whether a fresh socket can bind the port: the platform's word on a closed source."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def test_a_discover_sent_to_a_loopback_socket_comes_back_as_a_dhcp_frame() -> None:
    port = free_port()
    sent = _discover()
    frames = sniff_dhcp(f"127.0.0.1:{port}")
    try:
        _send(port, bytes(sent.encode()))
        frame = next(frames)
    finally:
        frames.close()  # type: ignore[attr-defined]

    layer = frame.layers[-1]
    assert isinstance(layer, DHCPLayer)
    datagram = frame.datagram()
    assert datagram is not None
    assert datagram.destination == ("127.0.0.1", port)
    assert DHCPMessage.decode(datagram.payload).to_mapping() == sent.to_mapping()
    assert layer.message == sent.to_mapping()
    assert layer.message_type == "DHCPDISCOVER"


def test_the_sockets_are_closed_when_the_consumer_closes_the_iterator() -> None:
    port = free_port()
    frames = sniff_dhcp(f"127.0.0.1:{port}")
    assert not _port_is_free(port)

    frames.close()  # type: ignore[attr-defined]

    assert _port_is_free(port)


def test_the_sockets_are_closed_when_stop_ends_the_iteration() -> None:
    port = free_port()

    assert list(sniff_dhcp(f"127.0.0.1:{port}", stop=lambda: True)) == []

    assert _port_is_free(port)


def test_the_sockets_are_closed_when_the_iterator_is_dropped() -> None:
    port = free_port()
    frames = sniff_dhcp(f"127.0.0.1:{port}")
    assert not _port_is_free(port)

    del frames
    gc.collect()

    assert _port_is_free(port)


def test_an_interface_binding_that_matches_nothing_opens_nothing() -> None:
    port = free_port()

    with pytest.raises(ValueError, match="no-such-adapter-0"):
        sniff_dhcp(f"127.0.0.1:{port},no-such-adapter-0:{port}")

    assert _port_is_free(port)


def test_an_argument_pktcap_refuses_leaves_no_socket_open() -> None:
    port = free_port()

    with pytest.raises(TypeError):
        sniff_dhcp(f"127.0.0.1:{port}", stop=5)  # type: ignore[arg-type]

    assert _port_is_free(port)


def test_a_dissector_given_is_the_one_used() -> None:
    port = free_port()
    frames = sniff_dhcp(
        f"127.0.0.1:{port}", dissector=pktcap.FrameDissector(pktcap.DissectorRegistry())
    )
    try:
        _send(port, bytes(_discover().encode()))
        frame = next(frames)
    finally:
        frames.close()  # type: ignore[attr-defined]

    assert not any(isinstance(layer, DHCPLayer) for layer in frame.layers)


def test_a_datagram_that_is_no_message_still_comes_back_with_the_reason() -> None:
    port = free_port()
    frames = sniff_dhcp(f"127.0.0.1:{port}")
    try:
        _send(port, b"not dhcp")
        frame = next(frames)
    finally:
        frames.close()  # type: ignore[attr-defined]

    assert frame.error is not None
    assert not any(isinstance(layer, DHCPLayer) for layer in frame.layers)
    assert frame.payload_of(pktcap.UDPLayer) == b"not dhcp"


def test_the_listen_specification_is_read_with_dhcp_ports_family_and_broadcast(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netimps

    calls: "_ty.List[_ty.Tuple[_ty.Any, _ty.Dict[str, _ty.Any]]]" = []
    real = netimps.bind_listen

    def record(*args: _ty.Any, **options: _ty.Any) -> _ty.Any:
        calls.append((args, options))
        return real(*args, **options)

    # patched where the source reads it
    monkeypatch.setattr("pydhcp.capture._source._netimps.bind_listen", record)
    port = free_port()

    sniff_dhcp(f"127.0.0.1:{port}", per_interface=True).close()  # type: ignore[attr-defined]
    sniff_dhcp(f"127.0.0.1:{port}").close()  # type: ignore[attr-defined]

    first, second = calls
    assert first[0] == (f"127.0.0.1:{port}", (67, 68))
    assert first[1] == {
        "family": socket.AF_INET,
        "per_address": True,
        "broadcast": True,
    }
    assert second[1]["per_address"] is None


# -- the asynchronous twin ----------------------------------------------------------


def test_asniff_dhcp_returns_the_frame_of_a_datagram_and_leaves_nothing_behind() -> (
    None
):
    port = free_port()
    sent = _discover()

    async def main() -> DHCPLayer:
        frames = asniff_dhcp(f"127.0.0.1:{port}")
        _send(port, bytes(sent.encode()))
        frame = await asyncio.wait_for(frames.__anext__(), 10)
        await frames.aclose()  # type: ignore[attr-defined]
        await asyncio.sleep(0)
        assert asyncio.all_tasks() == {asyncio.current_task()}
        layer = frame.layers[-1]
        assert isinstance(layer, DHCPLayer)
        return layer

    layer = asyncio.run(main())

    assert layer.message == sent.to_mapping()
    assert _port_is_free(port)


def test_asniff_dhcp_stopped_early_leaves_no_task_and_no_socket() -> None:
    port = free_port()

    async def main() -> None:
        frames = asniff_dhcp(f"127.0.0.1:{port}")
        _send(port, bytes(_discover().encode()))
        async for _frame in frames:
            break
        await frames.aclose()  # type: ignore[attr-defined]
        await asyncio.sleep(0)
        assert asyncio.all_tasks() == {asyncio.current_task()}

    asyncio.run(main())

    assert _port_is_free(port)


def test_asniff_dhcp_cancelled_leaves_no_task_and_no_socket() -> None:
    port = free_port()

    async def consume(frames: _ty.Any) -> None:
        async for _frame in frames:
            pass

    async def main() -> None:
        frames = asniff_dhcp(f"127.0.0.1:{port}")
        task = asyncio.ensure_future(consume(frames))
        await asyncio.sleep(0.3)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await frames.aclose()
        for _ in range(5):
            await asyncio.sleep(0)
        assert asyncio.all_tasks() == {asyncio.current_task()}

    asyncio.run(main())

    assert _port_is_free(port)


def test_asniff_dhcp_refuses_an_interface_that_matches_nothing_with_nothing_opened() -> (
    None
):
    port = free_port()

    with pytest.raises(ValueError, match="no-such-adapter-0"):
        asniff_dhcp(f"127.0.0.1:{port},no-such-adapter-0:{port}")

    assert _port_is_free(port)
