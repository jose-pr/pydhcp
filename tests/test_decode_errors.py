"""Every decoder raises `DHCPDecodeError` for malformed octets, or returns.

A path that leaks `struct.error`, `IndexError`, `UnicodeDecodeError` or a bare
`ValueError` is a defect: a server reading the network must catch one type.
Inputs are seeded, so a failure reproduces.
"""

from __future__ import annotations

import random
from datetime import timedelta
import typing as _ty

import pytest

from pydhcp import DhcpMessage, DhcpOptions
from pydhcp.exceptions import DHCPDecodeError
from pydhcp.options import DhcpOptionCode
from pydhcp.options.type import IPv4Address
from pydhcp.network import IPv4
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode


def _seed_message() -> bytes:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = bytearray(
        [DhcpMessageType.DHCPDISCOVER.value]
    )
    options[DhcpOptionCode.HOSTNAME] = bytearray(b"host")
    options[DhcpOptionCode.PARAMETER_REQUEST_LIST] = bytearray([1, 3, 6, 15])
    message = DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=1,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=bytes([0, 17, 34, 51, 68, 85]),
        sname="",
        file="",
        options=options,
    )
    return bytes(message.encode())


def _mutations(count: int) -> _ty.Iterator[bytes]:
    rng = random.Random(20261005)
    base = bytearray(_seed_message())
    for i in range(count):
        data = bytearray(base)
        mode = i % 4
        if mode == 0:
            data = bytearray(rng.getrandbits(8) for _ in range(rng.randrange(0, 400)))
        elif mode == 1:
            del data[rng.randrange(1, len(data)) :]
        elif mode == 2:
            tail = bytearray(rng.getrandbits(8) for _ in range(rng.randrange(1, 80)))
            data = data[:240] + tail
        else:
            for _ in range(rng.randrange(1, 6)):
                data[rng.randrange(len(data))] = rng.getrandbits(8)
        yield bytes(data)


def test_a_mutated_message_raises_the_decode_error_or_nothing() -> None:
    leaked: _ty.Dict[str, int] = {}
    for data in _mutations(20000):
        try:
            DhcpMessage.decode(data)
        except DHCPDecodeError:
            pass
        except Exception as exc:  # noqa: BLE001 - the type is the report
            key = type(exc).__name__
            leaked[key] = leaked.get(key, 0) + 1
    assert leaked == {}


def test_a_random_payload_for_every_option_raises_the_decode_error_or_nothing() -> None:
    """Each option's own codec, fed payloads of every short length."""
    rng = random.Random(20261006)
    leaked: _ty.Dict[str, _ty.List[str]] = {}
    for code in range(1, 255):
        try:
            code_obj = DhcpOptionCode(code)
        except ValueError:
            continue
        for _ in range(60):
            size = rng.choice((0, 1, 2, 3, 4, 5, 8, 13, 30))
            payload = bytes(rng.getrandbits(8) for _ in range(size))
            options = DhcpOptions()
            options[code_obj] = bytearray(payload)
            try:
                options.get(code_obj)
            except DHCPDecodeError:
                pass
            except Exception as exc:  # noqa: BLE001 - the type is the report
                key = f"{code_obj.name} {type(exc).__name__}"
                leaked.setdefault(key, []).append(f"{payload.hex()}: {exc}")
    assert {key: values[:1] for key, values in leaked.items()} == {}


def test_an_unknown_op_is_a_decode_error() -> None:
    data = bytearray(_seed_message())
    data[0] = 9
    with pytest.raises(DHCPDecodeError):
        DhcpMessage.decode(data)


def test_a_codec_decode_error_names_the_codec() -> None:
    with pytest.raises(DHCPDecodeError, match="IPv4Address"):
        IPv4Address._dhcp_decode(memoryview(b"\x01\x02"))
