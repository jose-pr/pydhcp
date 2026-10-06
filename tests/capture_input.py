"""The fixed input of the capture tests: `tests/data/capture_output/build.py`, loaded.

`datagrams()` is the 53 messages every capture-output test sends, in order.
"""

from __future__ import annotations

import importlib.util
import pathlib
import typing as _ty

_BUILD = pathlib.Path(__file__).parent / "data" / "capture_output" / "build.py"
_SPEC = importlib.util.spec_from_file_location("capture_output_build", _BUILD)
assert _SPEC is not None and _SPEC.loader is not None
build = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(build)


def datagrams() -> "list[bytes]":
    return _ty.cast("list[bytes]", build.datagrams())


def short_datagram() -> bytes:
    """A recorded DISCOVER with the zero padding after its end option cut off.

    A client may send no padding at all; the message encodes back to 300 octets.
    """
    data = build.recorded()[0].rstrip(b"\0")
    assert data[-1] == 0xFF and len(data) < 300
    return _ty.cast(bytes, data)
