"""What a decoder forgave, handed to whoever is counting.

Decoding is liberal on receive: an option cut short keeps what arrived, and text
that is not UTF-8 keeps its octets. A decoder is the wrong place to hold state
or to write a line per datagram, so it calls `note()` and logs at DEBUG; the
listener decodes inside `collecting()` and counts the datagram in its metrics.
"""

from __future__ import annotations

import contextvars as _contextvars
import types as _types
import typing as _ty

_current: "_contextvars.ContextVar[_ty.Optional[collecting]]" = _contextvars.ContextVar(
    "pydhcp_decode_leniency", default=None
)


class collecting:
    """Counts the `note()` calls made while it is open, on this thread or task."""

    def __init__(self) -> None:
        self.count = 0
        self._token: "_ty.Optional[_contextvars.Token[_ty.Optional[collecting]]]" = None

    def __enter__(self) -> "collecting":
        self._token = _current.set(self)
        return self

    def __exit__(
        self,
        exc_type: "_ty.Optional[type[BaseException]]",
        exc: "_ty.Optional[BaseException]",
        tb: "_ty.Optional[_types.TracebackType]",
    ) -> None:
        if self._token is not None:
            _current.reset(self._token)
            self._token = None


def note() -> None:
    """Record that the decoder in progress accepted something it could have refused."""
    open_collector = _current.get()
    if open_collector is not None:
        open_collector.count += 1
