"""Lossless text for the fields RFC 2131 calls NVT ASCII.

`sname`, `file` and the RFC 2132 string options are specified as NVT ASCII, and
real senders put other encodings in them -- a Latin-1 hostname, a boot filename
from a non-English TFTP server. Two behaviours are both wrong:

* rejecting the packet throws away its message type, client id and everything
  else over a name the receiver usually does not read;
* decoding with ``errors="replace"`` keeps the packet but destroys the bytes,
  and a relay re-encoding it emits a *different* name. One octet becomes the
  three of U+FFFD, so the value can also overrun its fixed-width field and be
  truncated. For `file` that is the PXE boot filename, and the boot then fails.

``surrogateescape`` keeps both: undecodable octets are parked in the surrogate
range and restored exactly on encode, while valid UTF-8 is untouched. The cost
is that the resulting `str` cannot be written to a non-UTF-8 stream or a strict
encoder, so anything rendering one for a human or for structured output passes
it through `display` first.
"""

from __future__ import annotations

from .log import LOGGER

_ERRORS = "surrogateescape"


def decode(raw: bytes, what: str = "text") -> str:
    """Decode NVT text, preserving octets that are not valid UTF-8."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        LOGGER.warning(
            f"{what} is not valid UTF-8, preserving the original octets: {raw.hex()}"
        )
        return raw.decode("utf-8", _ERRORS)


def encode(text: str) -> bytes:
    """Encode NVT text, restoring octets `decode` could not represent."""
    return text.encode("utf-8", _ERRORS)


def display(text: str) -> str:
    """Render NVT text safely for a terminal, a log, or structured output.

    Surrogates become U+FFFD here and only here: this is the lossy step, taken
    at the boundary where the value is being shown rather than when it is
    parsed, so the wire bytes survive for anything that re-encodes the message.
    """
    # Via the original octets, not str.encode(errors="replace"): the replace
    # handler on the *encode* side substitutes "?", losing the fact that a byte
    # was undecodable at all. Round-tripping through surrogateescape first
    # restores the octet, so the decode-side handler yields U+FFFD as it would
    # have for a value that was never preserved.
    return text.encode("utf-8", _ERRORS).decode("utf-8", "replace")
