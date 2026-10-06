"""Every exception the package raises on its own account.

`DHCPError` is the one base: a caller who wants "anything pydhcp reported"
catches it. Each class also inherits the builtin a caller would already catch
for that kind of failure, so an `except ValueError` keeps working.

A caller's own mistake, such as a wrong argument type or a call made out of
order, is not here: it raises plain `ValueError` or `TypeError`.
"""

from __future__ import annotations

import typing as _ty

__all__ = [
    "DHCPError",
    "DHCPDecodeError",
    "DHCPValueError",
    "NoClientIdentityError",
    "DHCPTimeoutError",
    "DHCPRefusedError",
]


class DHCPError(Exception):
    """The base of every exception pydhcp raises on its own account."""


class DHCPDecodeError(DHCPError, ValueError):
    """Octets that are not the message, option or name they were read as.

    Raised by every decoder for a truncated, oversized, looping or otherwise
    malformed input. Also a `ValueError`.
    """


class DHCPValueError(DHCPError, ValueError):
    """A value an option codec or message field cannot represent.

    Raised when a constructor rejects what it was given: an entry past one
    octet's length, an empty list where the RFC requires an entry, a prefix
    past 32. Also a `ValueError`.
    """


class NoClientIdentityError(DHCPError, ValueError):
    """A message carries nothing that identifies its client.

    Neither a client identifier option nor a hardware address. Also a
    `ValueError`; a server drops the message rather than failing.
    """


class DHCPTimeoutError(DHCPError, TimeoutError):
    """A client exchange ended with no usable reply from the server.

    Raised by `DHCPClient` and `AsyncDHCPClient` when the retransmissions, or the
    `deadline` of the call, ran out before an acceptable DHCPOFFER or DHCPACK
    arrived. Also a `TimeoutError`.
    """


class DHCPRefusedError(DHCPError):
    """The server answered a DHCPREQUEST with a DHCPNAK.

    The client's configuration process starts over (RFC 2131 section 3.1), so the
    exchange ends at once instead of retransmitting. `nak` is the DHCPNAK
    message; its `DHCP_MESSAGE` option, when present, says why.
    """

    #: The DHCPNAK `DHCPMessage`. Typed `Any` because this module is a leaf
    #: that the message decoder itself imports.
    nak: _ty.Any

    def __init__(self, message: str, nak: _ty.Any) -> None:
        super().__init__(message, nak)
        self.nak = nak

    def __str__(self) -> str:
        return str(self.args[0])
