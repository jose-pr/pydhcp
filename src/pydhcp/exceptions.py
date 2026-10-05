"""Every exception the package raises on its own account.

`DHCPError` is the one base: a caller who wants "anything pydhcp reported"
catches it. Each class also inherits the builtin a caller would already catch
for that kind of failure, so an `except ValueError` keeps working.

A caller's own mistake, such as a wrong argument type or a call made out of
order, is not here: it raises plain `ValueError` or `TypeError`.
"""

from __future__ import annotations

__all__ = [
    "DHCPError",
    "DHCPDecodeError",
    "DHCPValueError",
    "NoClientIdentityError",
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
