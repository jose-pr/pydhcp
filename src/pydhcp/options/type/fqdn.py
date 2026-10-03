"""The client FQDN option (RFC 4702)."""

from __future__ import annotations

import typing as _ty
from .base import DhcpOptionType
from .domain import decode_domain_name, encode_domain_name

if _ty.TYPE_CHECKING:
    from typing_extensions import Self


class ClientFqdn(DhcpOptionType):
    """RFC 4702 Client FQDN: flags, RCODE1, RCODE2, then the name.

    Registering this as a plain `String` lost data silently rather than loudly:
    `String` splits at the first NUL, so the form every Windows client sends
    (`00 00 00` then the name) decoded to the empty string, and a server reading
    it for DDNS saw no name at all. Emitting was the mirror image -- the first
    three characters of the name were read by the client as Flags/RCODE1/RCODE2.
    """

    #: The client requests that the server update the A RR (RFC 4702 s2.1).
    FLAG_S = 0x01
    #: The server overrode the client's S bit.
    FLAG_O = 0x02
    #: The name is in DNS wire format rather than ASCII.
    FLAG_E = 0x04
    #: The server should not perform any DNS update.
    FLAG_N = 0x08

    # Declared so the instance-accepting constructor can read `other.name`
    # without mypy hitting a circular inference.
    name: str
    flags: int
    rcode1: int
    rcode2: int

    def __init__(
        self,
        name: _ty.Any = "",
        flags: int = 0,
        rcode1: int = 0,
        rcode2: int = 0,
    ) -> None:
        if isinstance(name, ClientFqdn):
            name, flags, rcode1, rcode2 = (
                name.name,
                name.flags,
                name.rcode1,
                name.rcode2,
            )
        elif isinstance(name, _ty.Mapping):
            mapping = name
            name = mapping.get("name", "")
            flags = int(mapping.get("flags", 0))
            rcode1 = int(mapping.get("rcode1", 0))
            rcode2 = int(mapping.get("rcode2", 0))
        for label, value in (("flags", flags), ("rcode1", rcode1), ("rcode2", rcode2)):
            if not 0 <= int(value) <= 0xFF:
                raise ValueError(f"ClientFqdn {label} must fit in one octet")
        self.name = str(name)
        self.flags = int(flags)
        self.rcode1 = int(rcode1)
        self.rcode2 = int(rcode2)

    @property
    def encoded(self) -> bool:
        """Whether the name is carried in DNS wire format (the E bit)."""
        return bool(self.flags & self.FLAG_E)

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        if len(option) < 3:
            raise ValueError("ClientFqdn option is truncated: needs at least 3 octets")
        flags, rcode1, rcode2 = option[0], option[1], option[2]
        if flags & 0xF0:
            raise ValueError(f"ClientFqdn reserved flag bits set: {flags:#04x}")
        rest = option[3:]
        if flags & cls.FLAG_E:
            name, read = decode_domain_name(rest, 0, "ClientFqdn name")
            if read != len(rest):
                raise ValueError("ClientFqdn has trailing data after the name")
        else:
            name = rest.tobytes().split(b"\x00", 1)[0].decode("utf-8")
        return cls(name, flags, rcode1, rcode2), len(option)

    def _dhcp_write(self, data: bytearray) -> int:
        start = len(data)
        data.append(self.flags)
        data.append(self.rcode1)
        data.append(self.rcode2)
        if self.encoded:
            data.extend(
                encode_domain_name(self.name, "ClientFqdn name", allow_root=True)
            )
        else:
            data.extend(self.name.encode("utf-8"))
        return len(data) - start

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ClientFqdn):
            return NotImplemented
        return (self.name, self.flags, self.rcode1, self.rcode2) == (
            other.name,
            other.flags,
            other.rcode1,
            other.rcode2,
        )

    def __hash__(self) -> int:
        return hash((self.name, self.flags, self.rcode1, self.rcode2))

    def __repr__(self) -> str:
        return (
            f"ClientFqdn(name={self.name!r}, flags={self.flags:#04x}, "
            f"rcode1={self.rcode1}, rcode2={self.rcode2})"
        )

    def __json__(self) -> dict[str, _ty.Any]:
        return {
            "name": self.name,
            "flags": self.flags,
            "rcode1": self.rcode1,
            "rcode2": self.rcode2,
        }
