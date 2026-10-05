"""The client FQDN option (RFC 4702)."""

from __future__ import annotations

import typing as _ty
from ...exceptions import DHCPDecodeError, DHCPValueError
from .base import DhcpOptionType
from .domain import decode_domain_name, encode_domain_name

_ClientFqdnT = _ty.TypeVar("_ClientFqdnT", bound="ClientFqdn")


class ClientFqdn(DhcpOptionType):
    """RFC 4702 Client FQDN: flags, RCODE1, RCODE2, then the name.

    With the E bit the name is a fully qualified name (RFC 1035 labels and the
    terminating zero-length label), a **partial** name (the labels without the
    terminator) or empty (RFC 4702 s2.3). `partial` says which: it is true for
    a partial name and for an empty field, false for a qualified name and for
    the root (a lone terminator), so what is decoded is encoded to the octets
    it came from. The four reserved flag bits are ignored on receive and may
    not be set on send (s2.1).

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

    #: The flag bits RFC 4702 s2.1 defines; the other four must be zero.
    FLAGS_MASK = 0x0F

    # Declared so the instance-accepting constructor can read `other.name`
    # without mypy hitting a circular inference.
    name: str
    partial: bool
    flags: int
    rcode1: int
    rcode2: int

    def __init__(
        self,
        name: _ty.Any = "",
        flags: int = 0,
        rcode1: int = 0,
        rcode2: int = 0,
        partial: bool = False,
    ) -> None:
        if isinstance(name, ClientFqdn):
            name, flags, rcode1, rcode2, partial = (
                name.name,
                name.flags,
                name.rcode1,
                name.rcode2,
                name.partial,
            )
        elif isinstance(name, _ty.Mapping):
            mapping = name
            name = mapping.get("name", "")
            flags = int(mapping.get("flags", 0))
            rcode1 = int(mapping.get("rcode1", 0))
            rcode2 = int(mapping.get("rcode2", 0))
            partial = bool(mapping.get("partial", False))
        for label, value in (("flags", flags), ("rcode1", rcode1), ("rcode2", rcode2)):
            if not 0 <= int(value) <= 0xFF:
                raise DHCPValueError(f"ClientFqdn {label} must fit in one octet")
        if int(flags) & ~self.FLAGS_MASK:
            raise DHCPValueError(
                f"ClientFqdn flags {int(flags):#04x} set reserved bits; "
                "RFC 4702 s2.1 requires the senders to clear them"
            )
        if partial and not int(flags) & self.FLAG_E:
            raise DHCPValueError(
                "ClientFqdn partial applies to the DNS wire format: set the E bit"
            )
        self.name = str(name)
        self.flags = int(flags)
        self.rcode1 = int(rcode1)
        self.rcode2 = int(rcode2)
        self.partial = bool(partial)

    @property
    def encoded(self) -> bool:
        """Whether the name is carried in DNS wire format (the E bit)."""
        return bool(self.flags & self.FLAG_E)

    @classmethod
    def _dhcp_read(
        cls: type[_ClientFqdnT], option: memoryview
    ) -> tuple[_ClientFqdnT, int]:
        if len(option) < 3:
            raise DHCPDecodeError(
                "ClientFqdn option is truncated: needs at least 3 octets"
            )
        # RFC 4702 s2.1: the reserved bits MUST be ignored.
        flags, rcode1, rcode2 = option[0] & cls.FLAGS_MASK, option[1], option[2]
        rest = option[3:]
        partial = False
        if flags & cls.FLAG_E:
            name, partial = cls._read_wire_name(rest)
        else:
            try:
                name = rest.tobytes().split(b"\x00", 1)[0].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DHCPDecodeError("ClientFqdn name is not valid UTF-8") from exc
        return cls(name, flags, rcode1, rcode2, partial), len(option)

    @staticmethod
    def _read_wire_name(field: memoryview) -> tuple[str, bool]:
        """The name of an E-bit field and whether it is partial (RFC 4702 s2.3)."""
        if not field:
            return "", True
        try:
            name, read = decode_domain_name(field, 0, "ClientFqdn name")
        except DHCPDecodeError:
            # Ran out before a terminating label: a partial name if what was
            # read is whole labels, an error if a label is cut short. Reading
            # the labels followed by a terminator tells the two apart.
            name, read = decode_domain_name(
                memoryview(field.tobytes() + b"\x00"), 0, "ClientFqdn name"
            )
            if read != len(field) + 1:
                raise DHCPDecodeError("ClientFqdn name is truncated") from None
            return name, True
        if read != len(field):
            raise DHCPDecodeError("ClientFqdn has trailing data after the name")
        return name, False

    def _dhcp_write(self, data: bytearray) -> int:
        start = len(data)
        data.append(self.flags)
        data.append(self.rcode1)
        data.append(self.rcode2)
        if self.encoded:
            wire = encode_domain_name(self.name, "ClientFqdn name", allow_root=True)
            # A partial name has no terminating label; with no name at all the
            # field is empty (RFC 4702 s2.3).
            data.extend(wire[:-1] if self.partial else wire)
        else:
            data.extend(self.name.encode("utf-8"))
        return len(data) - start

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ClientFqdn):
            return NotImplemented
        return (self.name, self.flags, self.rcode1, self.rcode2, self.partial) == (
            other.name,
            other.flags,
            other.rcode1,
            other.rcode2,
            other.partial,
        )

    def __hash__(self) -> int:
        return hash((self.name, self.flags, self.rcode1, self.rcode2, self.partial))

    def __repr__(self) -> str:
        return (
            f"ClientFqdn(name={self.name!r}, flags={self.flags:#04x}, "
            f"rcode1={self.rcode1}, rcode2={self.rcode2}"
            + (", partial=True)" if self.partial else ")")
        )

    def __json__(self) -> dict[str, _ty.Any]:
        return {
            "name": self.name,
            "flags": self.flags,
            "rcode1": self.rcode1,
            "rcode2": self.rcode2,
            "partial": self.partial,
        }
