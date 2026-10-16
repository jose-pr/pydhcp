"""A DHCP message as a plain mapping, and back -- the structured formats' basis."""

from __future__ import annotations

import ipaddress as _ipaddress
import datetime as _dt
import typing as _ty

from . import _enums as _enum
from .. import _nvt as _nvt
from ..options._codes import OptionCode
from ..options import DHCPOptions
from ..options._mapping import coerce_enum_value, strip_hex_text
from ._encode import _MessageEncode
from ._fields import _MessageFields
from . import structured as _structured


def _coerce_chaddr(value: _ty.Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, int) and not isinstance(value, bool):
        # YAML 1.1 reads an unquoted `10:20:30:40:50:55` as a sexagesimal
        # integer (measured: 8041827055), so hand-authored YAML loses the MAC
        # before `from_mapping` ever sees it. A generic "must be text or
        # bytes-like" would name the symptom and not the cause.
        raise TypeError(
            f"chaddr arrived as the integer {value}, which is how YAML reads an "
            "unquoted colon-separated MAC address -- quote it "
            "(chaddr: '10:20:30:40:50:55')"
        )
    if not isinstance(value, str):
        raise TypeError("chaddr must be text or bytes-like")
    return bytes.fromhex(strip_hex_text(value))


def _text_value(text: str) -> _ty.Any:
    """`sname` or `file` for a document: the text, or its octets when the text
    would not give them back (a name that is not UTF-8)."""
    shown = _nvt.display(text)
    if _nvt.encode(shown) == _nvt.encode(text):
        return shown
    return {_MessageFields.HEX_VALUE_KEY: _nvt.encode(text).hex()}


def _coerce_bootp_text(value: _ty.Any, field: str) -> str:
    """Coerce a mapping's `sname`/`file` to text without inventing content.

    A bare `sname:` / `file:` key in YAML (and a JSON `null`) loads as `None`,
    which is an empty field, what the wire encodes as an all-NUL BOOTP field;
    octets (`bytes`, or the explicit hex form) are read as they are.
    """
    if value is None:
        return ""
    if isinstance(value, _ty.Mapping) and set(value) == {_MessageFields.HEX_VALUE_KEY}:
        try:
            value = bytes.fromhex(
                strip_hex_text(str(value[_MessageFields.HEX_VALUE_KEY]))
            )
        except ValueError as exc:
            raise ValueError(f"{field} is not hex octets: {exc}") from exc
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _nvt.decode(bytes(value))
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text or null, not {type(value).__name__}")
    return value


#: How each header field but `op` is read from a mapping. A field the mapping
#: leaves out takes the constructor's default.
_HEADER: dict[str, _ty.Callable[[_ty.Any], _ty.Any]] = {
    "htype": lambda v: coerce_enum_value(_enum.HardwareAddressType, v),
    "hlen": int,
    "hops": int,
    "xid": int,
    "secs": lambda v: _dt.timedelta(seconds=int(v)),
    "flags": lambda v: coerce_enum_value(_enum.DHCPFlags, v),
    "ciaddr": _ipaddress.IPv4Address,
    "yiaddr": _ipaddress.IPv4Address,
    "siaddr": _ipaddress.IPv4Address,
    "giaddr": _ipaddress.IPv4Address,
    "chaddr": _coerce_chaddr,
    "sname": lambda v: _coerce_bootp_text(v, "sname"),
    "file": lambda v: _coerce_bootp_text(v, "file"),
}

#: The class `from_mapping` is called on, which it constructs: typed as that
#: class (`DHCPMessage` for `DHCPMessage.from_mapping`).
_Mapped = _ty.TypeVar("_Mapped", bound="_MessageMapping")


class _MessageMapping(_MessageEncode):
    """`to_mapping` / `from_mapping`, byte-exact."""

    def to_mapping(self) -> dict[str, _ty.Any]:
        """The message as a plain dict: header fields, then `options`.

        The basis of the JSON/YAML/TOML/INI helpers, and byte-exact: `options`
        is `DHCPOptions.to_mapping`'s form, and `sname` and `file` are text, or
        ``{HEX_VALUE_KEY: "..."}`` when they are not UTF-8. Integers are plain `int`.
        """
        return {
            "op": self.op.name,
            # label(), not .name: an unnamed hardware type has no .name at all,
            # so a mapping would carry a null where a string is expected and
            # from_mapping() could not read it back.
            "htype": self.htype.label(),
            "hlen": self.hlen,
            "hops": self.hops,
            "xid": self.xid,
            "secs": int(self.secs.total_seconds()),
            # The name when the field is one of the two assigned values, the
            # number when a reserved bit is set (a name cannot carry it).
            "flags": (
                self.flags.label()
                if int(self.flags) in (0, 0x8000)
                else int(self.flags)
            ),
            "ciaddr": str(self.ciaddr),
            "yiaddr": str(self.yiaddr),
            "siaddr": str(self.siaddr),
            "giaddr": str(self.giaddr),
            "chaddr": self.chaddr.hex(":").upper(),
            # Text a strict serializer can write, or the octets as hex when the
            # name is not UTF-8.
            "sname": _text_value(self.sname),
            "file": _text_value(self.file),
            "options": self.options.to_mapping(),
        }

    def to_text(self, format: str) -> str:
        """The message as a document in `format`: ``"json"``, ``"yaml"``, ``"toml"`` or ``"ini"``.

        `to_mapping` written out by `pydhcp.packet.structured.dumps`; a format
        that is not one of the four raises `ValueError`.
        """
        return _structured.dumps(self.to_mapping(), format)

    @classmethod
    def from_text(
        cls: "type[_Mapped]",
        text: str,
        format: str,
        *,
        codemap: _ty.Optional[type[OptionCode]] = None,
    ) -> _Mapped:
        """Build a message from a document `to_text` (or the capture command) wrote.

        `pydhcp.packet.structured.loads` then `from_mapping`, with the same
        `codemap` and the same errors.
        """
        return cls.from_mapping(_structured.loads(text, format), codemap=codemap)

    @classmethod
    def from_hex(cls: "type[_Mapped]", text: str) -> _Mapped:
        """Decode a message written as hexadecimal text.

        Spaces, tabs, line ends and colons between the digits are ignored, so
        `01:01:06:00` and a hexdump's lines read the same. `ValueError` for
        anything else that is not a hexadecimal digit or for an odd number of
        digits; `DHCPDecodeError` when the octets are not a message.
        """
        return cls.decode(bytes.fromhex(strip_hex_text(text)))

    @classmethod
    def from_mapping(
        cls: "type[_Mapped]",
        data: _ty.Mapping[str, _ty.Any],
        *,
        codemap: _ty.Optional[type[OptionCode]] = None,
    ) -> _Mapped:
        """Build a message from a mapping in the shape `to_mapping` produces.

        Only `op` is required: a header field left out (or `options`) takes the
        constructor's default -- `0.0.0.0` for an address, 0 for a number, an
        empty `chaddr`, `hlen` its length. `options` is read by
        `DHCPOptions.from_mapping` with `codemap`, so `to_mapping` ->
        `from_mapping` round-trips exactly when `codemap` is the one the options
        were named with (the default is `DHCPOptionCode`). `sname` and `file`
        take text, null (empty), `bytes` or the hex form. A MAC written unquoted
        in YAML (read as a sexagesimal integer) is refused with a message naming
        the cause. Constructs `cls`.

        Raises:
            TypeError: `options` is not a mapping, or a field or option value has
                the wrong type.
            ValueError: `op` is missing, or a field or option value cannot be
                coerced.
        """
        if "op" not in data:
            raise ValueError("the message has no 'op' field")
        fields = {
            name: read(data[name]) for name, read in _HEADER.items() if name in data
        }
        return cls(
            coerce_enum_value(_enum.DHCPOpcode, data["op"]),
            options=DHCPOptions.from_mapping(data.get("options"), codemap=codemap),
            **fields,
        )
