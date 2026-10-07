"""A DHCP message as a plain mapping, and back -- the structured formats' basis."""

from __future__ import annotations

import ipaddress as _ipaddress
import datetime as _dt
import enum as _enum_base
import typing as _ty

from . import _enums as _enum
from .. import _nvt as _nvt
from ..options._codes import OptionCode
from ..options import DHCPOptions
from ..options import _codecs as _type
from ._encode import _MessageEncode
from ._fields import _MessageFields
from . import structured as _structured


def _strip_hex_text(value: str) -> str:
    return "".join(ch for ch in value if ch not in " \t\r\n:")


def _enum_name(value: _ty.Any) -> _ty.Any:
    """Name an enum value for structured output, or fall back to its number.

    `.name` is None for a value with no member -- an OPTION_OVERLOAD of 4, say,
    or any flag combination the enum does not spell. Emitting that put a null
    where a string belongs and the document would not load back.
    """
    if isinstance(value, _enum_base.Enum):
        return value.name if value.name is not None else _enum_value_of(value)
    return value


def _enum_value_of(value: _ty.Any) -> _ty.Any:
    inner = getattr(value, "value", value)
    return int(inner) if isinstance(inner, int) else inner


def _coerce_enum_value(enum_type: type[_ty.Any], value: _ty.Any) -> _ty.Any:
    if isinstance(value, str):
        try:
            return enum_type[value]
        except KeyError:
            pass
    return enum_type(value)


def _coerce_int(value: _ty.Any) -> int:
    return int(value)


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
    return bytes.fromhex(_strip_hex_text(value))


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
                _strip_hex_text(str(value[_MessageFields.HEX_VALUE_KEY]))
            )
        except ValueError as exc:
            raise ValueError(f"{field} is not hex octets: {exc}") from exc
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _nvt.decode(bytes(value))
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text or null, not {type(value).__name__}")
    return value


def _header(data: _ty.Mapping[str, _ty.Any], key: str) -> _ty.Any:
    """The header field `key`, or a `ValueError` that names it."""
    try:
        return data[key]
    except KeyError:
        raise ValueError(f"the message has no {key!r} field") from None


def _coerce_option_value(
    option_type: type[_type.OptionCodec],
    value: _ty.Any,
) -> _ty.Any:
    if isinstance(value, str) and issubclass(option_type, _enum_base.Enum):
        return _coerce_enum_value(option_type, value)
    if isinstance(value, str) and issubclass(option_type, _type.Bytes):
        # A document writes octets as hex text; `Bytes` itself is built from bytes.
        return option_type.parse(value)
    return value


def _option_type(codemap: type[OptionCode], code: int) -> type[_type.OptionCodec]:
    """The codec `codemap` binds `code` to; opaque bytes for a code it cannot name."""
    try:
        return codemap.from_code(code).get_type()
    except (ValueError, KeyError):
        return _type.Bytes


def _coerce_option_code(raw_code: _ty.Any, codemap: type[OptionCode]) -> int:
    if isinstance(raw_code, int):
        return raw_code
    if isinstance(raw_code, str):
        if raw_code.isdigit():
            return int(raw_code)
        try:
            return int(codemap[raw_code])  # type: ignore[index]
        except (KeyError, TypeError):
            raise ValueError(
                f"unknown option {raw_code!r}: it is neither a name in "
                f"{codemap.__name__} nor a number"
            ) from None
    return int(raw_code)


#: The class `from_mapping` is called on, which it constructs: typed as that
#: class (`DHCPMessage` for `DHCPMessage.from_mapping`).
_Mapped = _ty.TypeVar("_Mapped", bound="_MessageMapping")


class _MessageMapping(_MessageEncode):
    """`to_mapping` / `from_mapping`, byte-exact."""

    def to_mapping(self) -> dict[str, _ty.Any]:
        """The message as a plain dict: header fields, then `options`.

        The basis of the JSON/YAML/TOML/INI helpers, and byte-exact: an option whose
        readable form would not reproduce its octets -- non-UTF-8 text, a payload
        its codec normalises, a length the codec does not keep -- is written as
        ``{HEX_VALUE_KEY: "..."}`` instead. Option keys are the code's name, or its
        number as a string when it has none. Integers are plain `int`.
        """
        options: dict[str, _ty.Any] = {}
        for code, value in self.options._options.items():
            try:
                code_obj = self.options._codemap.from_code(code)
                # The numeric code when there is no name. `label()` answers
                # "UNKNOWN" for every unnamed code, so two of them collided on
                # one key and the document then failed to load on int("UNKNOWN").
                key = (
                    code_obj.label()
                    if getattr(code_obj, "_name_", None) is not None
                    else str(int(code))
                )
                option_type = code_obj.get_type()
                decoded = option_type.unpack(value)
                option_value = _enum_name(decoded.to_json())
                if not self._survives_round_trip(code, option_value, value):
                    # The readable form would come back as different octets --
                    # text holding a byte that is not valid UTF-8, a payload the
                    # codec normalizes, a length the codec does not preserve.
                    # Better an opaque value that reloads exactly than a pretty
                    # one that silently does not.
                    option_value = {self.HEX_VALUE_KEY: bytes(value).hex()}
            except Exception:
                # Also the self-describing form, not a bare hex string: a bare
                # one is ambiguous for a numeric option. A 2-octet
                # IP_ADDRESS_LEASE_TIME was emitted as "1234" and read back as
                # the decimal 1234, so the reloaded packet carried 000004d2 --
                # different octets, no error.
                key = str(code)
                option_value = {self.HEX_VALUE_KEY: bytes(value).hex()}
            options[key] = option_value

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
            "options": options,
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
        return cls.decode(bytes.fromhex(_strip_hex_text(text)))

    def _survives_round_trip(
        self, code: int, option_value: _ty.Any, original: _ty.Any
    ) -> bool:
        """Whether loading `option_value` back yields the original octets.

        Goes through a `DHCPOptions` keyed by the *real* code and the same
        codemap, because that is the path `from_mapping` takes. Probing under a
        different code silently measures a different codec -- code 0 is `PAD`,
        which is unregistered and falls back to `Bytes`, so everything looked
        lossy and every option came out as hex.
        """
        try:
            option_type = self.options._codemap.from_code(code).get_type()
            probe = DHCPOptions(codemap=self.options._codemap)
            probe[code] = _coerce_option_value(option_type, option_value)
            return bytes(probe.get(code, decode=False) or b"") == bytes(original)
        except Exception:
            return False

    @classmethod
    def from_mapping(
        cls: "type[_Mapped]",
        data: _ty.Mapping[str, _ty.Any],
        *,
        codemap: _ty.Optional[type[OptionCode]] = None,
    ) -> _Mapped:
        """Build a message from a mapping in the shape `to_mapping` produces.

        Accepts option keys by name or number, so `to_mapping` -> `from_mapping`
        round-trips exactly when `codemap` is the one the options were named with
        (the default is `DHCPOptionCode`). An option's value is what its codec
        accepts, and a codec that refuses it is an error naming the option and the
        kind of value. Octets are read only in the explicit ``{HEX_VALUE_KEY: ...}``
        form, which any option takes, and as hex text for an option whose codec is
        opaque bytes. `sname` and `file` take text, null (empty), `bytes` or the
        hex form. A MAC written unquoted in YAML (read as a sexagesimal integer) is
        refused with a message naming the cause. Constructs `cls`.

        Raises:
            TypeError: `options` is not a mapping, or a field or option value has
                the wrong type.
            ValueError: a header field is missing, or a field or option value
                cannot be coerced.
        """
        options = DHCPOptions(codemap)
        raw_options = data.get("options", {})
        if not isinstance(raw_options, _ty.Mapping):
            raise TypeError("options must be a mapping")

        for raw_code, raw_value in raw_options.items():
            code = _coerce_option_code(raw_code, options._codemap)
            with options._naming(code, raw_value):
                if isinstance(raw_value, _ty.Mapping) and set(raw_value) == {
                    cls.HEX_VALUE_KEY
                }:
                    value: _ty.Any = bytearray.fromhex(
                        _strip_hex_text(str(raw_value[cls.HEX_VALUE_KEY]))
                    )
                else:
                    value = _coerce_option_value(
                        _option_type(options._codemap, code), raw_value
                    )
            options[code] = value

        return cls(
            op=_coerce_enum_value(_enum.DHCPOpcode, _header(data, "op")),
            htype=_coerce_enum_value(_enum.HardwareAddressType, _header(data, "htype")),
            hlen=_coerce_int(_header(data, "hlen")),
            hops=_coerce_int(_header(data, "hops")),
            xid=_coerce_int(_header(data, "xid")),
            secs=_dt.timedelta(seconds=_coerce_int(_header(data, "secs"))),
            flags=_coerce_enum_value(_enum.DHCPFlags, _header(data, "flags")),
            ciaddr=_ipaddress.IPv4Address(_header(data, "ciaddr")),
            yiaddr=_ipaddress.IPv4Address(_header(data, "yiaddr")),
            siaddr=_ipaddress.IPv4Address(_header(data, "siaddr")),
            giaddr=_ipaddress.IPv4Address(_header(data, "giaddr")),
            chaddr=_coerce_chaddr(_header(data, "chaddr")),
            sname=_coerce_bootp_text(_header(data, "sname"), "sname"),
            file=_coerce_bootp_text(_header(data, "file"), "file"),
            options=options,
        )
