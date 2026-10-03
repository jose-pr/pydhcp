"""A DHCP message as a plain mapping, and back -- the structured formats' basis."""

from __future__ import annotations

import datetime as _dt
import enum as _enum_base
import typing as _ty

from . import enums as _enum
from .. import network as _net, nvt as _nvt
from ..options import BaseDhcpOptionCode, DhcpOptions, type as _type
from ._encode import _MessageEncode


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
        # integer (measured: 8041827055), so hand-authored YAML lost the MAC
        # before `from_mapping` ever saw it. The generic "must be text or
        # bytes-like" named the symptom and not the cause.
        raise TypeError(
            f"chaddr arrived as the integer {value}, which is how YAML reads an "
            "unquoted colon-separated MAC address -- quote it "
            "(chaddr: '10:20:30:40:50:55')"
        )
    if not isinstance(value, str):
        raise TypeError("chaddr must be text or bytes-like")
    return bytes.fromhex(_strip_hex_text(value))


def _coerce_bootp_text(value: _ty.Any, field: str) -> str:
    """Coerce a mapping's `sname`/`file` to text without inventing content.

    A bare `sname:` / `file:` key in YAML (and a JSON `null`) loads as `None`,
    and the previous `str(data[field])` turned that into the literal four
    characters `None` -- a silently corrupt packet rather than an error or an
    empty field. An absent field means "empty", which is what the wire encodes
    as an all-NUL BOOTP field.
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _nvt.decode(bytes(value))
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text or null, not {type(value).__name__}")
    return value


def _coerce_option_value(
    option_type: type[_type.DhcpOptionType],
    value: _ty.Any,
) -> _ty.Any:
    if isinstance(value, str) and issubclass(option_type, _enum_base.Enum):
        return _coerce_enum_value(option_type, value)
    return value


def _coerce_option_code(raw_code: _ty.Any, codemap: type[BaseDhcpOptionCode]) -> int:
    if isinstance(raw_code, int):
        return raw_code
    if isinstance(raw_code, str):
        if raw_code.isdigit():
            return int(raw_code)
        try:
            return int(codemap[raw_code])  # type: ignore[index]
        except Exception:
            pass
    return int(raw_code)


#: The class `from_mapping` is called on, which it constructs: typed as that
#: class (`DhcpMessage` for `DhcpMessage.from_mapping`).
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
                decoded = option_type._dhcp_decode(value)
                option_value = _enum_name(
                    decoded.__json__()
                    if isinstance(decoded, _type.DhcpOptionType)
                    else decoded
                )
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
            "flags": self.flags.name,
            "ciaddr": str(self.ciaddr),
            "yiaddr": str(self.yiaddr),
            "siaddr": str(self.siaddr),
            "giaddr": str(self.giaddr),
            "chaddr": self.chaddr.hex(":").upper(),
            # Display form: a mapping is written out as JSON/YAML/TOML/INI, and
            # a preserved octet cannot be encoded by a strict serializer.
            "sname": _nvt.display(self.sname),
            "file": _nvt.display(self.file),
            "options": options,
        }

    def _survives_round_trip(
        self, code: int, option_value: _ty.Any, original: _ty.Any
    ) -> bool:
        """Whether loading `option_value` back yields the original octets.

        Goes through a `DhcpOptions` keyed by the *real* code and the same
        codemap, because that is the path `from_mapping` takes. Probing under a
        different code silently measures a different codec -- code 0 is `PAD`,
        which is unregistered and falls back to `Bytes`, so everything looked
        lossy and every option came out as hex.
        """
        try:
            option_type = self.options._codemap.from_code(code).get_type()
            probe = DhcpOptions(codemap=self.options._codemap)
            probe[code] = _coerce_option_value(option_type, option_value)
            return bytes(probe.get(code, decode=False) or b"") == bytes(original)
        except Exception:
            return False

    @classmethod
    def from_mapping(cls: "type[_Mapped]", data: _ty.Mapping[str, _ty.Any]) -> _Mapped:
        """Build a message from a mapping in the shape `to_mapping` produces.

        Accepts option keys by name or number and the ``{HEX_VALUE_KEY: ...}`` raw
        form, so `to_mapping` -> `from_mapping` round-trips exactly. A MAC written
        unquoted in YAML (read as a sexagesimal integer) is refused with a message
        naming the cause, and a missing `sname`/`file` is empty, never the text
        "None". Constructs `cls`.

        Raises:
            TypeError: `options` is not a mapping, or a field has the wrong type.
            ValueError: a field or option value cannot be coerced.
        """
        options = DhcpOptions()
        raw_options = data.get("options", {})
        if not isinstance(raw_options, _ty.Mapping):
            raise TypeError("options must be a mapping")

        for raw_code, raw_value in raw_options.items():
            code = _coerce_option_code(raw_code, options._codemap)
            if isinstance(raw_value, _ty.Mapping) and set(raw_value) == {
                cls.HEX_VALUE_KEY
            }:
                options[code] = bytearray.fromhex(
                    _strip_hex_text(str(raw_value[cls.HEX_VALUE_KEY]))
                )
                continue
            try:
                code_obj = options._codemap.from_code(code)
                option_type = code_obj.get_type()
                value = _coerce_option_value(option_type, raw_value)
                options[code] = value
            except Exception:
                if isinstance(raw_value, str):
                    raw_bytes = bytearray.fromhex(_strip_hex_text(raw_value))
                elif isinstance(raw_value, (bytes, bytearray, memoryview)):
                    raw_bytes = bytearray(raw_value)
                else:
                    raise TypeError(
                        f"Unsupported value for unknown option {raw_code!r}"
                    ) from None
                options[code] = raw_bytes

        return cls(
            op=_coerce_enum_value(_enum.OpCode, data["op"]),
            htype=_coerce_enum_value(_enum.HardwareAddressType, data["htype"]),
            hlen=_coerce_int(data["hlen"]),
            hops=_coerce_int(data["hops"]),
            xid=_coerce_int(data["xid"]),
            secs=_dt.timedelta(seconds=_coerce_int(data["secs"])),
            flags=_coerce_enum_value(_enum.Flags, data["flags"]),
            ciaddr=_net.IPv4(data["ciaddr"]),
            yiaddr=_net.IPv4(data["yiaddr"]),
            siaddr=_net.IPv4(data["siaddr"]),
            giaddr=_net.IPv4(data["giaddr"]),
            chaddr=_coerce_chaddr(data["chaddr"]),
            sname=_coerce_bootp_text(data["sname"], "sname"),
            file=_coerce_bootp_text(data["file"], "file"),
            options=options,
        )
