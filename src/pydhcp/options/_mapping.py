"""An option bag as a plain mapping, and back: the `options` of a message's or a
lease's document."""

from __future__ import annotations

import enum as _enum
import typing as _ty

from . import DHCPOptions
from . import _codecs
from ._codes import OptionCode

#: The key of the self-describing octets form, `{"hex": "0a000001"}`.
HEX_VALUE_KEY = "hex"


def strip_hex_text(value: str) -> str:
    return "".join(ch for ch in value if ch not in " \t\r\n:")


def _enum_name(value: _ty.Any) -> _ty.Any:
    """Name an enum value for structured output, or fall back to its number.

    `.name` is None for a value with no member -- an OPTION_OVERLOAD of 4, say,
    or any flag combination the enum does not spell. Emitting that put a null
    where a string belongs and the document would not load back.
    """
    if isinstance(value, _enum.Enum):
        if value.name is not None:
            return value.name
        inner = getattr(value, "value", value)
        return int(inner) if isinstance(inner, int) else inner
    return value


def coerce_enum_value(enum_type: type[_ty.Any], value: _ty.Any) -> _ty.Any:
    if isinstance(value, str):
        try:
            return enum_type[value]
        except KeyError:
            pass
    return enum_type(value)


def _coerce_option_value(
    option_type: type[_codecs.OptionCodec], value: _ty.Any
) -> _ty.Any:
    """`value` as the codec reads its `to_json` form; octets are stored as they are."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return value
    from_json = getattr(option_type, "from_json", None)
    if from_json is not None:
        return from_json(value)
    # A codec that only satisfies `OptionCodec` has no `from_json`.
    if isinstance(value, str) and issubclass(option_type, _enum.Enum):
        return coerce_enum_value(option_type, value)
    return value


def _option_type(codemap: type[OptionCode], code: int) -> type[_codecs.OptionCodec]:
    """The codec `codemap` binds `code` to; opaque bytes for a code it cannot name."""
    try:
        return codemap.from_code(code).get_type()
    except (ValueError, KeyError):
        return _codecs.Bytes


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


def _survives_round_trip(
    codemap: type[OptionCode], code: int, option_value: _ty.Any, original: _ty.Any
) -> bool:
    """Whether loading `option_value` back yields the original octets.

    Goes through a bag keyed by the *real* code and the same codemap, because
    that is the path `from_mapping` takes. Probing under a different code
    measures a different codec -- code 0 is `PAD`, which is unregistered and
    falls back to `Bytes`, so everything would look lossy.
    """
    try:
        probe = DHCPOptions(codemap=codemap)
        probe[code] = _coerce_option_value(_option_type(codemap, code), option_value)
        return bytes(probe.get(code, decode=False) or b"") == bytes(original)
    except Exception:
        return False


def to_mapping(options: DHCPOptions) -> dict[str, _ty.Any]:
    """`options` as plain data; see `DHCPOptions.to_mapping`."""
    codemap = options._codemap
    mapping: dict[str, _ty.Any] = {}
    for code, value in options.items(decoded=False):
        try:
            code_obj = codemap.from_code(code)
            # The numeric code when there is no name. `label()` answers
            # "UNKNOWN" for every unnamed code, so two of them would collide on
            # one key and the document then fail to load on int("UNKNOWN").
            key = (
                code_obj.label()
                if getattr(code_obj, "_name_", None) is not None
                else str(int(code))
            )
            option_value = _enum_name(code_obj.get_type().unpack(value).to_json())
            if not _survives_round_trip(codemap, code, option_value, value):
                # Text holding a byte that is not UTF-8, a payload the codec
                # normalizes, a length the codec does not keep: an opaque
                # value that reloads exactly beats a readable one that does not.
                option_value = {HEX_VALUE_KEY: bytes(value).hex()}
        except Exception:
            # Also the self-describing form, never a bare hex string: a bare
            # one is ambiguous for a numeric option ("1234" reads as decimal).
            key = str(code)
            option_value = {HEX_VALUE_KEY: bytes(value).hex()}
        mapping[key] = option_value
    return mapping


def fill_from_mapping(options: DHCPOptions, data: _ty.Any) -> None:
    """Store what `data` holds in `options`; see `DHCPOptions.from_mapping`."""
    if data is None:
        return
    if not isinstance(data, _ty.Mapping):
        raise TypeError("options must be a mapping")
    codemap = options._codemap
    for raw_code, raw_value in data.items():
        code = _coerce_option_code(raw_code, codemap)
        with options._naming(code, raw_value):
            if isinstance(raw_value, _ty.Mapping) and set(raw_value) == {HEX_VALUE_KEY}:
                value: _ty.Any = bytearray.fromhex(
                    strip_hex_text(str(raw_value[HEX_VALUE_KEY]))
                )
            else:
                value = _coerce_option_value(_option_type(codemap, code), raw_value)
        options[code] = value
