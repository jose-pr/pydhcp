from __future__ import annotations

import json as _json
import typing as _ty

from .._extras import pktcap_module
from ..exceptions import DHCPDecodeError

__all__ = ["dumps", "loads"]

#: The record formats pktcap writes and reads; JSON is the standard library's.
_PKTCAP_FORMATS = ("yaml", "toml", "ini")


def _normalize_format(format: str) -> str:
    normalized = format.lower().strip()
    if normalized not in {"json", *_PKTCAP_FORMATS}:
        raise ValueError(f"Unsupported structured format: {format}")
    return normalized


def _ensure_mapping(data: _ty.Any) -> dict[str, _ty.Any]:
    if not isinstance(data, dict):
        raise DHCPDecodeError("Structured packet data must be a mapping")
    return data


def _plain(value: _ty.Any) -> _ty.Any:
    """`value` as plain data: a list or string subclass (a codec's list, a text option)
    is the builtin it stands for, which is what a record format accepts."""
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        return str.__getitem__(value, slice(None))
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return float(value)
    return value


def _is_table(value: _ty.Any) -> bool:
    """Whether TOML writes `value` as a table, after the plain values of its own table."""
    if isinstance(value, dict):
        return True
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, dict) for item in value)
    )


def _refuse_a_reordering(data: dict[str, _ty.Any]) -> None:
    """`ValueError` when TOML would write the options of `data` in another order.

    A table follows the plain values of its parent in TOML, so an option held as a table
    (octets in the `hex` form, a record) that comes before a plain one is read back after
    it, and the message would encode its options in another order.
    """
    options = data.get("options")
    if not isinstance(options, dict):
        return
    after_a_table = False
    for key, value in options.items():
        if _is_table(value):
            after_a_table = True
        elif after_a_table:
            raise ValueError(
                f"TOML would write option {key} before an option held as octets or "
                "a record, and the message would encode its options in another order: "
                "write it as JSON, YAML or INI"
            )


def _from_the_old_ini(data: dict[str, _ty.Any]) -> dict[str, _ty.Any]:
    """A message written as INI with a `[message]` and an `[options]` section is one mapping."""
    if set(data) == {"message", "options"} and all(
        isinstance(item, dict) for item in data.values()
    ):
        return {**data["message"], "options": data["options"]}
    return data


def loads(text: str, format: str) -> dict[str, _ty.Any]:
    """The mapping a structured document holds, with `json.loads`'s meaning.

    `text` is the content, never a file name. `format` is `json`, `yaml`, `toml` or
    `ini` in any letter case (`ValueError` otherwise). JSON is read by the standard
    library; the others by `pktcap.loads_record`, so they need the `pktcap` extra
    (`ImportError` naming `pip install "pydhcp[pktcap]"`), and `yaml` and `toml` the
    format library of pktcap (`ImportError` naming `pip install "pktcap[yaml]"` or
    `"pktcap[toml]"`). A document pktcap does not take as one record is a `ValueError`
    (`pktcap.RecordFormatError`) that never quotes the text. An INI document is the
    sections `[record]` and `[options]` that `dumps` writes, or the `[message]` and
    `[options]` a message was written with before. A document that is not a mapping is
    a `DHCPDecodeError`.
    """
    normalized = _normalize_format(format)
    if normalized == "json":
        return _ensure_mapping(_json.loads(text))
    pktcap = pktcap_module("a message or a lease as YAML, TOML or INI text")
    data = _ensure_mapping(pktcap.loads_record(text, normalized))
    return _from_the_old_ini(data) if normalized == "ini" else data


def dumps(data: dict[str, _ty.Any], format: str) -> str:
    """The text of a mapping in a structured format, with `json.dumps`'s meaning.

    `format` is `json`, `yaml`, `toml` or `ini` in any letter case (`ValueError`
    otherwise). JSON is written by the standard library, indented; the others by
    `pktcap.dumps_record`, so they need the `pktcap` extra (`ImportError` naming
    `pip install "pydhcp[pktcap]"`) and `yaml` and `toml` the format library of pktcap
    (`ImportError` naming `pip install "pktcap[yaml]"` or `"pktcap[toml]"`). A value
    the format cannot hold is a `TypeError` or `ValueError` from pktcap that does not
    quote the record, and so is a message whose options TOML would write in another
    order (an option held as a table before a plain one). The INI form is `[record]`
    with the header fields and one section for `options`, each value one line of JSON,
    and keeps the case of every name.
    """
    normalized = _normalize_format(format)
    if normalized == "json":
        return _json.dumps(data, indent=2) + "\n"
    pktcap = pktcap_module("a message or a lease as YAML, TOML or INI text")
    if normalized == "toml":
        _refuse_a_reordering(data)
    return _ty.cast(str, pktcap.dumps_record(_plain(data), normalized))
