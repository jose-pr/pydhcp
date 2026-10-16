"""What `DHCPOptions.update` and `copy` merge, and the all-or-nothing merge itself."""

from __future__ import annotations

import typing as _ty

from . import _names

if _ty.TYPE_CHECKING:
    from . import DHCPOptions


class _Keyed(_ty.Protocol):
    """What `dict.update` reads as a mapping: `keys()` and `[]`."""

    def keys(self) -> _ty.Iterable[_ty.Any]: ...

    def __getitem__(self, __key: _ty.Any) -> _ty.Any: ...


#: What `update()` and `copy()` merge: a mapping of code to value, or pairs.
OptionSource = _ty.Union[_Keyed, _ty.Iterable[_ty.Tuple[int, _ty.Any]]]


def merge(
    bag: "DHCPOptions",
    options: _ty.Tuple[OptionSource, ...],
    overrides: _ty.Mapping[str, _ty.Any],
) -> None:
    """Store `options`, then `overrides`, in `bag`, all of them or none."""
    staged = _scratch(bag)
    for source in options:
        pairs: _ty.Iterable[tuple[int, _ty.Any]]
        if hasattr(source, "keys"):
            mapping = _ty.cast(_Keyed, source)
            pairs = ((code, mapping[code]) for code in mapping.keys())
        else:
            pairs = source
        for code, value in pairs:
            staged[code] = value
    for name, value in overrides.items():
        staged[_code_named(bag, name)] = value
    bag._options.update(staged._options)


def _scratch(bag: "DHCPOptions") -> "DHCPOptions":
    """A plain bag holding `bag`'s payloads, to merge into before anything is kept."""
    from . import DHCPOptions

    staged = DHCPOptions(bag._codemap)
    # Payloads are shared, never written: a store replaces the bytearray.
    staged._options = _ty.OrderedDict(bag._options)
    return staged


def _code_named(bag: "DHCPOptions", name: str) -> int:
    """The code a keyword names in `bag`'s codemap (`_names.resolve_code`).

    `TypeError`, as for any keyword a call does not take, when it names none.
    """
    try:
        return _names.resolve_code(bag._codemap, name)
    except ValueError as exc:
        raise TypeError(str(exc)) from None
