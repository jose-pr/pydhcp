"""A snapshot of an option bag that cannot be changed."""

from __future__ import annotations

import typing as _ty

from . import DHCPOptions

__all__ = ["FrozenDHCPOptions"]


class FrozenDHCPOptions(DHCPOptions):
    """A copy of an option bag taken once and never changed.

    Reads work as on `DHCPOptions`, and a payload is `bytes`, so nothing handed
    out can write back. Every way of changing the bag raises `TypeError`;
    `copy()` returns an ordinary mutable `DHCPOptions`. It compares equal to
    another bag holding the same payloads and hashes from them.
    """

    def __init__(self, source: DHCPOptions) -> None:
        # What `DHCPOptions.__init__` sets, with payloads as `bytes`: nothing
        # handed out can write back.
        self._codemap = source._codemap
        payloads: _ty.Any = _ty.OrderedDict(
            [(code, bytes(value)) for code, value in source._options.items()]
        )
        self._options = payloads

    def _read_only(self) -> _ty.NoReturn:
        raise TypeError("these options are read-only; copy() them to change them")

    def __setitem__(self, __key: int, __value: _ty.Any) -> None:
        self._read_only()

    def __delitem__(self, __key: int) -> None:
        self._read_only()

    def append(self, option: _ty.Any) -> None:
        self._read_only()

    def retain(self, codes: _ty.Iterable[int]) -> None:
        self._read_only()

    def _decode_into(self, options: memoryview, base_offset: int = 0) -> memoryview:
        self._read_only()

    @classmethod
    def decode(
        cls,
        data: _ty.Union[bytes, bytearray, memoryview],
        *,
        codemap: _ty.Any = None,
    ) -> _ty.Any:
        return cls(DHCPOptions.decode(data, codemap=codemap))

    def __hash__(self) -> int:  # type: ignore[override]
        return hash(frozenset((code, bytes(v)) for code, v in self._options.items()))

    def __repr__(self) -> str:
        return f"DHCPOptions({list(self._options)})"
