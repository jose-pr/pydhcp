from __future__ import annotations
from collections.abc import Iterable
import enum as _enum
import functools as _functools
import inspect as _inspect
import ipaddress as _ipaddress
import typing as _ty
from ...exceptions import DHCPDecodeError, DHCPError, DHCPValueError

_DHCPOptionTypeT = _ty.TypeVar("_DHCPOptionTypeT", bound="DHCPOptionType")
_OptionCodecT = _ty.TypeVar("_OptionCodecT", bound="OptionCodec")


@_ty.runtime_checkable
class OptionCodec(_ty.Protocol):
    """What an option payload codec is: a value that reads and writes its octets.

    A codec is built from one value (`Codec(value)`), reads itself from the
    octets of an option (`unpack`, `unpack_from`), writes itself back (`pack`,
    `pack_into`) and renders itself for a structured document (`to_json`) and
    for the message display (`display_text`). `DHCPOptionType` is the base class
    that supplies everything but `unpack_from`, `pack_into` and the
    constructor; subclassing it is the way to get a codec the registry accepts.
    `isinstance(x, OptionCodec)` checks that the methods exist, not their
    signatures.
    """

    def __init__(self, value: _ty.Any, /) -> None: ...

    @classmethod
    def unpack(
        cls: type[_OptionCodecT], data: _ty.Union[memoryview, bytes, bytearray]
    ) -> _OptionCodecT:
        """The value held by all of `data`; `DHCPDecodeError` if it is not one."""
        ...

    @classmethod
    def unpack_from(
        cls: type[_OptionCodecT], option: memoryview
    ) -> tuple[_OptionCodecT, int]:
        """The value at the start of `option`, and how many octets it took."""
        ...

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        """The payload length every value has, or `None` when it varies."""
        ...

    def pack(self) -> bytes:
        """The octets of the payload."""
        ...

    def pack_into(self, buffer: bytearray) -> int:
        """Append the octets of the payload to `buffer`; how many were written."""
        ...

    def to_json(self) -> _ty.Any:
        """The value as plain data for a JSON, YAML, TOML or INI document."""
        ...

    def display_text(self) -> str:
        """The text the message display shows for the value."""
        ...


class DHCPOptionType:
    """The base class of the option payload codecs: the defaults of `OptionCodec`.

    A subclass implements `unpack_from` and `pack_into` (and its constructor),
    may set `fixed_size`, and may override `to_json` and `display_text`. `unpack`
    and `pack` are built on those: `unpack` refuses a payload of the wrong size
    or with octets left over, and `pack` collects what `pack_into` writes. The
    pair should round-trip the same Python value.
    """

    __slots__ = ()

    @classmethod
    def unpack_from(
        cls: type[_DHCPOptionTypeT], option: memoryview
    ) -> tuple[_DHCPOptionTypeT, int]:
        raise NotImplementedError()

    def pack_into(self, buffer: bytearray) -> int:
        raise NotImplementedError()

    def pack(self) -> bytes:
        encoded = bytearray()
        self.pack_into(encoded)
        return bytes(encoded)

    def to_json(self) -> _ty.Any:
        return self

    @classmethod
    def from_json(cls: type[_DHCPOptionTypeT], data: _ty.Any) -> _DHCPOptionTypeT:
        """The value `to_json` wrote: `cls(data)`, and an enum also by member name.

        A codec whose constructor does not take its own `to_json` form overrides
        this (`Bytes` reads hex text here, and only here).
        """
        if isinstance(data, str) and issubclass(cls, _enum.Enum):
            member = cls.__members__.get(data)
            if member is not None:
                return _ty.cast(_DHCPOptionTypeT, member)
        return cls(data)  # type: ignore[call-arg]

    def display_text(self) -> str:
        """The text the message display and the capture formats show for this value."""
        return repr(self)

    @classmethod
    def fixed_size(cls) -> _ty.Optional[int]:
        return None

    @classmethod
    def unpack(
        cls: type[_DHCPOptionTypeT], option: _ty.Union[memoryview, bytes, bytearray]
    ) -> _DHCPOptionTypeT:
        hint = cls.fixed_size()
        todecode = len(option)
        option = memoryview(option) if not isinstance(option, memoryview) else option
        # `is not None`, not truthiness: a hint of 0 is a real constraint (a
        # zero-length presence option such as RFC 4039 Rapid Commit must reject
        # any payload), and `if hint:` silently skipped it.
        if hint is not None:
            if todecode != hint:
                raise DHCPDecodeError(
                    f"{cls.__name__} payload must be exactly {hint} octets, got {todecode}"
                )
        try:
            decoded, read = cls.unpack_from(option)
        except DHCPValueError as exc:
            # A constructor refusing the octets it was built from.
            raise DHCPDecodeError(str(exc)) from exc
        if read != todecode:
            raise DHCPDecodeError(
                f"{cls.__name__} decoded only {read} of {todecode} octets; "
                "the payload carries trailing data the codec does not account for"
            )
        return decoded


def is_codec(value: _ty.Any) -> bool:
    """Whether `value` is an option codec: a `DHCPOptionType`, or anything shaped like one."""
    return isinstance(value, (DHCPOptionType, OptionCodec))


def is_codec_class(value: _ty.Any) -> bool:
    """Whether `value` is a codec class: a `DHCPOptionType` subclass, or shaped like one."""
    return isinstance(value, type) and (
        issubclass(value, DHCPOptionType) or issubclass(value, OptionCodec)
    )


def display_of(value: _ty.Any) -> str:
    """The display text of `value`, a codec value or one of the plain items inside one.

    A list codec reads as a bracketed list of its items' texts (its own `_item_text`
    for an item, where it has one); the message display prints one item per line.
    """
    if isinstance(value, list):
        return "[%s]" % ", ".join(map(getattr(value, "_item_text", display_of), value))
    if is_codec(value):
        return str(value.display_text())
    if isinstance(value, (_ipaddress.IPv4Address, _ipaddress.IPv4Network)):
        return str(value)
    return repr(value)


def option_text(value: _ty.Any) -> str:
    """The text the message display shows for a decoded option, one line per list item."""
    if isinstance(value, list):
        return "\n".join(map(getattr(value, "_item_text", display_of), value))
    return display_of(value)


_ItemT = _ty.TypeVar("_ItemT")


def hashable_payload(value: _ty.Any) -> _ty.Any:
    """A hashable stand-in for a payload value, for use inside `__hash__`.

    A record may hold a list codec (`List[IPv4AddressOption]`, `UserClass`, a
    label list), and a list does not hash. Every such codec is a flat sequence
    of hashable items, so the tuple of its items hashes consistently with the
    element-wise `==` beside it.
    """
    if isinstance(value, list):
        return tuple(hashable_payload(item) for item in value)
    return value


_set = object.__setattr__


def _text_argument(cls: type, text: _ty.Any) -> str:
    """`text` when it is text; `TypeError` otherwise, naming `cls`."""
    if not isinstance(text, str):
        raise TypeError(f"{cls.__name__}.parse takes text, not {type(text).__name__}")
    return text


class _TextForm:
    """A codec with a text form: `parse` reads what `str()` writes.

    A subclass defines `parse(text)`, which raises `DHCPValueError` for text that
    is not a value of the type and `TypeError` for an argument that is not text.
    """

    __slots__ = ()

    @classmethod
    def parse(cls, text: str) -> _ty.Any:
        raise NotImplementedError()

    @classmethod
    def try_parse(cls, text: str, default: _ty.Any = None) -> _ty.Any:
        """`parse`, or `default` for text that does not parse; `TypeError` for a non-text."""
        try:
            return cls.parse(text)
        except DHCPValueError:
            return default


def _field_repr(value: _ty.Any) -> str:
    if type(value).__module__ == "ipaddress":
        return repr(str(value))
    if isinstance(value, tuple):
        return repr(list(value))
    return repr(value)


@_functools.lru_cache(maxsize=None)
def _required_positionals(cls: type) -> int:
    """How many positional arguments `cls(...)` cannot do without."""
    return sum(
        1
        for parameter in _inspect.signature(cls).parameters.values()
        if parameter.default is _inspect.Parameter.empty
        and parameter.kind
        in (
            _inspect.Parameter.POSITIONAL_ONLY,
            _inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    )


class _Record(DHCPOptionType):
    """A read-only value made of named fields.

    A subclass lists its fields, in constructor order, as `__slots__` and as
    `_FIELDS`, and stores each with `_set(self, name, value)` in `__init__`.
    Equality, hash, `repr` and pickling follow from the fields: two records of
    one class are equal when their fields are, equal records hash equal, and
    `repr()` is the constructor call that builds the same record. A record
    never holds a list that can change (see `frozen`), so its hash cannot move.
    """

    __slots__ = ()
    _FIELDS: _ty.ClassVar[tuple[str, ...]] = ()

    def __setattr__(self, name: str, value: _ty.Any) -> _ty.NoReturn:
        raise AttributeError(f"{type(self).__name__} is read-only")

    def __delattr__(self, name: str) -> _ty.NoReturn:
        raise AttributeError(f"{type(self).__name__} is read-only")

    def _args(self) -> tuple[_ty.Any, ...]:
        """The constructor arguments that build an equal record."""
        return tuple(getattr(self, name) for name in self._FIELDS)

    @classmethod
    def from_json(cls: type[_DHCPOptionTypeT], data: _ty.Any) -> _DHCPOptionTypeT:
        """A record whose constructor takes several fields reads its `to_json`
        list as those fields; any other takes the document whole."""
        if isinstance(data, list) and _required_positionals(_ty.cast(_ty.Any, cls)) > 1:
            return cls(*data)
        return cls(data)  # type: ignore[call-arg]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _Record):
            return NotImplemented
        if not (isinstance(other, type(self)) or isinstance(self, type(other))):
            return NotImplemented
        return self._args() == other._args()

    def __hash__(self) -> int:
        return hash(tuple(hashable_payload(arg) for arg in self._args()))

    def __repr__(self) -> str:
        fields = ", ".join(
            f"{name}={_field_repr(value)}"
            for name, value in zip(self._FIELDS, self._args())
        )
        return f"{type(self).__name__}({fields})"

    def display_text(self) -> str:
        fields = ", ".join(
            f"{name}={display_of(value)}"
            for name, value in zip(self._FIELDS, self._args())
        )
        return f"{type(self).__name__}({fields})"

    def __reduce__(self) -> tuple[_ty.Any, ...]:
        return (type(self), self._args())

    def __copy__(self) -> _ty.Any:
        return self

    def __deepcopy__(self, memo: dict[int, _ty.Any]) -> _ty.Any:
        return self


class _NormalizedList(DHCPOptionType, list[_ItemT]):
    """A list that holds only normalised items, however it is changed.

    A subclass defines `_normalize(item)`, which returns the stored form of one
    item or raises. Every operation that adds an item calls it first, for the
    whole batch before anything changes, so a refused item leaves the list as it
    was. A value that is not a `ValueError` of the package is raised as
    `DHCPValueError`; a wrong type stays a `TypeError`.

    A list put in a record is `frozen`: it then refuses every change with a
    `TypeError`.
    """

    _locked = False

    @classmethod
    def _normalize(cls, item: _ty.Any) -> _ItemT:
        raise NotImplementedError()

    def _accepted(self, item: _ty.Any) -> _ItemT:
        try:
            return self._normalize(item)
        except (DHCPError, TypeError):
            raise
        except ValueError as exc:
            raise DHCPValueError(str(exc)) from exc

    def _modifiable(self) -> None:
        if self._locked:
            raise TypeError(f"this {type(self).__name__} is read-only")

    def append(self, item: _ty.Any) -> None:
        self._modifiable()
        list.append(self, self._accepted(item))

    def extend(self, __iterable: Iterable[_ty.Any]) -> None:
        self._modifiable()
        list.extend(self, [self._accepted(item) for item in __iterable])

    def insert(self, __index: _ty.SupportsIndex, __item: _ty.Any) -> None:
        self._modifiable()
        list.insert(self, __index, self._accepted(__item))

    def __iadd__(self, __iterable: Iterable[_ty.Any]) -> _ty.Any:  # type: ignore[misc]
        self.extend(__iterable)
        return self

    def __imul__(self, __count: _ty.SupportsIndex) -> _ty.Any:
        self._modifiable()
        return list.__imul__(self, __count)

    def __setitem__(self, __index: _ty.Any, __value: _ty.Any) -> None:
        self._modifiable()
        if isinstance(__index, slice):
            list.__setitem__(self, __index, [self._accepted(i) for i in __value])
        else:
            list.__setitem__(self, __index, self._accepted(__value))

    def __delitem__(self, __index: _ty.Any) -> None:
        self._modifiable()
        list.__delitem__(self, __index)

    def pop(self, __index: _ty.SupportsIndex = -1) -> _ItemT:
        self._modifiable()
        return list.pop(self, __index)

    def remove(self, __value: _ty.Any) -> None:
        self._modifiable()
        list.remove(self, __value)

    def clear(self) -> None:
        self._modifiable()
        list.clear(self)

    def reverse(self) -> None:
        self._modifiable()
        list.reverse(self)

    def sort(self, *, key: _ty.Any = None, reverse: bool = False) -> None:
        self._modifiable()
        list.sort(self, key=key, reverse=reverse)

    def _lock(self) -> None:
        self._locked = True

    def _locked_copy(self) -> _ty.Any:
        """A read-only copy; the items are already normalised."""
        copied = type(self).__new__(type(self))
        list.extend(copied, self)
        copied._locked = True
        return copied

    def __repr__(self) -> str:
        return f"{type(self).__name__}({list.__repr__(self)})"

    def __reduce__(self) -> tuple[_ty.Any, ...]:
        if self._locked:
            return (type(self), (list(self),), {"_locked": True})
        return (type(self), (list(self),))


def frozen(value: _ty.Any) -> _ty.Any:
    """`value` as a record may hold it: a list codec read-only, anything else as is.

    A list codec the caller still holds is copied, so changing it afterwards
    does not reach the record; one already read-only is shared.
    """
    if isinstance(value, _NormalizedList):
        return value if value._locked else value._locked_copy()
    return value
