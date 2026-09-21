from __future__ import annotations

import typing as _ty
import builtins as _builtins
from .base import BaseDhcpOptionCode as BaseDhcpOptionCode, DhcpOption as DhcpOption
from .type import DhcpOptionType as DhcpOptionType
from .type import *  # noqa: F403
from .code import DhcpOptionCode as DhcpOptionCode
from .. import constants as _const
from ..log import LOGGER
from math import inf as _inf

T = _ty.TypeVar("T", bound=DhcpOptionType)
C = _ty.TypeVar("C", bound=BaseDhcpOptionCode)
_R = _ty.TypeVar("_R")

#: The codes an option may be stored under. 0 (PAD) and 255 (END) are framing
#: markers rather than options -- see `_check_code`.
MIN_OPTION_CODE = 1
MAX_OPTION_CODE = 254


def _check_code(key: _ty.Any) -> int:
    """Return `key` as a storable option code, or raise.

    Stores used to accept anything: `options[0]` and `options[255]` encoded as
    real `00 02 ..` / `ff 02 ..` TLVs, which a receiver reads as padding and as
    end-of-options -- the first silently discards the payload, the second makes
    every option after it disappear. `options[300]` was accepted too and only
    failed at `encode()`, with `byte must be in range(0, 256)` naming neither
    the option nor the code. `decode()` deliberately does not come through
    here: receive stays liberal, and it already handles 0 and 255 as framing.
    """
    if isinstance(key, bool) or not isinstance(key, int):
        # `_builtins.type`: importing `.type` binds the submodule as this
        # module's global `type`, shadowing the builtin.
        raise TypeError(
            f"option code must be an int, not {_builtins.type(key).__name__}"
        )
    code = int(key)
    if code == 0:
        raise ValueError("option code 0 is PAD, a padding marker, not an option")
    if code == 255:
        raise ValueError(
            "option code 255 is END, the end-of-options marker, not an option"
        )
    if not MIN_OPTION_CODE <= code <= MAX_OPTION_CODE:
        raise ValueError(
            f"option code must be in range "
            f"{MIN_OPTION_CODE}-{MAX_OPTION_CODE}, got {code}"
        )
    return code


class DhcpOptions(_ty.MutableMapping[int, bytearray]):
    """The option bag: a mutable mapping of option code to **raw** payload.

    Two members deliberately do not mean what `MutableMapping` says they mean,
    and both `type: ignore[override]`s below mark exactly that:

    * **`get()` decodes; `[]` does not.** `options[53]` is
      `bytearray(b'\\x05')`, `options.get(53)` is `DhcpMessageType.DHCPACK`.
      Everything the ABC supplies -- `values()`, `pop()`, `setdefault()`,
      `popitem()`, `update()`, and `dict(options)` -- routes through
      `__getitem__`, so all of it yields raw `bytearray`s like `[]`, not
      decoded values like `get()`. Reach for `get(code, decode=False)` when you
      want the bytes and you want to say so.
    * **`items()` returns a `list`, not a view.** The decoded form has to build
      `DhcpOption` pairs, so there is nothing to keep a live view of; only
      `items(decoded=False)` is the ABC's `ItemsView`.

    This asymmetry is the API, not drift: `get(..., decode=...)` is the
    documented surface every caller uses, and making it return raw bytes to
    satisfy the ABC would trade a real API for a formal one. It is pinned by
    `tests/test_options.py::test_get_decodes_and_getitem_does_not`, which fails
    if anyone "fixes" it the other way.
    """

    def __init__(self, codemap: _ty.Optional[type[BaseDhcpOptionCode]] = None) -> None:
        if codemap is None:
            codemap = DhcpOptionCode
        self._codemap = codemap
        if codemap is DhcpOptionCode:
            DhcpOptionCode.ensure_registered()
        self._options: _ty.OrderedDict[int, bytearray] = _ty.OrderedDict()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({list(self._options.keys())})"

    def decode(self, options: memoryview, base_offset: int = 0) -> memoryview:
        offset = base_offset
        while options:
            code = options[0]
            if code == 0:
                options = options[1:]
                offset += 1
                continue

            if code == 255:
                break

            if len(options) < 2:
                LOGGER.warning(
                    f"Option {code} at offset {offset} is truncated (cannot read length)"
                )
                options = options[len(options) :]
                break

            length = options[1]
            remaining = len(options) - 2
            if length > remaining:
                LOGGER.warning(
                    f"Option {code} at offset {offset} claims {length} bytes but only {remaining} available"
                )
                data = options[2:]
                self._options.setdefault(code, bytearray()).extend(data)
                options = options[len(options) :]
                continue

            next_idx = 2 + length
            data = options[2:next_idx]
            options = options[next_idx:]
            offset += next_idx
            self._options.setdefault(code, bytearray()).extend(data)
        return options

    def partial_encode(
        self, maxsize: _ty.Optional[float], word_size: int = 1
    ) -> tuple[bytearray, _ty.Optional["DhcpOptions"]]:
        if maxsize is None:
            maxsize = _inf

        if word_size <= 0:
            raise ValueError(
                f"Invalid options word size {word_size}: must be a positive number of octets"
            )

        endbytes = b"\xff" + b"\x00" * (word_size - 1)

        if maxsize < max(word_size * 2, 4):
            raise ValueError(
                f"Invalid options max size {maxsize}: needs at least "
                f"{max(word_size * 2, 4)} octets for a word size of {word_size}"
            )

        tofill = maxsize - word_size
        options = bytearray()
        _extraoptions: _ty.OrderedDict[int, bytearray] = _ty.OrderedDict()

        for code, option in self._options.items():
            opt_view = memoryview(option)
            written = False

            # Every fragment is a complete code/length/data instance. RFC 3396 s4
            # requires a long option to be split into multiple instances of the *same
            # code*, each with its own length octet -- writing the code once leaves the
            # receiver reading continuation data as new options. A zero-length option
            # (e.g. RAPID_COMMIT, RFC 4039) still gets its length octet, or the next
            # option's code byte is read as this option's length and everything after
            # it is swallowed. Both octets are charged against `tofill`.
            while tofill >= 3:
                take = int(min(255, tofill - 2))
                chunk = opt_view[:take]
                _len = len(chunk)
                options.append(int(code))
                options.append(_len)
                options.extend(chunk)
                tofill -= 2 + _len
                opt_view = opt_view[_len:]
                written = True
                if not opt_view:
                    break

            if opt_view or not written:
                _extraoptions[code] = bytearray(opt_view)

        options.extend(endbytes)
        if _extraoptions:
            leftover = DhcpOptions(self._codemap)
            leftover._options = _extraoptions
        else:
            leftover = None
        return options, leftover

    def encode(self, word_size: int = 1) -> bytearray:
        encoded, _ = self.partial_encode(None, word_size)
        return encoded

    def copy(self) -> "DhcpOptions":
        """Return an independent copy sharing no mutable state with `self`.

        The codemap is preserved and every payload is copied into a fresh
        `bytearray`, so mutating either container (or a payload handed out by
        `get(..., decode=False)`) cannot write through to the other.
        """
        copied = DhcpOptions(self._codemap)
        copied._options = _ty.OrderedDict(
            (code, bytearray(value)) for code, value in self._options.items()
        )
        return copied

    def __getitem__(self, _key: int) -> bytearray:
        return self._options[_key]

    # Deliberate ABC deviation -- see the class docstring. `Mapping.get` is
    # declared to return the mapping's value type (`bytearray`); this one
    # decodes by default and returns a `DhcpOptionType`.
    @_ty.overload  # type: ignore[override]
    def get(
        self, __key: int, default: _ty.Any = None, *, decode: type[T]
    ) -> T | None: ...

    @_ty.overload
    def get(
        self,
        __key: int,
        default: _ty.Any = None,
        *,
        decode: _ty.Callable[[bytearray], _R],
    ) -> _R | None: ...

    @_ty.overload
    def get(
        self, __key: int, default: _ty.Any = None, *, decode: _ty.Literal[True]
    ) -> DhcpOptionType | None: ...

    @_ty.overload
    def get(
        self, __key: int, default: _ty.Any = None, *, decode: _ty.Literal[False]
    ) -> bytearray | None: ...

    @_ty.overload
    def get(self, __key: int, default: _ty.Any = None) -> DhcpOptionType | None: ...

    def get(
        self,
        __key: int,
        default: _ty.Any = None,
        decode: _ty.Union[
            bool, type[DhcpOptionType], _ty.Callable[[bytearray], _ty.Any]
        ] = True,
    ) -> _ty.Any:
        value = self._options.get(__key, _const.MISSING)
        if value is _const.MISSING:
            return default
        assert isinstance(value, bytearray)
        if decode:
            target_decoder: _ty.Union[
                type[DhcpOptionType], _ty.Callable[[bytearray], _ty.Any]
            ]
            if decode is True:
                target_decoder = self._codemap.from_code(__key).get_type()
            else:
                target_decoder = decode

            if isinstance(target_decoder, _builtins.type) and issubclass(
                target_decoder, DhcpOptionType
            ):
                return target_decoder._dhcp_decode(value)
            return _ty.cast(_ty.Callable[[bytearray], _ty.Any], target_decoder)(value)
        else:
            return value

    def _ensuretype(
        self, option: _ty.Union[DhcpOption, tuple[int, _ty.Any]]
    ) -> DhcpOption:
        if isinstance(option, DhcpOption):
            return option
        return self._codemap.normalize(*option)

    def append(self, option: _ty.Union[DhcpOption, tuple[int, _ty.Any]]) -> None:
        opt = self._ensuretype(option)
        code = _check_code(int(opt.code))
        opt.value._dhcp_write(self._options.setdefault(code, bytearray()))

    def replace(self, option: _ty.Union[DhcpOption, tuple[int, _ty.Any]]) -> None:
        opt = self._ensuretype(option)
        self[int(opt.code)] = opt.value

    def __setitem__(self, __key: int, __value: _ty.Any) -> None:
        """Store an option, building the payload before it is visible.

        Two properties the obvious implementation does not have:

        * **Atomic.** The old code did `setdefault(key, bytearray()).clear()`
          and then `_dhcp_write` into that same buffer, so a codec that raised
          part-way left the option *emptied* -- or, for a key that was not
          there before, newly present and empty. A zero-length option is legal
          on the wire (RFC 4039's RAPID_COMMIT is one), so the wreckage encodes
          and sends cleanly: the failed set becomes a valid option meaning
          something else. Building into a scratch buffer and assigning only on
          success leaves the previous value untouched instead.
        * **Non-aliasing.** A `bytearray` argument used to be stored by
          reference, so the caller kept a live handle on the stored option and
          later mutations of their own buffer silently rewrote it. Every other
          accepted type was already copied, which made the exception invisible
          until a `bytearray` happened to be reused. `DhcpOptions.copy()` exists
          because that same aliasing bit the server's lease path.

        Assigning an existing key keeps its position: `OrderedDict` only
        reorders on insert, and the options order is wire-visible (`encode`
        puts DHCP_MESSAGE_TYPE first).

        The key is checked first -- see `_check_code`. PAD (0) and END (255)
        are framing, not options, and a code outside 0-255 has no wire form at
        all; all three used to be stored and only noticed, if ever, by the
        receiver.
        """
        key = _check_code(__key)
        if not isinstance(__value, (bytes, memoryview, bytearray, DhcpOptionType)):
            __value = self._codemap.from_code(key).get_type()(__value)  # type: ignore[call-arg]
        data = bytearray()
        if isinstance(__value, DhcpOptionType):
            __value._dhcp_write(data)
        else:
            data.extend(__value)
        self._options[key] = data

    def __delitem__(self, __key: int) -> None:
        return self._options.__delitem__(__key)

    def __len__(self) -> int:
        return len(self._options)

    def __iter__(self) -> _ty.Iterator[int]:
        return self._options.__iter__()

    # Deliberate ABC deviation -- see the class docstring. The decoded forms
    # return a `list[DhcpOption]`, not an `ItemsView`: decoding builds new pairs,
    # so there is no live view to hand back, and the old `ItemsView` annotation
    # promised `.mapping` and set operations that the list has never had. Only
    # `decoded=False` is the mapping's own view.
    @_ty.overload  # type: ignore[override]
    def items(self) -> list[DhcpOption]: ...

    @_ty.overload
    def items(self, decoded: _ty.Literal[False]) -> _ty.ItemsView[int, bytearray]: ...

    @_ty.overload
    def items(self, decoded: _ty.Literal[True]) -> list[DhcpOption]: ...

    @_ty.overload
    def items(self, decoded: type[C]) -> list[DhcpOption]: ...

    def items(
        self, decoded: _ty.Union[bool, type[BaseDhcpOptionCode]] = True
    ) -> _ty.Union[list[DhcpOption], _ty.ItemsView[int, bytearray]]:
        raw = self._options.items()
        if not decoded:
            return raw
        codemap = self._codemap if decoded is True else decoded
        return [codemap.decode(code, value) for code, value in raw]

    def __contains__(self, __key: object) -> bool:
        return self._options.__contains__(__key)
