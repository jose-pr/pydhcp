from __future__ import annotations

import contextlib as _contextlib
import logging as _logging
import typing as _ty
import builtins as _builtins
from ._codes import (
    BaseDHCPOptionCode as BaseDHCPOptionCode,
    DHCPOption as DHCPOption,
    OptionCode as OptionCode,
)
from ._codecs import DHCPOptionType as DHCPOptionType, OptionCodec as OptionCodec
from ._codecs._base import is_codec, is_codec_class
from ._codecs import *  # noqa: F403
from ._codes import DHCPOptionCode as DHCPOptionCode
from .. import _constants as _const, _leniency
from . import _wire
from .._missing import MISSING as _MISSING

LOGGER = _logging.getLogger(__name__)

_T = _ty.TypeVar("_T", bound=DHCPOptionType)
_C = _ty.TypeVar("_C", bound=OptionCode)
_R = _ty.TypeVar("_R")
_OptionsT = _ty.TypeVar("_OptionsT", bound="DHCPOptions")

#: The codes an option may be stored under. 0 (PAD) and 255 (END) are framing
#: markers rather than options -- see `_check_code`.
MIN_OPTION_CODE = 1
MAX_OPTION_CODE = 254

__all__ = [
    "BaseDHCPOptionCode",
    "BaseFixedLengthInteger",
    "Boolean",
    "Bytes",
    "CCCAPBackoffRetry",
    "CCCAPBackoffRetrySubOption",
    "CCCASBackoffRetry",
    "CCCASBackoffRetrySubOption",
    "CCCKDCServerAddressList",
    "CCCKDCServerAddressSubOption",
    "CCCKerberosRealmName",
    "CCCKerberosRealmNameSubOption",
    "CCCOption",
    "CCCPrimaryDHCPServerAddress",
    "CCCPrimaryDHCPServerAddressSubOption",
    "CCCProvisioningServerAddress",
    "CCCProvisioningServerAddressSubOption",
    "CCCProvisioningServerFQDN",
    "CCCProvisioningTimer",
    "CCCProvisioningTimerSubOption",
    "CCCSecondaryDHCPServerAddress",
    "CCCSecondaryDHCPServerAddressSubOption",
    "CCCSecurityTicketControl",
    "CCCSecurityTicketControlSubOption",
    "CCCSubOption",
    "CCCTicketGrantingServerUtilization",
    "CCCTicketGrantingServerUtilizationSubOption",
    "ClasslessRoute",
    "ClientFQDN",
    "ClientIdentifier",
    "DHCPOption",
    "DHCPOptionCode",
    "DHCPOptionCodes",
    "DHCPOptionType",
    "DHCPOptions",
    "DomainList",
    "DomainName",
    "EncapsulatedOptions",
    "FixedLengthInteger",
    "Flag",
    "I32",
    "IPv4AddressOption",
    "List",
    "MAX_OPTION_CODE",
    "MIN_OPTION_CODE",
    "MoSFQDNList",
    "MoSFQDNRecord",
    "MoSIPv4AddressList",
    "MoSIPv4AddressRecord",
    "OctetString",
    "OptionCode",
    "OptionCodec",
    "OptionOverload",
    "PCPServerList",
    "PolicyFilter",
    "RDNSSSelection",
    "RecordList",
    "RelayAgentInformation",
    "SIPServers",
    "StaticRoute",
    "StatusCode",
    "String",
    "TLVOption",
    "U16",
    "U32",
    "U8",
    "URIList",
    "UncompressedDomainList",
    "UserClass",
    "VIVendorClass",
    "VIVendorClassRecord",
    "VIVendorSpecificInformation",
    "VIVendorSpecificInformationRecord",
    "VendorSpecificInformation",
]


def _check_code(key: _ty.Any) -> int:
    """Return `key` as a storable option code, or raise.

    Code 0 stored as an option would be read back as padding and code 255 as the
    end of the options, so a store refuses both and anything outside 1 to 254.
    `decode()` does not come through here: receive is liberal and treats 0 and
    255 as the framing they are.
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


class DHCPOptions(_ty.MutableMapping[int, bytearray]):
    """The option bag: a mutable mapping of option code to **raw** payload.

    Two members deliberately do not mean what `MutableMapping` says they mean,
    and both `type: ignore[override]`s below mark exactly that:

    * **`get()` decodes; `[]` does not.** `options[53]` is
      `bytearray(b'\\x05')`, `options.get(53)` is `DHCPMessageType.DHCPACK`.
      Everything the ABC supplies -- `values()`, `pop()`, `setdefault()`,
      `popitem()`, `update()`, and `dict(options)` -- routes through
      `__getitem__`, so all of it yields raw `bytearray`s like `[]`, not
      decoded values like `get()`. Reach for `get(code, decode=False)` when you
      want the bytes and you want to say so.
    * **`items()` returns a `list`, not a view.** The decoded form has to build
      `DHCPOption` pairs, so there is nothing to keep a live view of; only
      `items(decoded=False)` is the ABC's `ItemsView`.

    This asymmetry is the API, not drift: `get(..., decode=...)` is the
    documented surface every caller uses, and making it return raw bytes to
    satisfy the ABC would trade a real API for a formal one. It is pinned by
    `tests/test_options.py::test_get_decodes_and_getitem_does_not`, which fails
    if anyone "fixes" it the other way.

    **Equality is on the raw payloads.** Two bags are equal when they hold the
    same codes with the same octets, in any order (a mapping has none to keep),
    whatever their code maps; nothing is decoded, so comparing never raises on
    a malformed payload and octets that read alike are still different. A bag
    is unequal to anything that is not a `DHCPOptions`, a `dict` of its own
    items included.
    """

    def __init__(
        self, codemap: _ty.Optional[_builtins.type[OptionCode]] = None
    ) -> None:
        if codemap is None:
            codemap = DHCPOptionCode
        self._codemap = codemap
        self._options: _ty.OrderedDict[int, bytearray] = _ty.OrderedDict()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({list(self._options.keys())})"

    @classmethod
    def decode(
        cls: "_builtins.type[_OptionsT]",
        data: _ty.Union[bytes, bytearray, memoryview],
        *,
        codemap: _ty.Optional[_builtins.type[OptionCode]] = None,
    ) -> _OptionsT:
        """Parse a TLV options buffer into a new bag.

        Liberal on receive: PAD octets are skipped, parsing stops at END, and a
        truncated option keeps what arrived (logged at DEBUG and counted by a listener). Octets after END
        are ignored. A repeated code is joined (RFC 3396).
        """
        options = cls(codemap)
        options._decode_into(memoryview(data))
        return options

    def _decode_into(self, options: memoryview, base_offset: int = 0) -> memoryview:
        """Add the options in `options` to this bag; the unconsumed tail comes back.

        `base_offset` is where the buffer starts in the message, for log lines.
        """
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
                _leniency.note()
                LOGGER.debug(
                    "Option %d at offset %d is truncated (cannot read length)",
                    code,
                    offset,
                )
                options = options[len(options) :]
                break

            length = options[1]
            remaining = len(options) - 2
            if length > remaining:
                # Keep what arrived only if there is something to keep: an
                # option that declares a length and supplies nothing would read
                # as present and then fail in whatever handler decodes it.
                _leniency.note()
                LOGGER.debug(
                    "Option %d at offset %d claims %d bytes but only %d available",
                    code,
                    offset,
                    length,
                    remaining,
                )
                data = options[2:]
                if data:
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
    ) -> tuple[bytearray, _ty.Optional["DHCPOptions"]]:
        """Encode up to `maxsize` octets, returning the bytes and the leftovers.

        An option that does not fit whole is split into instances of its code
        (RFC 3396), and what is not written comes back as a bag of its own.
        `word_size` pads the END marker out to a multiple of that many octets,
        so the options field finishes on a word boundary: at 4, END is
        `ff 00 00 00` rather than a bare `ff`. It also reserves that much room
        rather than one octet when deciding what still fits. DHCP itself needs
        no alignment; the padding is for a caller filling a word-aligned buffer.
        """
        written, extra = _wire.partial_encode(self._options, maxsize, word_size)
        if not extra:
            return written, None
        leftover = DHCPOptions(self._codemap)
        leftover._options = extra
        return written, leftover

    def encode(self, word_size: int = 1) -> bytearray:
        encoded, _ = self.partial_encode(None, word_size)
        return encoded

    def copy(self) -> "DHCPOptions":
        """Return an independent copy sharing no mutable state with `self`.

        The codemap is preserved and every payload is copied into a fresh
        `bytearray`, so mutating either container (or a payload handed out by
        `get(..., decode=False)`) cannot write through to the other.
        """
        copied = DHCPOptions(self._codemap)
        copied._options = _ty.OrderedDict(
            (code, bytearray(value)) for code, value in self._options.items()
        )
        return copied

    def retain(self, codes: _ty.Iterable[int]) -> None:
        """Keep only the options whose code is in `codes`; the order of the rest is kept."""
        keep = {int(code) for code in codes}
        for code in [code for code in self._options if code not in keep]:
            del self[code]

    def __getitem__(self, _key: int) -> bytearray:
        return self._options[_key]

    # Deliberate ABC deviation -- see the class docstring. `Mapping.get` is
    # declared to return the mapping's value type (`bytearray`); this one
    # decodes by default and returns a `DHCPOptionType`.
    @_ty.overload  # type: ignore[override]
    def get(
        self, __key: int, default: _ty.Any = None, *, decode: _builtins.type[_T]
    ) -> _ty.Optional[_T]: ...

    @_ty.overload
    def get(
        self,
        __key: int,
        default: _ty.Any = None,
        *,
        decode: _ty.Callable[[bytearray], _R],
    ) -> _ty.Optional[_R]: ...

    @_ty.overload
    def get(
        self, __key: int, default: _ty.Any = None, *, decode: _ty.Literal[True]
    ) -> _ty.Optional[DHCPOptionType]: ...

    @_ty.overload
    def get(
        self, __key: int, default: _ty.Any = None, *, decode: _ty.Literal[False]
    ) -> _ty.Optional[bytearray]: ...

    @_ty.overload
    def get(
        self, __key: int, default: _ty.Any = None
    ) -> _ty.Optional[DHCPOptionType]: ...

    def get(
        self,
        __key: int,
        default: _ty.Any = None,
        decode: _ty.Union[
            bool, _builtins.type[DHCPOptionType], _ty.Callable[[bytearray], _ty.Any]
        ] = True,
    ) -> _ty.Any:
        value = self._options.get(__key, _MISSING)
        if value is _MISSING:
            return default
        assert isinstance(value, (bytes, bytearray))
        if decode:
            target_decoder: _ty.Union[
                _builtins.type[DHCPOptionType], _ty.Callable[[bytearray], _ty.Any]
            ]
            if decode is True:
                target_decoder = self._codemap.from_code(__key).get_type()
            else:
                target_decoder = decode

            if isinstance(target_decoder, _builtins.type) and is_codec_class(
                target_decoder
            ):
                return _ty.cast(_builtins.type[OptionCodec], target_decoder).unpack(
                    value
                )
            return _ty.cast(_ty.Callable[[bytearray], _ty.Any], target_decoder)(value)
        else:
            return value

    def _ensuretype(
        self, option: _ty.Union[DHCPOption, tuple[int, _ty.Any]]
    ) -> DHCPOption:
        if isinstance(option, DHCPOption):
            return option
        return self._codemap.normalize(*option)

    def _describe(self, code: int) -> str:
        """`option 12 (HOSTNAME)`, or `option 230` for a code with no name."""
        try:
            label = self._codemap.from_code(code).label()
        except Exception:
            label = "UNKNOWN"
        return f"option {code}" if label == "UNKNOWN" else f"option {code} ({label})"

    @_contextlib.contextmanager
    def _naming(self, code: int, value: _ty.Any) -> _ty.Iterator[None]:
        """Say which option and which kind of value a refusal was about.

        The exception keeps its class, so a caller's `except` still catches it.
        """
        try:
            yield
        except (TypeError, ValueError) as exc:
            message = (
                f"{self._describe(code)} cannot hold a "
                f"{_builtins.type(value).__name__}: {exc}"
            )
            try:
                renamed = _builtins.type(exc)(message)
            except Exception:
                raise exc from None
            raise renamed from exc

    def append(self, option: _ty.Union[DHCPOption, tuple[int, _ty.Any]]) -> None:
        """Add `option`'s octets after those already stored under its code.

        All or nothing: the payload is built first, so an option that is
        refused leaves the bag as it was, a code that was absent still absent.
        """
        raw_code, value = option
        code = _check_code(int(raw_code))
        with self._naming(code, value):
            payload = bytearray()
            self._ensuretype(option).value.pack_into(payload)
        self._options.setdefault(code, bytearray()).extend(payload)

    def replace(self, option: _ty.Union[DHCPOption, tuple[int, _ty.Any]]) -> None:
        opt = self._ensuretype(option)
        self[int(opt.code)] = opt.value

    def __setitem__(self, __key: int, __value: _ty.Any) -> None:
        """Store an option, building the payload before it is visible.

        * **Atomic.** The payload is built in a scratch buffer and stored only
          on success, so a codec that raises part-way leaves the previous value,
          or no key. A zero-length option is legal on the wire (RFC 4039's
          RAPID_COMMIT), so a half-built one would encode and send cleanly as
          an option meaning something else.
        * **Non-aliasing.** A `bytearray` argument is copied, never kept: the
          caller's later writes to their buffer do not reach the stored option.

        Assigning an existing key keeps its position; the options order is
        wire-visible. The key is checked first (`_check_code`).
        """
        key = _check_code(__key)
        with self._naming(key, __value):
            if not isinstance(__value, (bytes, memoryview, bytearray)) and not is_codec(
                __value
            ):
                __value = self._codemap.from_code(key).get_type()(__value)
            data = bytearray()
            if is_codec(__value):
                __value.pack_into(data)
            else:
                data.extend(__value)
        self._options[key] = data

    def setdefault(self, key: int, default: _ty.Any = None) -> bytearray:
        """The raw payload under `key`; `default` is stored first when absent."""
        if key not in self._options:
            self[key] = default
        return self._options[key]

    def __delitem__(self, __key: int) -> None:
        return self._options.__delitem__(__key)

    def __len__(self) -> int:
        return len(self._options)

    def __iter__(self) -> _ty.Iterator[int]:
        return self._options.__iter__()

    # Deliberate ABC deviation -- see the class docstring. The decoded forms
    # return a `list[DHCPOption]`, not an `ItemsView`: decoding builds new pairs,
    # so there is no live view to hand back, and the old `ItemsView` annotation
    # promised `.mapping` and set operations that the list has never had. Only
    # `decoded=False` is the mapping's own view.
    @_ty.overload  # type: ignore[override]
    def items(self) -> list[DHCPOption]: ...

    @_ty.overload
    def items(self, decoded: _ty.Literal[False]) -> _ty.ItemsView[int, bytearray]: ...

    @_ty.overload
    def items(self, decoded: _ty.Literal[True]) -> list[DHCPOption]: ...

    @_ty.overload
    def items(self, decoded: _builtins.type[_C]) -> list[DHCPOption]: ...

    def items(
        self, decoded: _ty.Union[bool, _builtins.type[OptionCode]] = True
    ) -> _ty.Union[list[DHCPOption], _ty.ItemsView[int, bytearray]]:
        raw = self._options.items()
        if not decoded:
            return raw
        codemap = self._codemap if decoded is True else decoded
        return [codemap.decode(code, value) for code, value in raw]

    def __contains__(self, __key: object) -> bool:
        return self._options.__contains__(__key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DHCPOptions):
            return NotImplemented
        mine, theirs = self._options, other._options
        return len(mine) == len(theirs) and all(
            code in theirs and theirs[code] == payload for code, payload in mine.items()
        )

    __hash__ = None  # type: ignore[assignment]
