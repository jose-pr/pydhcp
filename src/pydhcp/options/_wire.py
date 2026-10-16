"""Options as TLVs: what the bag's `decode` reads and `partial_encode` writes."""

from __future__ import annotations

import logging as _logging
import math as _math
import typing as _ty

from .. import _leniency

LOGGER = _logging.getLogger(__name__)

#: The codes an option may be stored under. 0 (PAD) and 255 (END) are framing
#: markers rather than options -- see `check_code`.
MIN_OPTION_CODE = 1
MAX_OPTION_CODE = 254


def check_code(key: _ty.Any) -> int:
    """Return `key` as a storable option code, or raise.

    Code 0 stored as an option would be read back as padding and code 255 as the
    end of the options, so a store refuses both and anything outside 1 to 254.
    `decode_into` does not come through here: receive is liberal and treats 0
    and 255 as the framing they are.
    """
    if isinstance(key, bool) or not isinstance(key, int):
        raise TypeError(f"option code must be an int, not {type(key).__name__}")
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


def decode_into(
    store: _ty.MutableMapping[int, bytearray],
    options: memoryview,
    base_offset: int = 0,
) -> memoryview:
    """Add the TLVs in `options` to `store`; the unconsumed tail comes back.

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
                store.setdefault(code, bytearray()).extend(data)
            options = options[len(options) :]
            continue

        next_idx = 2 + length
        data = options[2:next_idx]
        options = options[next_idx:]
        offset += next_idx
        store.setdefault(code, bytearray()).extend(data)
    return options


def partial_encode(
    options: _ty.Mapping[int, _ty.Union[bytes, bytearray]],
    maxsize: _ty.Optional[float],
    word_size: int = 1,
) -> tuple[bytearray, _ty.OrderedDict[int, bytearray]]:
    """Write `options` in order into at most `maxsize` octets, END included.

    Returns the field and what did not fit, by code: the unwritten tail of an
    option that was split, or an option that did not start at all.
    """
    if maxsize is None:
        maxsize = _math.inf

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
    field = bytearray()
    extra: _ty.OrderedDict[int, bytearray] = _ty.OrderedDict()

    for code, option in options.items():
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
            field.append(int(code))
            field.append(_len)
            field.extend(chunk)
            tofill -= 2 + _len
            opt_view = opt_view[_len:]
            written = True
            if not opt_view:
                break

        if opt_view or not written:
            extra[code] = bytearray(opt_view)

    field.extend(endbytes)
    return field, extra


def option_octets(length: int) -> int:
    """The octets an option of `length` payload octets takes whole: its instances.

    Each instance carries at most 255 octets and its own code and length
    octets (RFC 3396 section 6); an empty option is one instance.
    """
    return length + 2 * max(1, -(-length // 255))


def write_items(
    field: bytearray,
    items: _ty.Iterable[tuple[int, _ty.Union[bytes, bytearray]]],
) -> None:
    """Append each `(code, payload)` whole to `field`, END not included."""
    for code, payload in items:
        length = len(payload)
        if length <= 255:
            field.append(code)
            field.append(length)
            field.extend(payload)
            continue
        view = memoryview(payload)
        for start in range(0, length, 255):
            chunk = view[start : start + 255]
            field.append(code)
            field.append(len(chunk))
            field.extend(chunk)
