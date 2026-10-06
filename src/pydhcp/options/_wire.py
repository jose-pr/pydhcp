"""Writing options as TLVs: what the bag's `partial_encode` does."""

from __future__ import annotations

import math as _math
import typing as _ty


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
