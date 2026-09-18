"""Uncompressed RFC 1035 domain names, shared by every option that carries one.

Options 81 (RFC 4702 §3.1), 120 (RFC 3361 §3.1), 122 (RFC 3495) and 139/140
(RFC 5678) all carry names that MUST NOT use compression: there is no enclosing
message for a pointer to resolve against. Each of those codecs used to carry its
own copy of this pair, and the copies had drifted -- only one rejected a
compression pointer, only one enforced the 255-octet name limit -- so the same
malformed input was accepted, rejected or silently misread depending on which
option it arrived in.

This module deliberately imports nothing from the package. `options.type` and
`options.ccc` import each other and work only by statement order, so a shared
helper that pulled in either would be one more thing depending on that ordering.
"""

from __future__ import annotations

#: RFC 1035 §2.3.4: 63 octets per label, 255 per name.
MAX_LABEL_OCTETS = 63
MAX_NAME_OCTETS = 255

#: The top two bits of a length octet mark a compression pointer (RFC 1035 §4.1.4).
_POINTER_MASK = 0xC0


def encode_domain_name(
    name: str,
    what: str = "domain name",
    allow_root: bool = False,
) -> bytes:
    """Encode `name` as length-prefixed labels terminated by a root label.

    `allow_root` permits the empty name, which encodes as a bare root label --
    RFC 4702 lets a client send option 81 with no name at all. It is off by
    default because for most options an empty name is a caller mistake, and
    these codecs rejected it before this helper existed.
    """
    labels = (
        [label for label in name.rstrip(".").split(".") if label != ""] if name else []
    )
    if not labels and not allow_root:
        raise ValueError(f"{what} must not be empty")
    if name and any(label == "" for label in name.rstrip(".").split(".")):
        raise ValueError(f"{what} must not contain empty labels")

    data = bytearray()
    for label in labels:
        encoded = label.encode("utf-8")
        if len(encoded) > MAX_LABEL_OCTETS:
            raise ValueError(
                f"{what} label exceeds {MAX_LABEL_OCTETS} octets: {label!r}"
            )
        data.append(len(encoded))
        data.extend(encoded)
    data.append(0)
    if len(data) > MAX_NAME_OCTETS:
        raise ValueError(f"{what} exceeds {MAX_NAME_OCTETS} octets")
    return bytes(data)


def decode_domain_name(
    option: memoryview,
    start: int = 0,
    what: str = "domain name",
) -> tuple[str, int]:
    """Decode one name starting at `start`, returning it and the octets read.

    A compression pointer is a decode error rather than a length: read as one,
    0xC0 means "the next 192 octets are a label", which either runs off the end
    of a short option or silently produces a wrong name from a longer one.
    """
    labels: list[str] = []
    idx = start
    size = len(option)
    while True:
        if idx >= size:
            raise ValueError(f"{what} is truncated")
        length = option[idx]
        idx += 1
        if length == 0:
            return ".".join(labels), idx - start
        if length & _POINTER_MASK:
            raise ValueError(
                f"{what} must not use compression pointers (found {length:#04x})"
            )
        if idx + length > size:
            raise ValueError(f"{what} is truncated")
        labels.append(option[idx : idx + length].tobytes().decode("utf-8"))
        idx += length
