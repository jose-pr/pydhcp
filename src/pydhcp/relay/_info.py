"""Option 82 as the relay writes it: what it adds, and how a datagram shows it overloaded.

Pure functions over octets; the relay's rules that decide *when* to add the
option are in `_core`.
"""

from __future__ import annotations

import typing as _ty

from ..options import _codecs as _type

#: Offset of the options field: the fixed header (236 octets) and the magic cookie.
_OPTIONS_OFFSET = 240

_OVERLOAD = 52
_PAD = 0
_END = 255


def relay_info(
    circuit_id: _ty.Optional[bytes], remote_id: _ty.Optional[bytes]
) -> _type.RelayAgentInformation:
    """Option 82 carrying the circuit identifier (sub-option 1) and the remote
    identifier (sub-option 2) that were given (RFC 3046 s3.1, s3.2)."""
    suboptions: list[tuple[int, bytes]] = []
    if circuit_id is not None:
        suboptions.append((1, circuit_id))
    if remote_id is not None:
        suboptions.append((2, remote_id))
    return _type.RelayAgentInformation(suboptions)


def uses_overload(data: bytes) -> bool:
    """Whether the options field of an encoded message carries option 52.

    Read from the octets, because a decoded message has already folded what the
    overload moved back into its options.
    """
    index = _OPTIONS_OFFSET
    size = len(data)
    while index < size:
        code = data[index]
        if code == _END:
            return False
        if code == _PAD:
            index += 1
            continue
        if code == _OVERLOAD:
            return True
        if index + 1 >= size:
            return False
        index += 2 + data[index + 1]
    return False
