from __future__ import annotations

import typing as _ty


class Missing:
    """Type of the `MISSING` sentinel below."""


#: Sentinel for "argument not supplied", where `None` is itself a meaningful
#: value -- `DHCPOptions.get(code, default=None)` has to tell "no default given"
#: from "default is None". It lived in `constants.py`, which holds *protocol*
#: constants (packet sizes, port numbers, the infinite-lease sentinel); this is
#: a Python idiom, not a DHCP one.
MISSING: _ty.Final = Missing()
