"""What `capture` and `replay` share: the DHCP plugin, and the variables of pktcap's fields.

Imports `pktcap.cli`, so only the two commands that need the `pktcap` extra reach it.
"""

from __future__ import annotations

import typing as _ty

import pktcap.cli as _cli
from duho import Meta

#: The fields of a pktcap command that get no `PYDHCP_<COMMAND>_<FIELD>` variable: the
#: settings file and the logging options, whose variables are the root's or none, and
#: `listen` and `per_interface`, which `_Listening` names. `load` names `PKTCAP_LOAD` itself.
_UNNAMED = frozenset(
    {
        "config",
        "config_format",
        "listen",
        "per_interface",
        "verbose",
        "quiet",
        "loglevel",
        "loglevels",
    }
)


def _has_variable(hint: _ty.Any) -> bool:
    """Whether an `Annotated` hint already names an environment variable."""
    return any(
        isinstance(item, Meta) and isinstance(getattr(item, "env", None), str)
        for item in getattr(hint, "__metadata__", ())
    )


class _DHCPPackets(_cli.Loading):
    """The options of a command that reads DHCP from pktcap's frames.

    `pydhcp.capture` is always loaded as a plugin, so the DHCP layer and its filter keys
    are there. A subclass gets `PYDHCP_<COMMAND>_<FIELD>` for every field it inherits that
    names no variable already (`_UNNAMED` excepted), keeping the settings keys and variables
    of the command as the field names give them.
    """

    _plugins_ = ("pydhcp.capture",)

    def __init_subclass__(cls, **kwargs: _ty.Any) -> None:
        super().__init_subclass__(**kwargs)
        if "_parsername_" not in cls.__dict__:
            return
        command = str(cls._parsername_).upper()
        own = dict(cls.__dict__.get("__annotations__", {}))
        for name, hint in _ty.get_type_hints(cls, include_extras=True).items():
            if name.startswith("_") or name in _UNNAMED or name in own:
                continue
            if _ty.get_origin(hint) is _ty.ClassVar or _has_variable(hint):
                continue
            own[name] = _ty.Annotated[
                hint, Meta(env=f"PYDHCP_{command}_{name.upper()}")
            ]
        cls.__annotations__ = own
