"""DHCP as a pktcap plugin: the layer's filter keys, and the hook that registers them.

Nothing registers on import: the hook is handed the registry and changes only that one.
Every key converts its value with the function this package's own capture filter uses,
so the two filters cannot read a value differently.
"""

from __future__ import annotations

import typing as _ty

import pktcap as _pktcap

from ..options._codecs._message_type import DHCPMessageType
from ..options._codes import DHCPOptionCode
from ..packet._enums import DHCPOpcode
from ..packet._message import DHCPMessage
from ._dissector import DHCPLayer, register_dhcp_dissector
from ._filter import (
    _NO_TYPE,
    _UNNAMED_TYPE_RE,
    chaddr_matcher,
    client_id_matcher,
    msg_type_matcher,
    op_matcher,
    option_selector,
    option_value_text,
    xid_matcher,
)

LayerTest = _ty.Callable[[DHCPLayer], bool]

_OPTION_PREFIX = "option."


def _unrecognized(field: str, text: str) -> ValueError:
    return ValueError(f"the DHCP layer's {field} {text!r} names no number")


def _opcode(layer: DHCPLayer) -> int:
    """The opcode number of `layer.op`, which is the member's name."""
    member = DHCPOpcode.__members__.get(layer.op)
    if member is None:
        raise _unrecognized("op", layer.op)
    return int(member)


def _message_type(layer: DHCPLayer) -> _ty.Optional[int]:
    """Option 53's number from `layer.message_type`: a name, `TYPE_<n>`, or `UNKNOWN` for none."""
    text = layer.message_type
    if text == _NO_TYPE:
        return None
    member = DHCPMessageType.__members__.get(text)
    if member is not None:
        return int(member)
    unnamed = _UNNAMED_TYPE_RE.fullmatch(text)
    if unnamed:
        return int(unnamed.group(1))
    raise _unrecognized("message_type", text)


def _option_key(code: _ty.Union[int, DHCPOptionCode]) -> str:
    """The key `DHCPMessage.to_mapping` gives an option: its name, else its number."""
    number = int(code)
    try:
        member = DHCPOptionCode.from_code(number)
    except (ValueError, KeyError):
        return str(number)
    return member.label() if getattr(member, "_name_", None) else str(number)


def _option_text(
    options: _ty.Mapping[str, _ty.Any], code: _ty.Union[int, DHCPOptionCode]
) -> _ty.Optional[str]:
    """The text the library's filter compares for option `code`, read from a message mapping."""
    value = options.get(_option_key(code))
    if isinstance(value, dict):
        # The octets of a value whose readable form would not round-trip: decode them
        # as the message would have.
        try:
            octets = bytes.fromhex(value[DHCPMessage.HEX_VALUE_KEY])
            value = DHCPOptionCode.from_code(int(code)).get_type().unpack(octets)
        except Exception:
            return None
        return option_value_text(value)
    return None if value is None else str(value)


def _values(clause: "_pktcap.FilterClause") -> _ty.Tuple[str, ...]:
    if not clause.values:
        raise ValueError(f"Capture filter {clause.key}= expects a value")
    return clause.values


def _op(clause: "_pktcap.FilterClause") -> LayerTest:
    matches = op_matcher(clause.key, _values(clause))
    return lambda layer: matches(_opcode(layer))


def _msg_type(clause: "_pktcap.FilterClause") -> LayerTest:
    matches = msg_type_matcher(clause.key, _values(clause))
    return lambda layer: matches(_message_type(layer))


def _xid(clause: "_pktcap.FilterClause") -> LayerTest:
    matches = xid_matcher(clause.key, _values(clause))
    return lambda layer: matches(layer.xid)


def _client_id(clause: "_pktcap.FilterClause") -> LayerTest:
    matches = client_id_matcher(clause.key, _values(clause))
    return lambda layer: matches(layer.client_id)


def _chaddr(clause: "_pktcap.FilterClause") -> LayerTest:
    matches = chaddr_matcher(clause.key, _values(clause))
    return lambda layer: matches(layer.message["chaddr"])


def _option(clause: "_pktcap.FilterClause") -> LayerTest:
    if not clause.key.startswith(_OPTION_PREFIX):
        raise ValueError(
            "option takes an option's name or number: option.HOSTNAME or option.12"
        )
    code, wanted = option_selector(clause.key, clause.value)
    return lambda layer: _option_text(layer.message["options"], code) == wanted


def pktcap_plugin(registry: "_pktcap.DissectorRegistry") -> None:
    """Declare :class:`DHCPLayer` and its filter keys in `registry`, then register the dissector.

    The keys are `op`, `msg_type`, `xid`, `client_id`, `chaddr` and `option.NAME_OR_CODE`,
    each read as `compile_capture_filter` reads it, and the `DHCPLayer` fields as `dhcp.FIELD`.
    A call that raises leaves `registry` as it found it: `ValueError` for a layer name or a
    port that is taken.
    """
    registry.register_layer(
        DHCPLayer,
        keys={
            "op": _op,
            "msg_type": _msg_type,
            "xid": _xid,
            "client_id": _client_id,
            "chaddr": _chaddr,
            "option": _option,
        },
    )
    try:
        register_dhcp_dissector(registry)
    except Exception:
        registry.unregister_layer("dhcp")
        raise
