"""Where a message's options, `sname` and `file` go: the fields that can hold options.

RFC 2131 section 4.1 lets the `file` and `sname` fields carry options when option
52 says so (RFC 2132 section 9.3); RFC 3396 reads the options field, `file` and
`sname`, in that order, as one buffer and lets an option be split between them.
The layout is chosen in this order, and the first that holds everything wins:

1. no overload, the options in one pass;
2. each way of overloading, those that relocate no occupied name first, laying
   the options out in order and splitting the one that crosses a field's end;
3. the same ways again, each option kept whole and the fields filled so that
   every option has room (an exact search, bounded as `_assign` says).

Option 53 leads the options field, then option 52, then a relocated name (66, 67),
then the rest in the order they were set, with option 1 before option 3 (RFC 2132
section 3.3); every field keeps that order.
"""

from __future__ import annotations

import collections as _collections
import typing as _ty

from ..exceptions import DHCPValueError
from ..options import _wire
from ._fields import _FILE_FIELD_SIZE, _SNAME_FIELD_SIZE

_Octets = _ty.Union[bytes, bytearray]
_Item = tuple[int, _Octets]

_END = 0xFF
_SUBNET_MASK = 1
_ROUTER = 3
_OVERLOAD = 52
_MESSAGE_TYPE = 53
_TFTP_SERVER = 66
_BOOTFILE_NAME = 67

#: `OptionOverload` values: bit 0 is `file`, bit 1 is `sname`.
_FILE = 1
_SNAME = 2

#: Octets an overloaded field holds besides its END.
_FILE_ROOM = _FILE_FIELD_SIZE - 1
_SNAME_ROOM = _SNAME_FIELD_SIZE - 1

_FIELDS_TEXT = {
    _FILE: "the options and file fields",
    _SNAME: "the options and sname fields",
    _FILE | _SNAME: "the options, file and sname fields",
}


class PackedFields(_ty.NamedTuple):
    """What goes in the options field, the `sname` field and the `file` field."""

    options: _Octets
    sname: _Octets
    file: _Octets


def ordered(options: _ty.Mapping[int, _Octets]) -> list[_Item]:
    """The options as they are written: 53 first, 1 before 3, the rest as set.

    Option 52 is left out: whether the message overloads is decided here.
    """
    items: list[_Item] = []
    message_type = options.get(_MESSAGE_TYPE)
    if message_type is not None:
        items.append((_MESSAGE_TYPE, message_type))
    subnet_mask = options.get(_SUBNET_MASK)
    placed = False
    for code, payload in options.items():
        if code == _MESSAGE_TYPE or code == _OVERLOAD:
            continue
        if code == _SUBNET_MASK:
            if placed:
                continue
            placed = True
        elif code == _ROUTER and subnet_mask is not None and not placed:
            items.append((_SUBNET_MASK, subnet_mask))
            placed = True
        items.append((code, payload))
    return items


def _cost(item: _Item) -> int:
    return _wire.option_octets(len(item[1]))


class _Plan:
    """One way of carrying a message: which fields hold options and what leads."""

    def __init__(
        self,
        choice: int,
        items: list[_Item],
        options: _ty.Mapping[int, _Octets],
        sname: bytes,
        file: bytes,
        room: int,
    ) -> None:
        self.choice = choice
        self.conflict: _ty.Optional[str] = None
        self.unplaced: _ty.Optional[int] = None
        lead = items[:1] if items and items[0][0] == _MESSAGE_TYPE else []
        head: list[_Item] = [(_OVERLOAD, bytes([choice]))]
        for flag, code, name, field in (
            (_SNAME, _TFTP_SERVER, sname, "sname"),
            (_FILE, _BOOTFILE_NAME, file, "file"),
        ):
            if not choice & flag or not name:
                continue
            existing = options.get(code)
            if existing is None:
                head.append((code, name))
            elif bytes(existing) != name:
                self.conflict = (
                    f"{field} holds {len(name)} octets and option {code} other "
                    f"octets: with {field} carrying options, its name can only "
                    f"travel as option {code}"
                )
        self.pinned = lead + head[:1]
        self.movable = head[1:] + items[len(lead) :]
        self.room = room - 1
        self.capacity = (
            self.room
            + (_FILE_ROOM if choice & _FILE else 0)
            + (_SNAME_ROOM if choice & _SNAME else 0)
        )
        self.demand = sum(_cost(item) for item in self.pinned + self.movable)

    @property
    def pinned_cost(self) -> int:
        return sum(_cost(item) for item in self.pinned)


def _pour(plan: _Plan, sname: _Octets, file: _Octets) -> _ty.Optional[PackedFields]:
    """Write the options in order, splitting the one that crosses a field's end."""
    if plan.pinned_cost > plan.room:
        return None
    mapping: _ty.OrderedDict[int, _Octets] = _collections.OrderedDict(
        plan.pinned + plan.movable
    )
    field, extra = _wire.partial_encode(mapping, plan.room + 1)
    if plan.choice & _FILE:
        file, extra = _wire.partial_encode(extra, _FILE_FIELD_SIZE)
    if plan.choice & _SNAME:
        sname, extra = _wire.partial_encode(extra, _SNAME_FIELD_SIZE)
    if extra:
        plan.unplaced = next(iter(extra))
        return None
    return PackedFields(field, sname, file)


def _assign(
    costs: list[int], main: int, file: int, sname: int
) -> _ty.Optional[list[int]]:
    """Which field (0 options, 1 file, 2 sname) holds each whole option, or `None`.

    The options field takes what is left once `file` and `sname` hold some of the
    costs, so the question is which sets of costs fit the two small fields. Those
    are tracked as one integer with a bit per (octets used in `file`, octets used
    in `sname`) pair, at most 128 by 64 bits, and each option shifts it twice:
    the work is two operations on a 1 KiB integer per option, plus the search of
    at most 128 rows for a final state. The earliest options are kept in the
    options field wherever the room allows.
    """
    total = sum(costs)
    if total <= main:
        return [0] * len(costs)
    need = total - main
    if file + sname < need:
        return None
    stride = sname + 1
    width = (file + 1) * stride
    everything = (1 << width) - 1
    per_row = everything // ((1 << stride) - 1)
    reach = 1
    history = []
    for cost in reversed(costs):
        history.append(reach)
        moved = 0
        if cost <= file:
            moved |= (reach << (cost * stride)) & everything
        if cost <= sname:
            moved |= (reach & (((1 << (stride - cost)) - 1) * per_row)) << cost
        reach |= moved
    best: _ty.Optional[tuple[int, int, int]] = None
    for used_file in range(file + 1):
        row = (reach >> (used_file * stride)) & ((1 << stride) - 1)
        low = max(0, need - used_file)
        row >>= low
        if not row:
            continue
        used_sname = low + (row & -row).bit_length() - 1
        candidate = (used_file + used_sname, used_sname, used_file)
        if best is None or candidate < best:
            best = candidate
    if best is None:
        return None
    _, used_sname, used_file = best
    assignment = [0] * len(costs)
    for step in range(len(costs) - 1, -1, -1):
        cost = costs[len(costs) - 1 - step]
        before = history[step]
        index = len(costs) - 1 - step
        if (before >> (used_file * stride + used_sname)) & 1:
            continue
        if (
            used_file >= cost
            and (before >> ((used_file - cost) * stride + used_sname)) & 1
        ):
            assignment[index] = 1
            used_file -= cost
        else:
            assignment[index] = 2
            used_sname -= cost
    return assignment


def _tight(plan: _Plan, sname: _Octets, file: _Octets) -> _ty.Optional[PackedFields]:
    """Keep every option whole and find the field each has room in."""
    if plan.pinned_cost > plan.room:
        return None
    costs = [_cost(item) for item in plan.movable]
    assignment = _assign(
        costs,
        plan.room - plan.pinned_cost,
        _FILE_ROOM if plan.choice & _FILE else 0,
        _SNAME_ROOM if plan.choice & _SNAME else 0,
    )
    if assignment is None:
        return None
    fields = [bytearray(), bytearray(), bytearray()]
    _wire.write_items(fields[0], plan.pinned)
    for field in range(3):
        _wire.write_items(
            fields[field],
            (item for item, where in zip(plan.movable, assignment) if where == field),
        )
        fields[field].append(_END)
    return PackedFields(
        fields[0],
        fields[2] if plan.choice & _SNAME else sname,
        fields[1] if plan.choice & _FILE else file,
    )


def pack(
    options: _ty.Mapping[int, _Octets],
    sname: bytes,
    file: bytes,
    room: int,
    datagram: int,
    describe: _ty.Callable[[int], str],
) -> PackedFields:
    """Lay the options out for an options field of `room` octets.

    `datagram` is the caller's `max_packetsize`, for the refusal. Raises
    `OverflowError` when the options do not fit even with `sname` and `file`
    carrying options, and `DHCPValueError` when a name has no place to travel.
    """
    items = ordered(options)
    names_fit = len(sname) <= _SNAME_FIELD_SIZE and len(file) <= _FILE_FIELD_SIZE
    if names_fit:
        field = bytearray()
        _wire.write_items(field, items)
        field.append(_END)
        if len(field) <= room:
            return PackedFields(field, sname, file)

    # A name too long for its field can only travel as an option, so the field
    # it would have filled carries options (the decoder takes the option back).
    forced = (_SNAME if len(sname) > _SNAME_FIELD_SIZE else 0) | (
        _FILE if len(file) > _FILE_FIELD_SIZE else 0
    )
    choices = sorted(
        (_SNAME, _FILE, _SNAME | _FILE),
        key=lambda choice: bool(choice & _FILE and file)
        + bool(choice & _SNAME and sname),
    )
    plans = [
        _Plan(choice, items, options, sname, file, room)
        for choice in choices
        if choice & forced == forced
    ]
    usable = [plan for plan in plans if plan.conflict is None]
    for strategy in (_pour, _tight):
        for plan in usable:
            packed = strategy(plan, sname, file)
            if packed is not None:
                return packed
    raise _refusal(plans, items, room, datagram, describe)


def _refusal(
    plans: list[_Plan],
    items: list[_Item],
    room: int,
    datagram: int,
    describe: _ty.Callable[[int], str],
) -> Exception:
    """The error for options that fit no layout: which option, and by how much."""
    conflicts = "; ".join(sorted({p.conflict for p in plans if p.conflict}))
    usable = [plan for plan in plans if plan.conflict is None]
    if not usable:
        return DHCPValueError(conflicts)
    best = max(usable, key=lambda plan: plan.capacity - plan.demand)
    if best.pinned_cost > best.room:
        names = " and ".join(describe(code) for code, _ in best.pinned)
        demand = sum(_cost(item) for item in items)
        spent = 0
        first = items[-1][0] if items else _MESSAGE_TYPE
        for item in items:
            spent += _cost(item)
            if spent > room - 1:
                first = item[0]
                break
        text = (
            f"DHCP options exceed maximum packet size {datagram}: {describe(first)} "
            f"did not fit; the options need {demand} octets and the options "
            f"field has {room - 1} besides its END, {demand - room + 1} octets "
            f"short; overloading sname and file would take {best.pinned_cost} "
            f"of them for {names}"
        )
    else:
        short = best.demand - best.capacity
        unplaced = best.unplaced
        if unplaced is None:
            unplaced = best.movable[-1][0] if best.movable else _MESSAGE_TYPE
        verdict = (
            f"{short} octets short"
            if short > 0
            else "the room is there but not in a shape the options fit "
            "(an option split between fields costs 2 octets more)"
        )
        text = (
            f"DHCP options exceed maximum packet size {datagram}: {describe(unplaced)} "
            f"did not fit; the options need {best.demand} octets and "
            f"{_FIELDS_TEXT[best.choice]} hold {best.capacity} besides each END, "
            f"{verdict}"
        )
    if conflicts:
        text += f"; {conflicts}"
    return OverflowError(text)
