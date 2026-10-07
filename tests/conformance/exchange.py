"""The wire read and written with ``struct`` alone, shared by the recorder and the replay.

Nothing here imports ``pydhcp``, so what a golden holds does not depend on the
code under test. A case (``cases/<name>/case.json``) is written by hand:

    description  what the case asks
    role         ``server``, ``relay`` or ``client``: the one under comparison
    topology     ``single`` or ``relayed`` (``tests/interop/_topo.py``)
    config       what the reference and this library are both given
    steps        what is sent, in order (a server or relay case) or the asks (a client case)
    not_compared a list of ``{aspect, step, why}``: what is left out of the comparison

A message is written field by field::

    {"type": "DISCOVER", "chaddr": "02:00:00:99:00:02", "xid": "1001a001", "flags": 32768,
     "requested": "10.99.0.100", "prl": [1, 3], "options": [[61, "01020000990002"]]}

``type`` is option 53 by name; ``client_id`` (61, hex), ``requested`` (50), ``server_id`` (54),
``lease`` (51), ``hostname`` (12) and ``prl`` (55) are the options a case most often sets, in
that order after ``type``; ``options`` is any further ``[code, hex]``. Header fields not given are
zero, ``op`` is 1 (2 when ``reply`` is true), ``htype`` 1 and ``hlen`` 6.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import pathlib
import struct
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple

HERE = pathlib.Path(__file__).resolve().parent
CASES = HERE / "cases"
TRANSCRIPTS = HERE / "transcripts"
MIN_SIZE = 300
COOKIE = bytes([99, 130, 83, 99])
TYPES = {
    "DISCOVER": 1,
    "OFFER": 2,
    "REQUEST": 3,
    "DECLINE": 4,
    "ACK": 5,
    "NAK": 6,
    "RELEASE": 7,
    "INFORM": 8,
}
TYPE_NAMES = {number: name for name, number in TYPES.items()}
#: The header fields, in wire order, as ``read`` names them.
FIELDS = (
    "op htype hlen hops xid secs flags ciaddr yiaddr siaddr giaddr chaddr sname file"
).split()
ASPECTS = "count destination padding option-order".split()
#: The text of option 56 is the reference's own wording: only its presence compares.
PRESENCE_ONLY = (56,)

Datagram = Tuple[bytes, str]


class Difference(NamedTuple):
    """One thing a reply differs in: ``reply`` is its index in the step's replies, or None."""

    reply: Optional[int]
    aspect: str
    reference: str
    ours: str


def cases() -> List[pathlib.Path]:
    """The case directories, in name order: every one holds a ``case.json``."""
    return sorted(p for p in CASES.iterdir() if (p / "case.json").is_file())


def load(directory: pathlib.Path) -> Dict[str, Any]:
    return dict(json.loads((directory / "case.json").read_text(encoding="utf-8")))


def _mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def _ip(text: str) -> bytes:
    return ipaddress.IPv4Address(text).packed


def _integer(value: Any) -> int:
    return int(value, 16) if isinstance(value, str) else int(value)


def _option_list(message: Dict[str, Any]) -> List[Tuple[int, bytes]]:
    """The options a message spells, ``type`` first, then the named ones, then ``options``."""
    found: List[Tuple[int, bytes]] = []
    if "type" in message:
        found.append((53, bytes([TYPES[message["type"]]])))
    if "client_id" in message:
        found.append((61, bytes.fromhex(message["client_id"])))
    if "requested" in message:
        found.append((50, _ip(message["requested"])))
    if "server_id" in message:
        found.append((54, _ip(message["server_id"])))
    if "lease" in message:
        found.append((51, struct.pack("!I", message["lease"])))
    if "hostname" in message:
        found.append((12, message["hostname"].encode("ascii")))
    if "prl" in message:
        found.append((55, bytes(message["prl"])))
    found += [
        (int(code), bytes.fromhex(value)) for code, value in message.get("options", [])
    ]
    return found


def build(message: Dict[str, Any]) -> bytes:
    """A datagram from the hand-written fields: the options, END, padded to 300 octets."""
    chaddr = _mac(message["chaddr"])
    sname = message.get("sname", "").encode("ascii")
    file = message.get("file", "").encode("ascii")
    head = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2 if message.get("reply") else message.get("op", 1),
        message.get("htype", 1),
        message.get("hlen", len(chaddr)),
        message.get("hops", 0),
        _integer(message["xid"]),
        message.get("secs", 0),
        _integer(message.get("flags", 0)),
        _ip(message.get("ciaddr", "0.0.0.0")),
        _ip(message.get("yiaddr", "0.0.0.0")),
        _ip(message.get("siaddr", "0.0.0.0")),
        _ip(message.get("giaddr", "0.0.0.0")),
        chaddr,
        sname,
        file,
    )
    body = bytearray(COOKIE)
    for code, value in _option_list(message):
        body += bytes([code, len(value)]) + value
    body += b"\xff"
    return (head + bytes(body)).ljust(MIN_SIZE, b"\x00")


def answer(request: bytes, reply: Dict[str, Any]) -> bytes:
    """The scripted server's reply to ``request``: xid, flags, chaddr, giaddr and hops copied.

    ``reply`` spells the rest (``type``, ``yiaddr``, ``options`` ...); the identity of the
    request wins over anything it says for the copied fields.
    """
    seen = read(request)
    message = dict(reply)
    message.update(
        reply=True,
        xid=seen["xid"],
        flags=int(seen["flags"], 16),
        hops=int(seen["hops"]),
        giaddr=seen["giaddr"],
        htype=int(seen["htype"]),
        hlen=int(seen["hlen"]),
        chaddr=seen["chaddr"][: 2 * int(seen["hlen"])],
    )
    return build(message)


def read(payload: bytes) -> Dict[str, Any]:
    """A datagram as text: the header fields, ``options`` as ordered ``(code, hex)``, ``after_end``.

    ``ValueError`` for an option 52 (overload): no case uses it, and reading it would
    hide options in ``sname`` or ``file``.
    """
    if len(payload) < 240 or payload[236:240] != COOKIE:
        raise ValueError("not a DHCP message: no magic cookie")
    fixed = struct.unpack("!BBBBIHH4s4s4s4s16s64s128s", payload[:236])
    fields = dict(zip(FIELDS, fixed))
    read_back: Dict[str, Any] = {
        "op": str(fields["op"]),
        "htype": str(fields["htype"]),
        "hlen": str(fields["hlen"]),
        "hops": str(fields["hops"]),
        "xid": "%08x" % fields["xid"],
        "secs": str(fields["secs"]),
        "flags": "%04x" % fields["flags"],
        "chaddr": fields["chaddr"].hex(),
        "sname": fields["sname"].rstrip(b"\x00").hex(),
        "file": fields["file"].rstrip(b"\x00").hex(),
    }
    for name in ("ciaddr", "yiaddr", "siaddr", "giaddr"):
        read_back[name] = str(ipaddress.IPv4Address(fields[name]))
    options: List[Tuple[int, str]] = []
    index = 240
    after_end = ""
    while index < len(payload):
        code = payload[index]
        index += 1
        if code == 0:
            continue
        if code == 255:
            after_end = payload[index:].hex()
            break
        if index >= len(payload) or index + 1 + payload[index] > len(payload):
            raise ValueError("option %d runs past the datagram" % code)
        length = payload[index]
        if code == 52:
            raise ValueError("option overload (52) is not read")
        options.append((code, payload[index + 1 : index + 1 + length].hex()))
        index += 1 + length
    read_back["options"] = options
    read_back["after_end"] = after_end
    read_back["size"] = len(payload)
    return read_back


def message_type(payload: bytes) -> str:
    for code, value in read(payload)["options"]:
        if code == 53 and len(value) == 2:
            return TYPE_NAMES.get(int(value, 16), "TYPE%d" % int(value, 16))
    return "BOOTP"


def summary(payload: bytes) -> str:
    """What a datagram says in a line: its type, xid, the addresses it names, its option codes."""
    seen = read(payload)
    named = [
        "%s=%s" % (n, seen[n])
        for n in ("ciaddr", "yiaddr", "siaddr", "giaddr")
        if seen[n] != "0.0.0.0"
    ]
    codes = " ".join(str(code) for code, _ in seen["options"])
    return " ".join(
        [
            message_type(payload),
            "xid=" + seen["xid"],
            *named,
            "options[%s]" % codes,
            "%d octets" % len(payload),
        ]
    )


def _skipped(aspect: str, not_compared: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(aspect, pattern) for pattern in not_compared)


def _options_length(seen: Dict[str, Any]) -> int:
    return sum(2 + len(value) // 2 for _, value in seen["options"])


def differences(
    reference: Sequence[Datagram],
    ours: Sequence[Datagram],
    not_compared: Iterable[str] = (),
) -> List[Difference]:
    """Every aspect the replies of one step differ in, the ones in ``not_compared`` left out.

    ``reference`` and ``ours`` are lists of ``(payload, "address:port")``. The aspects: ``count``
    (silence is a count of zero), ``field:NAME``, ``option-absent:N`` (the reference sent it,
    this library did not), ``option-extra:N`` (the other way), ``option-value:N`` (to the octet),
    ``option-order`` (the options both sent), ``padding`` (the octets after END when the
    options are one length, else the datagram length) and ``destination``. An entry of
    ``not_compared`` is an aspect or an ``fnmatch`` pattern of one (``field:xid``,
    ``option-value:*``).
    """
    found: List[Difference] = []

    def note(reply: Optional[int], aspect: str, wanted: str, got: str) -> None:
        if not _skipped(aspect, not_compared):
            found.append(Difference(reply, aspect, wanted, got))

    if len(reference) != len(ours):
        note(None, "count", str(len(reference)), str(len(ours)))
    for index, ((wanted, where), (got, there)) in enumerate(zip(reference, ours)):
        one, two = read(wanted), read(got)
        for name in FIELDS:
            if one[name] != two[name]:
                note(index, "field:" + name, one[name], two[name])
        first, second = dict(one["options"]), dict(two["options"])
        for code in sorted(set(first) - set(second)):
            note(index, "option-absent:%d" % code, first[code], "")
        for code in sorted(set(second) - set(first)):
            note(index, "option-extra:%d" % code, "", second[code])
        for code in sorted(set(first) & set(second)):
            if first[code] != second[code] and code not in PRESENCE_ONLY:
                note(index, "option-value:%d" % code, first[code], second[code])
        shared = set(first) & set(second)
        order_one = [c for c, _ in one["options"] if c in shared]
        order_two = [c for c, _ in two["options"] if c in shared]
        if order_one != order_two:
            note(
                index,
                "option-order",
                " ".join(map(str, order_one)),
                " ".join(map(str, order_two)),
            )
        if _options_length(one) == _options_length(two):
            if one["after_end"] != two["after_end"]:
                note(
                    index,
                    "padding",
                    "%d octets after END" % (len(one["after_end"]) // 2),
                    "%d octets after END" % (len(two["after_end"]) // 2),
                )
        elif one["size"] != two["size"]:
            note(
                index,
                "padding",
                "%d octets in all" % one["size"],
                "%d octets in all" % two["size"],
            )
        if where != there:
            note(index, "destination", where, there)
    return found
