"""Generate the coverage table of `docs/options.md` from the option registry.

    python docs/options_table.py            print the table
    python docs/options_table.py --write    replace the table between the markers
                                            of docs/options.md
    python docs/options_table.py --check    exit 1 when the page differs

`tests/test_options_page.py` runs the check, so the page cannot disagree with
the registry. The RFC column is data kept here: the enum does not carry which
document defines each option.
"""

from __future__ import annotations

import sys
from pathlib import Path

BEGIN = "<!-- options-table:begin -->"
END = "<!-- options-table:end -->"
PAGE = Path(__file__).resolve().parent / "options.md"

#: The document that defines each option (IANA's BOOTP and DHCP parameters).
#: Codes 1 to 61 and 64 to 76 are all RFC 2132 and are not repeated here.
#: Compared with IANA's options.csv on 2026-10-07: every code that names an
#: RFC here names one the registry gives for it. Nothing re-checks it.
_RFC = {
    62: "RFC 2242",
    63: "RFC 2242",
    77: "RFC 3004",
    78: "RFC 2610",
    79: "RFC 2610",
    80: "RFC 4039",
    81: "RFC 4702",
    82: "RFC 3046",
    83: "RFC 4174",
    85: "RFC 2241",
    86: "RFC 2241",
    87: "RFC 2241",
    88: "RFC 4280",
    89: "RFC 4280",
    90: "RFC 3118",
    91: "RFC 4388",
    92: "RFC 4388",
    93: "RFC 4578",
    94: "RFC 4578",
    95: "RFC 3679",
    97: "RFC 4578",
    98: "RFC 2485",
    99: "RFC 4776",
    100: "RFC 4833",
    101: "RFC 4833",
    108: "RFC 8925",
    109: "RFC 8539",
    112: "RFC 3679",
    113: "RFC 3679",
    114: "RFC 8910",
    116: "RFC 2563",
    117: "RFC 2937",
    118: "RFC 3011",
    119: "RFC 3397",
    120: "RFC 3361",
    121: "RFC 3442",
    122: "RFC 3495",
    123: "RFC 6225",
    124: "RFC 3925",
    125: "RFC 3925",
    136: "RFC 5192",
    137: "RFC 5223",
    138: "RFC 5417",
    139: "RFC 5678",
    140: "RFC 5678",
    141: "RFC 6011",
    142: "RFC 6153",
    143: "RFC 8572",
    144: "RFC 6225",
    145: "RFC 6704",
    146: "RFC 6731",
    147: "RFC 8973",
    148: "RFC 8973",
    150: "RFC 5859",
    151: "RFC 6926",
    152: "RFC 6926",
    153: "RFC 6926",
    154: "RFC 6926",
    155: "RFC 6926",
    156: "RFC 6926",
    157: "RFC 6926",
    158: "RFC 7291",
    159: "RFC 7618",
    161: "RFC 8520",
    162: "RFC 9463",
    208: "RFC 5071",
    209: "RFC 5071",
    210: "RFC 5071",
    211: "RFC 5071",
    212: "RFC 5969",
    213: "RFC 5986",
    220: "RFC 6656",
    221: "RFC 6607",
}
for _code in range(128, 136):
    _RFC[_code] = "RFC 4578 (reserved)"
for _code in (0, 255):
    _RFC[_code] = "RFC 2132"
for _code in list(range(1, 62)) + list(range(64, 77)):
    _RFC[_code] = "RFC 2132"
#: Named in the registry and defined by no RFC.
_NO_RFC = "none"

#: Where the reading or the writing departs from the plain RFC text.
_NOTES = {
    0: "Framing, not an option with a value: no codec.",
    255: "Framing, not an option with a value: no codec.",
    33: "A route to `0.0.0.0` is read; building or writing one raises.",
    82: "Sub-options 0 and 255 are read as codes (RFC 3046 defines no pad and no end).",
    88: "Written uncompressed (RFC 4280 section 4.6).",
    119: "Written compressed (RFC 3397).",
    120: "Compressed names are read (RFC 3361); names are written uncompressed.",
    121: "A destination with host bits set is read with them zeroed; `ClasslessRoute(...)` stays strict.",
    141: "Written compressed (RFC 3397).",
    146: "Written uncompressed; the root name and the reserved flag bits are read as RFC 6731 allows.",
    212: "`DHCPOptionCode.GRD` is an alias member of `SIXRD`.",
    249: "Microsoft's number for option 121; read like it.",
}


def _codec(code: int, member) -> str:
    if code in (0, 255):
        return "framing"
    kind = member.get_type()
    name = getattr(kind, "__name__", str(kind))
    return f"`{name}` (opaque)" if name == "Bytes" else f"`{name}`"


def rows():
    """`(code, name, codec, rfc, note)` for every code the registry names."""
    from pydhcp.options import DHCPOptionCode

    names: dict[int, str] = {}
    for name, member in DHCPOptionCode.__members__.items():
        names.setdefault(int(member), name)
    out = []
    for code in sorted(names):
        member = DHCPOptionCode(code)
        out.append(
            (
                code,
                names[code],
                _codec(code, member),
                _RFC.get(code, _NO_RFC),
                _NOTES.get(code, ""),
            )
        )
    return out


def render() -> str:
    data = rows()
    named = [r for r in data if r[0] not in (0, 255)]
    opaque = [r for r in named if r[2].endswith("(opaque)")]
    lines = [
        f"{len(named)} option codes are named, and a further two (0 and 255) frame "
        f"the option stream. {len(named) - len(opaque)} of the named codes have a "
        f"structured codec; the other {len(opaque)} are carried as opaque `Bytes` "
        "(the octets are kept and forwarded unchanged). Any other code from 0 to "
        "255 is also read as opaque `Bytes`.",
        "",
        "| Code | Name | Codec | RFC | Departure from the RFC text |",
        "| ---: | --- | --- | --- | --- |",
    ]
    for code, name, codec, rfc, note in data:
        lines.append(f"| {code} | `{name}` | {codec} | {rfc} | {note} |")
    return "\n".join(lines)


def block(text: str) -> str:
    return f"{BEGIN}\n{render()}\n{END}"


def current_block(text: str) -> str:
    start = text.index(BEGIN)
    stop = text.index(END) + len(END)
    return text[start:stop]


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(render())
        return 0
    text = PAGE.read_text(encoding="utf-8")
    fresh = block(text)
    if args == ["--check"]:
        if current_block(text) != fresh:
            print(
                "docs/options.md differs from the registry: run --write",
                file=sys.stderr,
            )
            return 1
        return 0
    if args == ["--write"]:
        PAGE.write_bytes(text.replace(current_block(text), fresh).encode("utf-8"))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
