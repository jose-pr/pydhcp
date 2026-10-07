"""Generate the tables of `docs/conformance.md` from the conformance data.

    python docs/conformance_table.py            print both tables
    python docs/conformance_table.py --write    replace the tables between the markers
                                                of docs/conformance.md
    python docs/conformance_table.py --check    exit 1 when the page differs

`tests/test_conformance_page.py` runs the check. The coverage table comes from
`tests/conformance/features.json` and the differences table from
`tests/conformance/deviations.json`, so the page cannot disagree with the cases.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PAGE = Path(__file__).resolve().parent / "conformance.md"
DATA = Path(__file__).resolve().parents[1] / "tests" / "conformance"
COVERAGE = ("<!-- coverage-table:begin -->", "<!-- coverage-table:end -->")
DIFFERENCES = ("<!-- differences-table:begin -->", "<!-- differences-table:end -->")


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def coverage() -> str:
    features = json.loads((DATA / "features.json").read_text(encoding="utf-8"))
    lines = [
        "| Role | Feature | RFC | Implemented | Cases | Note |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in features:
        lines.append(
            "| %s | %s | %s | %s | %s | %s |"
            % (
                row["role"],
                _cell(row["feature"]),
                row["rfc"],
                "yes" if row["implemented"] else "no",
                ", ".join("`%s`" % name for name in row["cases"]),
                _cell(row["note"]),
            )
        )
    return "\n".join(lines)


def differences() -> str:
    deviations = json.loads((DATA / "deviations.json").read_text(encoding="utf-8"))
    lines = ["| Difference | What differs | Authority |", "| --- | --- | --- |"]
    for row in deviations:
        lines.append(
            "| `%s` | %s | %s |"
            % (row["id"], _cell(row["difference"]), _cell(row["authority"]))
        )
    return "\n".join(lines)


def _block(markers, body: str) -> str:
    return "%s\n%s\n%s" % (markers[0], body, markers[1])


def current_block(text: str, markers) -> str:
    start = text.index(markers[0])
    stop = text.index(markers[1]) + len(markers[1])
    return text[start:stop]


def fresh(text: str) -> str:
    """The page with both tables as the data writes them."""
    for markers, body in ((COVERAGE, coverage()), (DIFFERENCES, differences())):
        text = text.replace(current_block(text, markers), _block(markers, body))
    return text


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(coverage())
        print()
        print(differences())
        return 0
    text = PAGE.read_text(encoding="utf-8")
    if args == ["--check"]:
        if fresh(text) != text:
            print(
                "docs/conformance.md differs from the conformance data: run --write",
                file=sys.stderr,
            )
            return 1
        return 0
    if args == ["--write"]:
        PAGE.write_bytes(fresh(text).encode("utf-8"))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
