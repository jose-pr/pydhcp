"""Write floors.txt: every declared dependency pinned to its lower bound.

Run by the floors jobs, which then install the project with `-c floors.txt`.
Reads `pyproject.toml` (the dependencies and every extra except `dev` and
`docs`). A requirement whose marker is false for the running interpreter is
left out, so a floor that differs by platform or Python picks the one that
applies here. `--skip NAME ...` leaves out the dependencies that have no
published version to pin.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

try:
    import tomllib
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "tomli"], check=True)
    import tomli as tomllib  # type: ignore[no-redef]

try:
    from packaging.requirements import Requirement
except ImportError:
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "packaging"], check=True
    )
    from packaging.requirements import Requirement

TOOLING = ("dev", "docs")


def floors(project: dict, skip: "set[str]") -> "dict[str, str]":
    specs = list(project.get("dependencies", []))
    for extra, deps in project.get("optional-dependencies", {}).items():
        if extra not in TOOLING:
            specs += deps
    pins: "dict[str, str]" = {}
    for spec in specs:
        requirement = Requirement(spec)
        name = requirement.name.lower().replace("_", "-")
        if name in skip:
            continue
        if requirement.marker is not None and not requirement.marker.evaluate(
            {"extra": ""}
        ):
            continue
        bounds = [s.version for s in requirement.specifier if s.operator == ">="]
        if not bounds:
            continue
        if pins.get(name, bounds[0]) != bounds[0]:
            raise SystemExit(
                "%s has two floors for this interpreter: %s and %s"
                % (name, pins[name], bounds[0])
            )
        pins[name] = bounds[0]
    return pins


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip", nargs="*", default=[], metavar="NAME")
    args = parser.parse_args()
    with open("pyproject.toml", "rb") as handle:
        project = tomllib.load(handle)["project"]
    pins = floors(project, {n.lower().replace("_", "-") for n in args.skip})
    lines = ["%s==%s" % pair for pair in sorted(pins.items())]
    with open("floors.txt", "w", encoding="utf-8", newline="\n") as out:
        out.write("\n".join(lines) + "\n")
    print("\n".join(lines) or "(no floors declared)")


if __name__ == "__main__":
    main()
