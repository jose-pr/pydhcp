"""Every test statement that reaches a private name says why, on the line above.

A test that reaches past the public surface (an underscored attribute, module,
imported name, or a patch target that names one) is coupled to how the code is
built; the comment states what makes the reach necessary, so that a reader can
tell it from one that only saved a line, and so that the count of them is a
number somebody chose. A comment on the line above the statement, or on the line
above an earlier statement of the same function that gives the same reason, is the
reason. `tests/interop/` drives real peers in namespaces and is not held to this.
"""

from __future__ import annotations

import ast
import pathlib

TESTS = pathlib.Path(__file__).resolve().parent
OWN = ("pydhcp", "netimps", "pktcap")


def private(name):
    if name.startswith("__") and name.endswith("__"):
        return False
    if name.endswith("_") and len(name) > 2:
        return False
    return name.startswith("_")


def hits_of(tree):
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and private(node.attr):
            base = node.value
            if isinstance(base, ast.Name) and base.id in ("self", "cls", "mcs"):
                continue
            if (
                isinstance(base, ast.Call)
                and isinstance(base.func, ast.Name)
                and base.func.id == "super"
            ):
                continue
            out.append((node.lineno, "attr", node.attr))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if node.level == 0 and mod.split(".")[0] in OWN:
                if any(private(p) for p in mod.split(".")):
                    out.append((node.lineno, "import-module", mod))
                for a in node.names:
                    if private(a.name):
                        out.append((node.lineno, "import-name", a.name))
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] == "pydhcp" and any(
                    private(p) for p in a.name.split(".")
                ):
                    out.append((node.lineno, "import-module", a.name))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            v = node.value
            if (
                v.startswith(("pydhcp.", "netimps."))
                and any(private(p) for p in v.split("."))
                and " " not in v
            ):
                out.append((node.lineno, "target", v))
    return out


def statements(tree):
    """(start, end, scope, col) of every simple or compound statement header, innermost last."""
    result = []

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                s = scope
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    # the header: decorators excluded, the def line to the colon
                    end = child.body[0].lineno - 1 if child.body else child.lineno
                    result.append((child.lineno, end, scope, child.col_offset))
                    s = child
                elif isinstance(
                    child,
                    (
                        ast.If,
                        ast.While,
                        ast.For,
                        ast.With,
                        ast.Try,
                        ast.AsyncFor,
                        ast.AsyncWith,
                    ),
                ):
                    first_body = child.body[0].lineno if child.body else child.lineno
                    result.append(
                        (child.lineno, first_body - 1, scope, child.col_offset)
                    )
                else:
                    result.append(
                        (child.lineno, child.end_lineno, scope, child.col_offset)
                    )
                visit(child, s)
            else:
                visit(child, scope)

    visit(tree, tree)
    return result


def _unexplained(path: pathlib.Path) -> "list[str]":
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    lines = text.splitlines()
    stmts = statements(tree)
    found: "list[str]" = []
    owners: "dict[tuple[int, int, int], list[str]]" = {}
    for ln, kind, name in hits_of(tree):
        best = None
        for start, end, scope, col in stmts:
            if start <= ln <= end and (best is None or start >= best[0]):
                best = (start, end, scope, col)
        if best is not None:
            owners.setdefault((best[0], best[3], id(best[2])), []).append(name)
    scopes_with_reason: "set[int]" = set()
    for (start, _col, scope), names in sorted(owners.items()):
        previous = lines[start - 2].strip() if start >= 2 else ""
        if previous.startswith("#"):
            scopes_with_reason.add(scope)
        elif scope not in scopes_with_reason:
            found.append(f"{path.name}:{start}: {sorted(set(names))}")
    return found


def test_every_private_reach_in_a_test_has_a_reason() -> None:
    missing: "list[str]" = []
    for path in sorted(TESTS.rglob("*.py")):
        if "interop" in path.parts or "__pycache__" in path.parts:
            continue
        missing.extend(_unexplained(path))
    assert missing == []
