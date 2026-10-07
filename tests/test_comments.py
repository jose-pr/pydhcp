"""The shipped source and headers describe the code as it is.

A comment or docstring that narrates what the code "used to" do is true at one
version only; the changelog records a change. This scans every ``.py`` under
``src/pydhcp`` (the private packages included), every shipped ``AGENTS.md``
below it and the comments of ``pyproject.toml`` for that wording, and for
references to things a reader of the repository cannot open, and fails naming
the file and line.

A phrase that is a fact and not history goes in ``_ALLOWED`` with a reason.
"""

import ast
import io
import re
import sys
import tokenize
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_PACKAGE = _ROOT / "src" / "pydhcp"

#: History wording.
_HISTORY = re.compile(
    r"\bused to\b|\bno longer\b|\bpreviously\b|\bthe old\b|\bhas always\b"
    r"|\bas before\b|\bwas a (?:real )?bug\b|\bturned out\b|\bshipped broken\b"
    r"|\bbefore the fix\b|\bthis one is new\b|\bearlier version\b"
    r"|\bas of the\b|(?<![`=\w.])now(?![`=\w(])|\bformerly\b|\boriginally\b"
    r"|\bhardcoding\b|\bas before\b",
    re.IGNORECASE,
)

#: A reference to something outside the repository: private notes, plans,
#: findings, reviews, decisions.
_PRIVATE = re.compile(
    r"\.agents\b|\bPhase \d|\bfinding [\w-]+-\d+|\b(?:review|audit) (?:found|flagged|said)\b"
    r"|\bD\d\d\b|\bgap\d-|\b(?:security|transport|server|wire|tooling|options-core)-\d+\b",
    re.IGNORECASE,
)

#: ``(substring of the line, why the phrase is a fact and not history)``.
_ALLOWED = (
    ("to `ttl` from now", "'now' is the moment of the call, in a duration"),
    ("`ttl` from now;", "'now' is the moment of the call, in a duration"),
    ("seconds from now, or", "'now' is the moment of the call, in a duration"),
    ("enumerates now, ", "'now' is the moment of the call"),
    ("working directory *now*", "'now' is the moment the command is loaded"),
    ("is found now (", "'now' is the moment the command is loaded"),
    ("is no longer listened on", "the state of a retired socket, not a change"),
    ("for this long and no longer", "'no longer' bounds a duration"),
    (
        "miscellaneous options used to configure",
        "RFC text: 'used to' meaning 'employed for'",
    ),
    ("used to key leases", "'used to' meaning 'employed for'"),
    ("can be used to identify", "RFC 1542 quotation: 'used to' meaning 'employed for'"),
)


def _sources():
    return (
        sorted(_PACKAGE.rglob("*.py"))
        + sorted(_PACKAGE.rglob("AGENTS.md"))
        + [_ROOT / "pyproject.toml"]
    )


def _allowed(line):
    return any(fragment in line for fragment, _reason in _ALLOWED)


def _prose(path):
    """The ``(line number, text)`` of what a reader takes as prose in a file.

    A Python file contributes its comments and its docstrings, never code (the
    word "now" is also a clock call); a header contributes every line; a TOML
    file contributes its comments.
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".md":
        return list(enumerate(text.splitlines(), 1))
    if path.suffix == ".toml":
        return [
            (number, line)
            for number, line in enumerate(text.splitlines(), 1)
            if "#" in line
        ]
    found = []
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.COMMENT:
            found.append((token.start[0], token.string))
    for node in ast.walk(ast.parse(text)):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(getattr(body[0], "value", None), ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                first = body[0].lineno
                for offset, line in enumerate(body[0].value.value.splitlines()):
                    found.append((first + offset, line))
    return found


def _offences(pattern):
    found = []
    for path in _sources():
        for number, line in _prose(path):
            if pattern.search(line) and not _allowed(line):
                found.append(
                    "%s:%d: %s"
                    % (path.relative_to(_ROOT).as_posix(), number, line.strip())
                )
    return found


def test_the_comments_narrate_no_history():
    found = _offences(_HISTORY)
    assert not found, (
        "comments describe the code as it is, not what it used to do; state "
        "the property, or add a fact-not-history phrase to _ALLOWED:\n"
        + "\n".join(found)
    )


def test_the_comments_cite_nothing_outside_the_repository():
    found = _offences(_PRIVATE)
    assert (
        not found
    ), "a comment names only what a reader of the repository can open:\n" + "\n".join(
        found
    )


def test_every_shipped_header_is_scanned():
    names = {path.relative_to(_ROOT).as_posix() for path in _sources()}
    assert "src/pydhcp/AGENTS.md" in names
    assert any(name.endswith("/server/AGENTS.md") for name in names)
    assert "pyproject.toml" in names


def test_a_planted_history_phrase_in_a_sub_header_is_caught(tmp_path, monkeypatch):
    sub = tmp_path / "src" / "pydhcp" / "server" / "AGENTS.md"
    sub.parent.mkdir(parents=True)
    sub.write_text("# header\n\nThis previously raised.\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("# fine\n", encoding="utf-8")
    module = sys.modules[__name__]
    monkeypatch.setattr(module, "_ROOT", tmp_path)
    monkeypatch.setattr(module, "_PACKAGE", tmp_path / "src" / "pydhcp")
    assert any(
        line.startswith("src/pydhcp/server/AGENTS.md:3:")
        for line in _offences(_HISTORY)
    )


def test_a_planted_private_reference_in_a_comment_is_caught(tmp_path, monkeypatch):
    module_file = tmp_path / "src" / "pydhcp" / "x.py"
    module_file.parent.mkdir(parents=True)
    module_file.write_text("# see .agents/plans for why\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("# fine\n", encoding="utf-8")
    module = sys.modules[__name__]
    monkeypatch.setattr(module, "_ROOT", tmp_path)
    monkeypatch.setattr(module, "_PACKAGE", tmp_path / "src" / "pydhcp")
    assert _offences(_PRIVATE)


def test_the_patterns_catch_the_wording_they_are_for():
    for line in (
        "# this used to call gethostbyname",
        "It was a bug here: every error advanced.",
        "The old code swallowed these.",
        "this is previously cached",
        "no longer sends",
    ):
        assert _HISTORY.search(line), line
    for line in ("# per .agents/AGENTS.md", "Phase 3 added it", "see finding wire-9"):
        assert _PRIVATE.search(line), line


@pytest.mark.parametrize("fragment", [fragment for fragment, _ in _ALLOWED])
def test_every_allowed_phrase_is_still_in_the_source(fragment):
    # An entry whose phrase has gone is an exemption nothing needs.
    assert any(fragment in path.read_text(encoding="utf-8") for path in _sources())
