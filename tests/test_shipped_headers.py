"""The shipped ``AGENTS.md`` headers stay complete, listed and true.

``src/pydhcp/AGENTS.md`` is the top header: every name the root exports with its signature and one
sentence. A topic lives whole in the header beside the code that implements it. These tests pin what
makes the split trustworthy: every public name is in the header of its module, every header is listed
by the one above it, none outgrows its limit, every signature a header prints is the live one, and
each header reaches the wheel.
"""

from __future__ import annotations

import ast
import enum
import importlib
import inspect
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from test_surface import SURFACE

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "pydhcp"
TOP = PACKAGE / "AGENTS.md"
SUBHEADERS = sorted(p for p in PACKAGE.rglob("AGENTS.md") if p != TOP)

#: The most lines a header may have: the top header and each package header end under 400, the
#: repo-root file under 150 and the tests' file under 250. Past a limit, detail moves down or out.
TOP_MAX_LINES = 399
SUB_MAX_LINES = 399
ROOT_MAX_LINES = 149
TESTS_MAX_LINES = 249

#: The public modules: every one of them is in ``__all__`` form in `test_surface.py`.
PUBLIC = sorted(
    name
    for name in SURFACE
    if not any(part.startswith("_") for part in name.split("."))
)


def _text(path):
    return path.read_text(encoding="utf-8")


def _lines(path):
    return _text(path).splitlines()


def _inside_package(path):
    """The path a reader of the installed package uses: ``pydhcp/client/AGENTS.md``."""
    return "pydhcp/" + path.relative_to(PACKAGE).as_posix()


# -- sizes and the opening -----------------------------------------------------------------------


def test_the_top_header_is_not_over_its_limit():
    assert len(_lines(TOP)) <= TOP_MAX_LINES


@pytest.mark.parametrize("path", SUBHEADERS, ids=_inside_package)
def test_a_package_header_is_not_over_its_limit(path):
    assert len(_lines(path)) <= SUB_MAX_LINES


def test_there_are_package_headers():
    # A split that left nothing below would make the limits above vacuous.
    assert {p.parent.name for p in SUBHEADERS} >= {
        "listener",
        "server",
        "client",
        "relay",
        "capture",
        "packet",
        "options",
        "_codecs",
        "cli",
    }


def test_a_private_package_has_no_header_of_its_own():
    """Its names are documented where they are exported: `pydhcp._network` has none."""
    assert not (PACKAGE / "_network" / "AGENTS.md").exists()


@pytest.mark.parametrize("path", SUBHEADERS, ids=_inside_package)
def test_a_package_header_opens_as_one_and_names_the_top_header(path):
    head = "\n".join(_lines(path)[:12])
    assert head.startswith("# `pydhcp."), path
    assert "public API header" in head
    assert "`pydhcp/AGENTS.md`" in " ".join(head.split())


def test_the_top_header_opens_with_the_standards_paragraphs():
    head = "\n".join(_lines(TOP)[:40])
    assert head.startswith("# `pydhcp` — public API header")
    assert "importlib.resources.files" in head
    assert "pip install pydhcp" in head and 'pip install "pydhcp[cli]"' in head
    assert "`pydhcp.__version__`" in head
    assert "Modules and packages\nstarting with `_` are private" in head


@pytest.mark.parametrize("path", [TOP] + SUBHEADERS, ids=_inside_package)
def test_a_header_has_no_repository_link(path):
    # An installed consumer has no repository: nothing relative, nothing into private notes.
    text = _text(path)
    assert not re.search(r"\]\((?!https?://)[^)]*\)", text), "a relative link"
    assert "." + "agents" not in text and "CHANGELOG.md" not in text


# -- the names -------------------------------------------------------------------------------------


def _sections(path):
    """``[(heading, body)]`` of the ``##`` sections of a header."""
    parts = re.split(r"^## (.*)$", _text(path), flags=re.M)
    return [("", parts[0])] + [
        (parts[i], parts[i + 1]) for i in range(1, len(parts), 2)
    ]


def _spans(text):
    """The code spans and the fenced lines of a text."""
    return re.findall(r"`([^`\n]+)`", text) + [
        l for l in text.splitlines() if l and l[0] not in " #|-*"
    ]


def _names_in(spans, name):
    pattern = r"(?<![\w.])(?:pydhcp(?:\.\w+)*\.)?%s(?!\w)" % re.escape(name)
    return any(re.search(pattern, span) for span in spans)


def _heading_modules(heading):
    return re.findall(r"`(pydhcp(?:\.\w+)*)", heading)


def _owned_spans(module):
    """The code of every section, in any header, whose heading names *module*."""
    texts = []
    for path in [TOP] + SUBHEADERS:
        for heading, body in _sections(path):
            if heading.startswith("Where names live"):
                continue
            if module in _heading_modules(heading):
                texts.append(body)
    return _spans("\n".join(texts))


def _public_names():
    out = []
    for module in PUBLIC:
        live = importlib.import_module(module)
        out += [(module, name) for name in live.__all__]
    return out


@pytest.mark.parametrize("module,name", _public_names())
def test_every_public_name_is_in_the_header_of_its_module(module, name):
    spans = _owned_spans(module)
    assert _names_in(
        spans, name
    ), "%s.%s is in __all__ but in no code span of a section naming `%s`" % (
        module,
        name,
        module,
    )


def test_the_table_of_names_is_every_public_modules_all():
    """The "Where names live" table is the surface, not a copy that can age."""
    section = dict(_sections(TOP))["Where names live"]
    rows = dict(re.findall(r"^\| `([\w.]+)` \| (.*) \|$", section, flags=re.M))
    assert sorted(rows) == PUBLIC
    for module in PUBLIC:
        listed = re.findall(r"`([^`]+)`", rows[module])
        assert listed == sorted(importlib.import_module(module).__all__), module


def _class_constants():
    """Every public UPPER_CASE attribute of an exported class that is not an enum or an exception."""
    seen = set()
    for module in PUBLIC:
        live = importlib.import_module(module)
        for name in live.__all__:
            obj = getattr(live, name)
            if not inspect.isclass(obj) or issubclass(obj, (enum.Enum, BaseException)):
                continue
            for attribute in dir(obj):
                if attribute.isupper() and not attribute.startswith("_"):
                    seen.add((name, attribute))
    return sorted(seen)


@pytest.mark.parametrize("cls,attribute", _class_constants())
def test_every_public_class_constant_is_named_in_a_header(cls, attribute):
    text = "\n".join(_text(p) for p in [TOP] + SUBHEADERS)
    assert re.search(
        r"(?<![\w])%s(?!\w)" % re.escape(attribute), text
    ), "%s.%s is in no header" % (cls, attribute)


# -- the table of headers --------------------------------------------------------------------------


def _nearest_parent_header(path, headers):
    """The ``AGENTS.md`` of the closest directory above *path* that has one."""
    directory = PurePosixPath(path).parent
    for ancestor in directory.parents:
        candidate = (ancestor / "AGENTS.md").as_posix()
        if candidate == "AGENTS.md" or candidate in headers:
            return candidate
    return "AGENTS.md"


def _committed_headers():
    try:
        out = subprocess.run(
            ["git", "ls-files", "--", "*AGENTS.md"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [p for p in out.split() if p != "AGENTS.md"]


@pytest.mark.parametrize("path", SUBHEADERS, ids=_inside_package)
def test_every_package_header_is_in_the_top_headers_table(path):
    rows = [line for line in _lines(TOP) if line.startswith("|")]
    assert any(
        "`%s`" % _inside_package(path) in row for row in rows
    ), "%s is not named in a table row of the top header" % _inside_package(path)


def test_every_header_in_the_top_headers_table_exists():
    named = re.findall(
        r"^\| `(pydhcp/(?:[\w]+/)*AGENTS\.md)` \|", _text(TOP), flags=re.M
    )
    assert sorted(named) == sorted(
        ["pydhcp/AGENTS.md"] + [_inside_package(p) for p in SUBHEADERS]
    )


def test_a_nested_header_is_named_by_the_one_above_it():
    """`options/_codecs/AGENTS.md` is a child of `options/AGENTS.md`, which says so."""
    assert "`pydhcp/options/_codecs/AGENTS.md`" in _text(
        PACKAGE / "options" / "AGENTS.md"
    )


# -- the signature probe ---------------------------------------------------------------------------

_FENCE = re.compile(r"^```python\n(.*?)^```", re.S | re.M)
_ENTRY = re.compile(r"\A(?:async )?([A-Za-z_][\w.]*)\((.*)\)\s*(?:->.*)?\Z", re.S)

_KINDS = {
    inspect.Parameter.POSITIONAL_ONLY: "positional_only",
    inspect.Parameter.POSITIONAL_OR_KEYWORD: "positional",
    inspect.Parameter.VAR_POSITIONAL: "var_positional",
    inspect.Parameter.KEYWORD_ONLY: "keyword",
    inspect.Parameter.VAR_KEYWORD: "var_keyword",
}


def _entries(block):
    """The signatures of a fenced block: one starts at an unindented line and ends where it balances."""
    entries, current, depth = [], [], 0
    for line in block.splitlines():
        if not current and (not line.strip() or line[0] in " #"):
            continue
        current.append(line)
        depth += line.count("(") - line.count(")")
        if depth <= 0:
            entries.append("\n".join(current))
            current, depth = [], 0
    assert not current, "an unbalanced signature: %r" % current
    return entries


def _printed(args):
    """``[(name, kind, default source or None)]`` of a printed parameter list."""
    spec = ast.parse("def f(%s): pass" % " ".join(args.split())).body[0].args
    positional = spec.posonlyargs + spec.args
    defaults = [None] * (len(positional) - len(spec.defaults)) + list(spec.defaults)
    out = []
    for arg, default in zip(positional, defaults):
        kind = "positional_only" if arg in spec.posonlyargs else "positional"
        out.append((arg.arg, kind, default))
    if spec.vararg:
        out.append((spec.vararg.arg, "var_positional", None))
    for arg, default in zip(spec.kwonlyargs, spec.kw_defaults):
        out.append((arg.arg, "keyword", default))
    if spec.kwarg:
        out.append((spec.kwarg.arg, "var_keyword", None))
    return [(n, k, None if d is None else ast.unparse(d)) for n, k, d in out]


def _callee(obj):
    """What to read the signature of: for a class whose nearest constructor in its MRO is its
    own ``__init__``, that method. Python 3.9.6 reports an inherited ``__new__`` in its place,
    as ``(*args, **kwargs)``, and 3.9.10 does not (measured on both)."""
    if inspect.isclass(obj):
        for base in obj.__mro__[:-1]:
            if "__new__" in vars(base):
                break
            if "__init__" in vars(base):
                init = vars(base)["__init__"]
                return init if inspect.isfunction(init) else obj
    return obj


def _unmangled(name):
    """``_DHCPOptions__key`` is how a class body spells the positional-only ``__key``."""
    return re.sub(r"\A_[A-Za-z]\w*?__(?=\w)", "", name)


def _live(obj):
    """``[(name, kind, ("=", default) or None)]`` with ``self`` and ``cls`` dropped."""
    out = []
    for p in inspect.signature(_callee(obj)).parameters.values():
        if p.name in ("self", "cls"):
            continue
        out.append(
            (
                _unmangled(p.name),
                _KINDS[p.kind],
                None if p.default is inspect.Parameter.empty else ("=", p.default),
            )
        )
    return out


def _namespace():
    """What a printed default may name: every public module's names, the private ones headers print, ``ipaddress``."""
    import datetime
    import ipaddress

    space = {}
    for name in ("pydhcp._constants", "pydhcp._network", *reversed(PUBLIC)):
        space.update(vars(importlib.import_module(name)))
    space.update(
        {n: getattr(ipaddress, n) for n in dir(ipaddress) if not n.startswith("_")}
    )
    space.update(
        timedelta=datetime.timedelta,
        datetime=datetime.datetime,
        timezone=datetime.timezone,
    )
    return space


def _same_default(printed, live, namespace):
    if printed is None or live is None:
        return printed is None and live is None
    try:
        if bool(eval(printed, dict(namespace)) == live[1]):
            return True
    except Exception:
        pass
    # A factory or a private sentinel prints as <...>: the header says what it stands for.
    return repr(live[1]).startswith("<") or printed == repr(live[1])


def _resolve(modules, dotted):
    for module in modules:
        obj = importlib.import_module(module)
        for part in dotted.split("."):
            obj = getattr(obj, part, None)
            if obj is None:
                break
        if obj is not None:
            return module, obj
    return None, None


def _probe(text):
    """``(checked, problems)`` for every signature the fenced blocks of *text* print."""
    checked, problems = 0, []
    namespace = _namespace()
    for match in _FENCE.finditer(text):
        headings = re.findall(r"^## (.*)$", text[: match.start()], flags=re.M)
        modules = _heading_modules(headings[-1]) if headings else []
        if not modules:
            problems.append(
                "a signature block under no heading that names its import path"
            )
            continue
        for entry in _entries(match.group(1)):
            parsed = _ENTRY.match(entry)
            if parsed is None:
                problems.append("not a signature: %s" % " ".join(entry.split()))
                continue
            name, args = parsed.groups()
            module, obj = _resolve(modules, name)
            if obj is None:
                problems.append("%s does not exist in %s" % (name, ", ".join(modules)))
                continue
            checked += 1
            try:
                printed, live = _printed(args), _live(obj)
            except (SyntaxError, ValueError, TypeError) as exc:
                problems.append("%s: %s" % (name, exc))
                continue
            same = len(printed) == len(live) and all(
                p[0] == l[0] and p[1] == l[1] and _same_default(p[2], l[2], namespace)
                for p, l in zip(printed, live)
            )
            if not same:
                problems.append("%s(%s)" % (name, " ".join(args.split())))
    return checked, problems


def test_every_printed_signature_is_the_live_one():
    checked, bad = 0, []
    for path in [TOP] + SUBHEADERS:
        n, problems = _probe(_text(path))
        checked += n
        bad.extend("%s: %s" % (_inside_package(path), p) for p in problems)
    assert not bad, "signature drift:\n" + "\n".join(bad)
    # A probe that matched nothing would pass whatever the headers say.
    assert checked >= 150, checked


def test_the_probe_sees_a_changed_default():
    text = (
        "## Client (`pydhcp.client`)\n\n```python\n"
        "DHCPClient(listen=None, *, poll_interval=None)\n"
        "DHCPClient(listen=None, *, poll_interval=2.0)\n"
        "```\n"
    )
    checked, bad = _probe(text)
    assert (
        checked == 2 and len(bad) == 2
    )  # the short list, and a default that is not the live one


def test_the_probe_sees_a_missing_keyword_only_star_and_a_wrong_name():
    text = (
        "## Server (`pydhcp.server`)\n\n```python\n"
        "DHCPServer(listen=None, poll_interval=None)\n"
        "DHCPServer(listening=None)\n"
        "DHCPServer.acquire_lease(client_id, server_id, msg, commit=True)\n"
        "```\n"
    )
    checked, bad = _probe(text)
    assert checked == 3 and len(bad) == 3


def test_the_probe_refuses_a_block_under_no_import_path():
    checked, bad = _probe("## Gotchas\n\n```python\nDHCPClient(listen=None)\n```\n")
    assert checked == 0 and bad


def test_the_probe_sees_a_name_that_does_not_exist():
    checked, bad = _probe(
        "## Client (`pydhcp.client`)\n\n```python\nNoSuchThing(a)\n```\n"
    )
    assert checked == 0 and "does not exist" in bad[0]


def test_the_probe_reads_a_name_mangled_positional_parameter():
    text = "## Container (`pydhcp.options`)\n\n```python\nDHCPOptions.get(key, default=None, decode=True)\n```\n"
    assert _probe(text) == (1, [])


def test_the_signatures_the_old_check_pinned_are_still_printed():
    """The five client builders each have an entry of their own, and so does every role's constructor."""
    printed = set()
    for path in [TOP] + SUBHEADERS:
        for match in _FENCE.finditer(_text(path)):
            printed |= {_ENTRY.match(e).group(1) for e in _entries(match.group(1))}
    builders = {
        "DHCPClient.build_" + n
        for n in ("discover", "request", "inform", "release", "decline")
    }
    constructors = {
        "DHCPListener",
        "AsyncDHCPListener",
        "DHCPServer",
        "AsyncDHCPServer",
        "DHCPRelay",
        "AsyncDHCPRelay",
        "DHCPCapture",
        "AsyncDHCPCapture",
        "DHCPClient",
        "FileLeaseBackend",
        "SocketAddress",
    }
    assert builders | constructors <= printed, sorted(
        (builders | constructors) - printed
    )


# -- the wheel and the sdist -------------------------------------------------------------------


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """The wheel and the sdist the backend builds from this tree, as lists of member names."""
    builders = pytest.importorskip("hatchling.builders.wheel")
    sdist_builders = pytest.importorskip("hatchling.builders.sdist")
    out = tmp_path_factory.mktemp("dist")
    wheel = next(
        iter(
            builders.WheelBuilder(str(ROOT)).build(
                directory=str(out), versions=["standard"]
            )
        )
    )
    sdist = next(
        iter(
            sdist_builders.SdistBuilder(str(ROOT)).build(
                directory=str(out), versions=["standard"]
            )
        )
    )
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
    with tarfile.open(sdist) as archive:
        sdist_names = [
            name.split("/", 1)[1] for name in archive.getnames() if "/" in name
        ]
    return wheel_names, sdist_names


def test_every_header_is_inside_the_built_wheel(built):
    wheel, _ = built
    shipped = sorted(n for n in wheel if n.endswith("AGENTS.md"))
    assert shipped == sorted(
        ["pydhcp/AGENTS.md"] + [_inside_package(p) for p in SUBHEADERS]
    )


def test_the_sdist_ships_the_headers_and_leaves_out_the_root_file(built):
    _, sdist = built
    assert "AGENTS.md" not in sdist
    shipped = sorted(
        n for n in sdist if n.startswith("src/pydhcp/") and n.endswith("AGENTS.md")
    )
    assert shipped == sorted("src/" + _inside_package(p) for p in [TOP] + SUBHEADERS)
