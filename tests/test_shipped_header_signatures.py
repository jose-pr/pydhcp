"""The shipped header's signatures must match the code (`docs-drift-6`).

`src/pydhcp/AGENTS.md` is the API header a consuming agent reads *instead of*
the source, so a signature that drifts there is worse than an undocumented one:
it is confidently wrong. It had collapsed the five `DHCPClient.build_*`
builders into a single signature that was wrong for three of them — it offered
`broadcast` to builders that do not take it, and omitted the required
keyword-only argument that each of those three does.

This checks the header against `inspect.signature`, so the next drift fails a
test rather than waiting for the next review.
"""

import inspect
import pathlib
import re

import pytest

from pydhcp.client import DHCPClient

HEADER = pathlib.Path(__file__).resolve().parents[1] / "src" / "pydhcp" / "AGENTS.md"

BUILDERS = [
    "build_discover",
    "build_request",
    "build_inform",
    "build_release",
    "build_decline",
]


@pytest.fixture(scope="module")
def header_text() -> str:
    return HEADER.read_text(encoding="utf-8")


def _required_keyword_only(name: str) -> set:
    params = inspect.signature(getattr(DHCPClient, name)).parameters
    return {
        p.name
        for p in params.values()
        if p.kind is p.KEYWORD_ONLY and p.default is inspect.Parameter.empty
    }


def _accepts(name: str, arg: str) -> bool:
    return arg in inspect.signature(getattr(DHCPClient, name)).parameters


@pytest.mark.parametrize("name", BUILDERS)
def test_the_header_documents_each_builder_separately(name, header_text) -> None:
    """One signature for five builders cannot be right when three differ."""
    assert (
        f".{name}(chaddr" in header_text
    ), f"{name} has no signature of its own in the shipped header"


@pytest.mark.parametrize("name", BUILDERS)
def test_the_header_names_every_required_keyword_only_argument(
    name, header_text
) -> None:
    required = _required_keyword_only(name)
    # The documented signature for this builder, up to its closing paren.
    m = re.search(rf"\.{name}\((.*?)\) -> DHCPMessage", header_text, re.S)
    assert m, f"no documented signature for {name}"
    documented = m.group(1)
    for arg in required:
        assert (
            arg in documented
        ), f"{name} requires keyword-only {arg!r} and the header does not say so"


@pytest.mark.parametrize("name", BUILDERS)
def test_the_header_offers_broadcast_only_where_it_exists(name, header_text) -> None:
    """The specific error this test exists for: `broadcast=True` was documented
    on all five; only two take it."""
    m = re.search(rf"\.{name}\((.*?)\) -> DHCPMessage", header_text, re.S)
    assert m, f"no documented signature for {name}"
    documented_broadcast = "broadcast" in m.group(1)
    assert documented_broadcast == _accepts(name, "broadcast"), (
        f"header {'offers' if documented_broadcast else 'omits'} `broadcast` for "
        f"{name}, but the code {'accepts' if _accepts(name, 'broadcast') else 'does not'}"
    )


# --- every documented constructor ---

HEADERS = sorted(HEADER.parent.rglob("AGENTS.md"))
_CONSTRUCTOR = re.compile(r"\*\*`(\w+)\(([^`]*)\)`\*\*")
_MODULES = (
    "pydhcp",
    "pydhcp.listener",
    "pydhcp.server",
    "pydhcp.relay",
    "pydhcp.capture",
    "pydhcp.client",
    "pydhcp.lease",
)


def _resolve(name: str) -> "type | None":
    import importlib

    for module in _MODULES:
        found = getattr(importlib.import_module(module), name, None)
        if inspect.isclass(found):
            return found
    return None


def _documented_parameters(text: str) -> "list[str]":
    """Names in order, with `*` where the header marks the keyword-only start."""
    parts, depth, current = [], 0, ""
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return [part.strip().split("=")[0].strip() for part in parts if part.strip()]


def _documented_constructors() -> "list[tuple[str, str, type]]":
    found = []
    for path in HEADERS:
        for name, signature in _CONSTRUCTOR.findall(path.read_text(encoding="utf-8")):
            cls = _resolve(name)
            if cls is not None and ("__init__" in vars(cls) or "__new__" in vars(cls)):
                found.append((path.parent.name, name, signature, cls))
    return [(f"{p}/{n}", s, c) for p, n, s, c in found]


_CONSTRUCTORS = _documented_constructors()


def test_the_header_documents_the_roles_constructors() -> None:
    names = {entry[0].split("/")[1] for entry in _CONSTRUCTORS}
    assert {
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
    } <= names


@pytest.mark.parametrize(
    "label, signature, cls", _CONSTRUCTORS, ids=[c[0] for c in _CONSTRUCTORS]
)
def test_a_documented_constructor_matches_inspect_signature(
    label, signature, cls
) -> None:
    actual = []
    for parameter in inspect.signature(cls).parameters.values():
        if parameter.kind is parameter.KEYWORD_ONLY and "*" not in actual:
            actual.append("*")
        actual.append(parameter.name)
    assert _documented_parameters(signature) == actual, label
