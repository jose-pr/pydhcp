"""`pydhcp server --listen` and the `listen` key of a configuration file, on real sockets.

The grammar itself is a table in `tests/test_listen_grammar.py`, run against the
parser and the constructors. These tests are that the command reads the same text
from its flag and from each file format and binds what the table says: the rows
with an explicit port are run with the port rewritten to one that is free, and
the rows that name no port (67 and 68 are not ours to bind) stay in the table.
A refused form fails before anything is bound.
"""

from __future__ import annotations

import json
import typing as ty

import pytest

from cli_process import free_port
from command_run import run_command
from helpers import LOOPBACK_ALIAS_BINDABLE
from pydhcp import SocketAddress

# the grammar's own tables
from test_listen_grammar import ACCEPTED, REFUSED, _addresses, _ids

#: The example ports of the tables, each standing for a free one.
EXAMPLE_PORTS = (6767, 6768, 6769)


def _ports() -> "dict[int, int]":
    return {example: free_port() for example in EXAMPLE_PORTS}


def _usable(addresses: "list[SocketAddress]") -> bool:
    """Can this host bind every address of a row on a port of its own choosing?"""
    for address in addresses:
        if address.port not in (0, *EXAMPLE_PORTS):
            return False
        text = str(address.ip)
        if text not in ("127.0.0.1", "0.0.0.0") and not (
            text == "127.0.0.2" and LOOPBACK_ALIAS_BINDABLE
        ):
            return False
    return True


def _rewrite(text: str, ports: "dict[int, int]") -> str:
    for example, free in ports.items():
        text = text.replace(str(example), str(free))
    return text


def _matches(
    bound: "list[str]", expected: "list[SocketAddress]", ports: "dict[int, int]"
) -> bool:
    wanted = [(str(a.ip), ports.get(a.port, a.port)) for a in expected]
    got = [(b.rsplit(":", 1)[0], int(b.rsplit(":", 1)[1])) for b in bound]
    return len(got) == len(wanted) and all(
        g[0] == w[0] and (w[1] == 0 or g[1] == w[1]) for g, w in zip(got, wanted)
    )


def _write(path: ty.Any, name: str, text: str) -> str:
    target = path / name
    target.write_text(text, encoding="utf-8")
    return str(target)


# -- the flag -----------------------------------------------------------------------

TEXT_ROWS = [
    row
    for row in ACCEPTED
    if isinstance(row[0], str) and row[0].strip() and _usable(row[1])
]


@pytest.mark.parametrize("spec, expected", TEXT_ROWS, ids=_ids(TEXT_ROWS))
def test_the_listen_flag_binds_what_the_table_says(
    spec: str, expected: "list[SocketAddress]"
) -> None:
    ports = _ports()

    ran = run_command(
        ["server", "-v", f"--listen={_rewrite(spec, ports)}"], bound=len(expected)
    )

    assert ran.status == 0
    assert _matches(ran.bound, expected, ports), (ran.bound, expected)


@pytest.mark.parametrize(
    "spec", [r[0] for r in REFUSED if isinstance(r[0], str)], ids=repr
)
def test_the_listen_flag_refuses_the_same_text(spec: str) -> None:
    ran = run_command(["server", "-v", f"--listen={spec}"])

    assert ran.status == 2
    assert ran.bound == []


def test_an_empty_listen_flag_is_an_error_not_the_wildcard(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.delenv("PYDHCP_TRACEBACK", raising=False)

    ran = run_command(["server", "-v", "--listen", ""])

    assert ran.status == 2 and ran.bound == []
    err = capsys.readouterr().err
    assert err.startswith("pydhcp: error:") and "names no address" in err
    assert "Traceback" not in err


# -- the configuration file -----------------------------------------------------------

#: One value of the `listen` key in each file format, and what it must name.
FILES: "list[tuple[str, str, str, list[SocketAddress]]]" = [
    (
        "json",
        "c.json",
        json.dumps({"server": {"listen": ["127.0.0.1", 6767]}}),
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "json text port",
        "c.json",
        json.dumps({"server": {"listen": ["127.0.0.1", "6767"]}}),
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "json list of pairs",
        "c.json",
        json.dumps({"server": {"listen": [["127.0.0.1", 6767], ["127.0.0.2", 6768]]}}),
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
    (
        "json ports",
        "c.json",
        json.dumps({"server": {"listen": ["127.0.0.1", [6767, 6768]]}}),
        _addresses(("127.0.0.1", 6767), ("127.0.0.1", 6768)),
    ),
    (
        "json null host",
        "c.json",
        json.dumps({"server": {"listen": [None, 6767]}}),
        _addresses(("0.0.0.0", 6767)),
    ),
    (
        "yaml",
        "c.yaml",
        "server:\n  listen: [127.0.0.1, 6767]\n",
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "yaml text",
        "c.yaml",
        "server:\n  listen: 127.0.0.1:6767\n",
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "yaml block list",
        "c.yaml",
        "server:\n  listen:\n    - 127.0.0.1:6767\n    - [127.0.0.2, 6768]\n",
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
    (
        "toml",
        "c.toml",
        '[server]\nlisten = ["127.0.0.1", 6767]\n',
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "toml text",
        "c.toml",
        '[server]\nlisten = "127.0.0.1:6767"\n',
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "ini",
        "c.ini",
        "[server]\nlisten = 127.0.0.1:6767,127.0.0.2:6768\n",
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
]

BAD_FILES: "list[tuple[str, str, str]]" = [
    ("json empty", "c.json", json.dumps({"server": {"listen": ""}})),
    ("json empty list", "c.json", json.dumps({"server": {"listen": []}})),
    (
        "json bool port",
        "c.json",
        json.dumps({"server": {"listen": ["127.0.0.1", True]}}),
    ),
    ("json bare number", "c.json", json.dumps({"server": {"listen": 6767}})),
    ("yaml bool port", "c.yaml", "server:\n  listen: [127.0.0.1, true]\n"),
    ("yaml bare number", "c.yaml", "server:\n  listen: 6767\n"),
    ("yaml empty", "c.yaml", "server:\n  listen: ''\n"),
    ("toml bool port", "c.toml", '[server]\nlisten = ["127.0.0.1", true]\n'),
    ("toml empty", "c.toml", '[server]\nlisten = ""\n'),
    ("toml bad port", "c.toml", '[server]\nlisten = ["127.0.0.1", 70000]\n'),
    ("ini bad port", "c.ini", "[server]\nlisten = 127.0.0.1:+67\n"),
]


def _skip_without_the_format(name: str) -> None:
    if name.endswith(".yaml"):
        pytest.importorskip("yaml")
    if name.endswith(".toml"):
        import sys

        pytest.importorskip("tomli" if sys.version_info < (3, 11) else "tomllib")


FILE_ROWS = [row for row in FILES if _usable(row[3])]


@pytest.mark.parametrize(
    "label, name, text, expected", FILE_ROWS, ids=[f[0] for f in FILE_ROWS]
)
def test_a_configuration_file_listen_binds_what_the_table_says(
    label: str,
    name: str,
    text: str,
    expected: "list[SocketAddress]",
    tmp_path: ty.Any,
) -> None:
    _skip_without_the_format(name)
    ports = _ports()
    path = _write(tmp_path, name, _rewrite(text, ports))

    ran = run_command(["server", "-v", "--config", path], bound=len(expected))

    assert ran.status == 0
    assert _matches(ran.bound, expected, ports), (ran.bound, expected)


@pytest.mark.parametrize("label, name, text", BAD_FILES, ids=[f[0] for f in BAD_FILES])
def test_a_configuration_file_with_a_refused_listen_fails_before_binding(
    label: str, name: str, text: str, tmp_path: ty.Any
) -> None:
    _skip_without_the_format(name)
    path = _write(tmp_path, name, text)

    ran = run_command(["server", "-v", "--config", path])

    assert ran.status == 2
    assert ran.bound == []


@pytest.mark.skipif(
    not LOOPBACK_ALIAS_BINDABLE,
    reason="needs a second loopback address; this host binds only 127.0.0.1",
)
def test_the_flag_beats_a_list_in_the_file(tmp_path: ty.Any) -> None:
    ports = _ports()
    path = _write(
        tmp_path,
        "c.json",
        json.dumps({"server": {"listen": ["127.0.0.1", ports[6767]]}}),
    )

    ran = run_command(
        ["server", "-v", "--listen", f"127.0.0.2:{ports[6768]}", "--config", path]
    )

    assert ran.bound == [f"127.0.0.2:{ports[6768]}"]
