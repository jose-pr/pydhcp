"""The README keeps the standard's shape, and what it shows runs.

The Python blocks of the README and of the docs landing page are executed as written
with only the addresses substituted: the wildcard becomes a loopback socket, the
example ports become ports this test holds, and a call that would serve for ever
starts the server instead. The command lines are run by
`integration/test_documented_commands.py`.
"""

from __future__ import annotations

import pathlib
import re
import sys
import typing as _ty

import pytest

from cli_process import free_port
from helpers import FixedLeaseServer, running
from pydhcp.listener import DHCPListener
from test_surface import SURFACE

if sys.version_info >= (3, 11):
    import tomllib
else:
    tomllib = pytest.importorskip("tomli")

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PAGES = [README, ROOT / "docs" / "index.md"]
TEXT = README.read_text(encoding="utf-8")

PYTHON = re.compile(r"```python\n(.*?)```", re.S)
BLOCKS = [
    pytest.param(page, number, code, id=f"{page.name}[{number}]")
    for page in PAGES
    for number, code in enumerate(PYTHON.findall(page.read_text(encoding="utf-8")))
]

DIST = "pydhcp"
REPO = "jose-pr/pydhcp"
BADGES = [
    f"[![Version](https://img.shields.io/pypi/v/{DIST}.svg)](https://pypi.org/project/{DIST}/)",
    f"[![Python versions](https://img.shields.io/pypi/pyversions/{DIST}.svg)](https://pypi.org/project/{DIST}/)",
    f"[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/{REPO}/blob/main/LICENSE)",
    "[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/pydhcp/)",
    f"[![CI](https://img.shields.io/github/actions/workflow/status/{REPO}/test.yml)](https://github.com/{REPO}/actions/workflows/test.yml)",
]
SECTIONS = [
    "Features",
    "Installation",
    "Quick start",
    "Command line",
    "API overview",
    "Differences from dnsmasq and ISC dhclient",
    "Development",
    "License",
]


# -- the shape ---------------------------------------------------------------------------


def test_the_title_is_the_distribution_name_and_the_badges_follow_it() -> None:
    lines = TEXT.splitlines()
    assert lines[0] == f"# {DIST}"
    assert lines[2:7] == BADGES
    assert lines[7] == ""


def test_the_sections_are_the_standards_in_its_order() -> None:
    assert re.findall(r"^## (.*)$", TEXT, re.M) == SECTIONS


def test_the_opening_names_the_promise_in_bold_and_links_the_docs() -> None:
    opening = TEXT.split("## Features", 1)[0].split(BADGES[-1], 1)[1]
    assert re.search(r"\*\*[^*]+\*\*", opening)
    assert "https://jose-pr.github.io/pydhcp/" in opening


def test_every_link_is_absolute() -> None:
    assert re.findall(r"\]\((?!https?://)([^)]*)\)", TEXT) == []


def test_the_extras_table_lists_every_extra_the_manifest_declares() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        declared = set(tomllib.load(handle)["project"]["optional-dependencies"])
    section = TEXT.split("## Installation", 1)[1].split("## Quick start", 1)[0]
    listed = set(re.findall(r"^\| `(\w+)` \|", section, re.M))
    assert listed == declared - {"dev", "docs"}


def test_the_api_overview_names_every_public_module() -> None:
    section = TEXT.split("## API overview", 1)[1].split("## Development", 1)[0]
    public = {
        name
        for name in SURFACE
        if name != "pydhcp"
        and not any(part.startswith("_") for part in name.split("."))
    }
    assert (
        public and [name for name in sorted(public) if f"`{name}`" not in section] == []
    )


# -- the Python blocks run ---------------------------------------------------------------


def _on_loopback(code: str, server_port: int, client_port: int) -> str:
    """The block with the wildcard and the example ports pointed at loopback."""
    code = code.replace('listen="*"', 'listen="127.0.0.1:0"')
    code = re.sub(
        r"\b(DHCPServer|AsyncDHCPServer)\(\)", r'\1(listen="127.0.0.1:0")', code
    )
    code = code.replace("[6767, 6768]", "[0, 0]")
    code = code.replace('("127.0.0.1", 6768)', '("127.0.0.1", %d)' % client_port)
    code = code.replace("port=6767", "port=%d" % server_port)
    # A loopback exchange stays unicast: a broadcast reply would leave the host.
    code = re.sub(r"(\.build_discover\([^()]*)\)", r"\1, broadcast=False)", code)
    code = code.replace(
        'destination="127.0.0.1"', 'destination="127.0.0.1", broadcast=False'
    )
    return code.replace("serve_forever()", "start()")


def test_there_are_python_blocks_to_run() -> None:
    assert len(BLOCKS) >= 10


@pytest.mark.parametrize("page, number, code", BLOCKS)
def test_a_python_block_runs_as_written(
    page: pathlib.Path, number: int, code: str
) -> None:
    server_port, client_port = free_port(), free_port()
    ready = _on_loopback(code, server_port, client_port)
    left = [
        text for text in ('listen="*"', "6767", "6768", "Server()") if text in ready
    ]
    assert left == [], f"an example address would reach the network: {left}"
    with running(FixedLeaseServer(listen=[("127.0.0.1", server_port)])) as peer:
        # The client in the example sits on an ephemeral port, not 68.
        peer.REPLY_TO_CLIENT_PORT = client_port
        namespace: "dict[str, _ty.Any]" = {"__name__": "readme_block"}
        try:
            exec(
                compile(ready, f"{page.name} python block {number}", "exec"), namespace
            )
        finally:
            for value in list(namespace.values()):
                if isinstance(value, DHCPListener):
                    value.close()


def test_the_packet_block_rebuilds_what_it_wrote() -> None:
    block = next(code for code in PYTHON.findall(TEXT) if "DHCPMessage.decode" in code)
    namespace: "dict[str, _ty.Any]" = {}
    exec(compile(block, "README.md packet block", "exec"), namespace)
    assert len(namespace["wire"]) == 300
    assert namespace["again"].message_type.name == "DHCPDISCOVER"
