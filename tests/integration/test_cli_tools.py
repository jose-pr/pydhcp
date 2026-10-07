"""The command line served as tools: `packet` and `interfaces`, no other command.

`server`, `relay`, `capture` and `replay` do not return until stopped, start a
program per packet or put datagrams on a network, so none is a tool. The tools
are listed in this process; the server run is `PYDHCP_MCP=stdio` in a child
process, which a client talks to over its standard input and output.
"""

from __future__ import annotations

import json
import pathlib
import typing as _ty

import pytest

from cli_process import run_cli
from helpers import build_request

duho_mcp = pytest.importorskip("duho.mcp")

from pydhcp.cli import App  # noqa: E402

TOOLS = {"pydhcp.interfaces", "pydhcp.packet"}


def _hex() -> str:
    return bytes(build_request().encode()).hex()


def _tool_names() -> "set[str]":
    return {tool["name"] for tool in duho_mcp.describe_tools(App)}


def _talk(*requests: "dict[str, _ty.Any]") -> "list[dict[str, _ty.Any]]":
    """The replies of `pydhcp` served over stdio to `requests`, one per request."""
    lines = [
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        *requests,
    ]
    done = run_cli(
        input="".join(json.dumps(line) + "\n" for line in lines),
        env={"PYDHCP_MCP": "stdio"},
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    replies = [json.loads(text) for text in done.stdout.splitlines() if text.strip()]
    return replies[1:]


def test_the_served_tools_are_packet_and_interfaces_only() -> None:
    assert _tool_names() == TOOLS


@pytest.mark.parametrize("command", ["server", "relay", "capture", "replay"])
def test_a_command_that_does_not_return_or_sends_is_not_a_tool(command: str) -> None:
    assert f"pydhcp.{command}" not in _tool_names()
    # Still a command of the program.
    assert command in {str(c._parsername_) for c in App._subcommands_ or ()}


def test_every_field_of_a_tool_says_what_it_is() -> None:
    for tool in duho_mcp.describe_tools(App):
        for name, schema in tool["inputSchema"]["properties"].items():
            assert schema.get("description"), (tool["name"], name)


def test_the_files_a_packet_tool_reads_and_writes_say_what_omitting_them_means() -> (
    None
):
    (packet,) = (
        t for t in duho_mcp.describe_tools(App) if t["name"] == "pydhcp.packet"
    )
    fields = packet["inputSchema"]["properties"]
    assert "standard input" in fields["input"]["description"]
    assert "standard output" in fields["output"]["description"]


def test_packet_decode_called_as_a_tool_returns_the_message(
    tmp_path: pathlib.Path,
) -> None:
    source = tmp_path / "message.hex"
    source.write_text(_hex(), encoding="utf-8")

    result = duho_mcp.call_tool(
        App, "pydhcp.packet", {"decode": True, "input": str(source)}
    )

    assert not result.get("isError"), result
    text = "".join(part["text"] for part in result["content"])
    assert json.loads(text)["op"] == "BOOTREQUEST"


def test_a_tool_call_that_names_no_input_refuses_instead_of_waiting_on_stdin() -> None:
    result = duho_mcp.call_tool(App, "pydhcp.packet", {"decode": True})

    assert result["isError"] is True
    text = "".join(part["text"] for part in result["content"])
    assert "--input" in text and "standard input" in text


def test_packet_without_input_on_a_terminal_less_stdin_names_the_option() -> None:
    done = run_cli("packet", "--decode")

    assert done.returncode == 1
    assert "--input" in done.stderr and "standard input" in done.stderr


def test_the_variable_serves_exactly_those_tools_over_stdio() -> None:
    (listing,) = _talk({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    served = {tool["name"] for tool in listing["result"]["tools"]}
    assert served == TOOLS


def test_a_command_that_is_not_a_tool_is_refused_over_stdio() -> None:
    (reply,) = _talk(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "pydhcp.server", "arguments": {}},
        }
    )

    assert "error" in reply or reply["result"].get("isError")


def test_without_the_variable_the_command_line_behaves_as_before() -> None:
    done = run_cli("interfaces", "--format", "json")

    assert done.returncode == 0
    assert isinstance(json.loads(done.stdout), list)
