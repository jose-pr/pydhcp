"""The command line's contract: one entry point, honest statuses, help for every option.

`main(argv) -> int` never exits by itself: 0 is success, 1 a run that failed, 2 a
wrong invocation. Each case goes through the real parser; what only a process
shows (the status of `python -m pydhcp`, standard output against standard error)
is run as a process.
"""

from __future__ import annotations

import ast
import errno
import importlib.metadata
import inspect
import io
import json
import pathlib
import typing as _ty

import pytest

import pydhcp.cli
from cli_process import run_cli
from pydhcp.cli import main

CLI_SOURCES = [
    path
    for path in sorted(pathlib.Path(pydhcp.cli.__file__).parent.glob("*.py"))
    if path.name != "__main__.py"
]


def test_main_takes_an_argument_vector_and_returns_the_status() -> None:
    parameters = inspect.signature(main).parameters
    assert list(parameters) == ["argv"]
    assert parameters["argv"].default is None
    assert inspect.signature(main).return_annotation in (int, "int")


def test_the_version_option_returns_zero_without_exiting(capsys) -> None:
    try:
        importlib.metadata.version("pydhcp")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("--version needs installed package metadata")

    assert main(["--version"]) == 0

    assert capsys.readouterr().out.startswith("pydhcp ")


def test_no_command_module_exits_by_itself() -> None:
    """A command returns or raises; only `__main__` turns a status into an exit."""
    offenders = []
    for path in CLI_SOURCES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if name in ("sys.exit", "exit", "quit", "os._exit"):
                    offenders.append(f"{path.name}: {name}")
            if isinstance(node, ast.Raise) and node.exc is not None:
                if ast.unparse(node.exc).startswith("SystemExit"):
                    offenders.append(f"{path.name}: raise SystemExit")
    assert offenders == []


def test_a_relay_without_a_server_is_a_wrong_invocation(capsys) -> None:
    assert main(["relay", "--listen", "127.0.0.1:0"]) == 2

    err = capsys.readouterr().err
    assert "--server" in err
    assert "Starting" not in err


def test_a_malformed_listen_is_refused_before_anything_is_announced(
    caplog, capsys
) -> None:
    caplog.set_level("DEBUG")

    assert main(["server", "--listen", "127.0.0.1:notaport", "-v"]) == 2

    assert "Starting" not in caplog.text + capsys.readouterr().err


def test_a_packet_that_cannot_be_decoded_is_a_failed_run_not_a_wrong_invocation(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("00"))

    assert main(["packet", "--decode"]) == 1
    assert "pydhcp: error:" in capsys.readouterr().err


def test_summary_output_is_decode_only_and_that_is_a_wrong_invocation(capsys) -> None:
    assert main(["packet", "--encode", "--format", "summary"]) == 2
    assert "--decode" in capsys.readouterr().err


def test_a_usage_error_returns_the_parsers_status(capsys) -> None:
    assert main(["no-such-command"]) == 2
    assert "usage: pydhcp" in capsys.readouterr().err


def test_the_process_exits_with_the_status() -> None:
    wrong = run_cli("relay", "--listen", "127.0.0.1:0")
    assert wrong.returncode == 2
    assert "--server" in wrong.stderr
    assert "Traceback" not in wrong.stderr
    assert wrong.stdout == ""

    listed = run_cli("interfaces", "--format", "json")
    assert listed.returncode == 0
    assert isinstance(json.loads(listed.stdout), list)
    assert listed.stderr == ""


def test_the_root_reads_the_tool_server_variable_and_four_commands_are_not_tools() -> (
    None
):
    """`PYDHCP_MCP=stdio` serves `packet` and `interfaces`; the commands that do not
    return, start programs or send datagrams leave themselves out."""
    assert pydhcp.cli.App._mcp_ is True
    left_out = {
        str(command._parsername_)
        for command in pydhcp.cli.App._subcommands_ or ()
        if getattr(command, "_mcp_", True) is False
    }
    assert left_out == {"server", "relay", "capture", "replay"}


# -- interfaces and packet output -------------------------------------------------


def _rows() -> "list[dict[str, object]]":
    """What the host's own enumeration says, in the order and form the command prints."""
    # the enumeration the command prints is not public
    from pydhcp._network import host_ip_interfaces

    return [
        {
            "name": i.name,
            "ip": str(i.ip),
            "mac": i.mac.format("-", upper=True) if i.mac else None,
            "network": str(i.network),
        }
        for i in host_ip_interfaces()
    ]


def test_interfaces_text_is_one_line_per_address_and_no_banner(capsys) -> None:
    rows = _rows()
    assert any(row["ip"] == "127.0.0.1" for row in rows)

    assert main(["interfaces"]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert [line.split("	") for line in lines] == [
        [str(value or "-") for value in row.values()] for row in rows
    ]


def test_interfaces_json_is_one_array(capsys) -> None:
    rows = _rows()

    assert main(["interfaces", "--format", "json"]) == 0

    assert json.loads(capsys.readouterr().out) == rows


@pytest.mark.parametrize("error", [BrokenPipeError(), OSError(errno.EINVAL, "closed")])
def test_a_closed_stdout_ends_the_command_quietly(monkeypatch, capsys, error) -> None:
    """Nobody reads the output any more: no traceback, no message, status 1."""

    class Closed(io.StringIO):
        def write(self, text: str) -> int:
            raise error

    monkeypatch.setattr("sys.stdout", Closed())

    assert main(["interfaces"]) == 1

    assert capsys.readouterr().err == ""


# -- help ---------------------------------------------------------------------------


def _options(
    node: "dict[str, _ty.Any]", path: str = "pydhcp"
) -> "_ty.Iterator[tuple[str, dict[str, _ty.Any]]]":
    for option in node["options"]:
        yield path, option
    for child in node.get("subcommands", []):
        yield from _options(child, f"{path} {child['name']}")


def test_every_option_of_every_command_has_help_text() -> None:
    result = run_cli("--help", env={"AGENT_HELP": "1"})
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)

    empty = [
        f"{path}: {' '.join(option['names'])}"
        for path, option in _options(document)
        if not (option.get("help") or "").strip()
    ]
    assert empty == []


def test_the_filter_option_shows_a_metavar_that_is_not_a_field_name() -> None:
    result = run_cli("capture", "--help")
    assert "PACKET_FILTER" not in result.stdout
    assert "--filter EXPRESSION" in result.stdout


def test_no_module_of_the_command_line_is_over_200_lines() -> None:
    """A command that needs more holds logic that belongs in the library."""
    import pathlib

    import pydhcp.cli

    root = pathlib.Path(pydhcp.cli.__file__).parent
    long = {
        path.name: len(path.read_text(encoding="utf-8").splitlines())
        for path in root.glob("*.py")
    }
    assert {name: n for name, n in long.items() if n > 200} == {}


def test_the_command_line_package_exports_commands_and_main_only() -> None:
    import pydhcp.cli as cli

    assert sorted(cli.__all__) == [
        "App",
        "Capture",
        "Interfaces",
        "Packet",
        "Relay",
        "Replay",
        "Server",
        "main",
    ]
