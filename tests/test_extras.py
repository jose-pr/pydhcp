"""The optional dependencies: nothing loads one until it is used, and one that is
missing is an error that names the extra to install.

A missing dependency is simulated inside the test, with `sys.modules[name] = None`
(an import of the name then fails) or a finder in a child process; the installed
package is never removed. The clean-environment proof, with the dependencies
really absent, is the `bare` job of the test workflow.
"""

from __future__ import annotations

import json
import pathlib
import sys
import textwrap
import typing as _ty

import pytest

from cli_process import run_cli
from helpers import build_request
from pydhcp import DHCPConfigError, DHCPMessage
from pydhcp.cli import main
from pydhcp.packet import DHCPMessageType

# the loader behind the command line is not public
from pydhcp._config import load_config

#: Everything an extra installs.
OPTIONAL = ("yaml", "tomllib", "tomli", "tomli_w", "duho", "pktcap")


def _block(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    for name in names:
        monkeypatch.setitem(sys.modules, name, None)


def _the_command_for(extra: str) -> str:
    return f'pip install "pydhcp[{extra}]"'


def _message() -> DHCPMessage:
    return build_request(DHCPMessageType.DHCPDISCOVER)


# -- a missing dependency, by what asked for it -------------------------------------


PKTCAP_LINE = (
    "a message as YAML, TOML or INI text needs the 'pktcap' extra: "
    + 'pip install "pydhcp[pktcap]"'
)


@pytest.mark.parametrize("fmt", ["yaml", "toml", "ini"])
def test_text_beyond_json_without_pktcap_names_the_pktcap_extra(
    monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    _block(monkeypatch, "pktcap")

    with pytest.raises(ImportError) as written:
        _message().to_text(fmt)
    with pytest.raises(ImportError) as read:
        DHCPMessage.from_text("op = 'BOOTREQUEST'\n", fmt)

    assert str(written.value) == PKTCAP_LINE
    assert str(read.value) == PKTCAP_LINE


def test_yaml_text_without_pyyaml_names_the_yaml_extra_of_pktcap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pktcap's own line is passed through: the format library is pktcap's extra."""
    pytest.importorskip("pktcap")
    _block(monkeypatch, "yaml")

    with pytest.raises(ImportError) as written:
        _message().to_text("yaml")
    with pytest.raises(ImportError) as read:
        DHCPMessage.from_text("op: BOOTREQUEST\n", "yaml")

    assert 'pip install "pktcap[yaml]"' in str(written.value)
    assert 'pip install "pktcap[yaml]"' in str(read.value)


def test_toml_text_without_a_writer_names_the_toml_extra_of_pktcap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("pktcap")
    _block(monkeypatch, "tomli_w")

    with pytest.raises(ImportError) as error:
        _message().to_text("toml")

    assert 'pip install "pktcap[toml]"' in str(error.value)


def test_json_text_needs_no_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    _block(monkeypatch, *OPTIONAL)

    text = _message().to_text("json")

    assert DHCPMessage.from_text(text, "json").to_mapping() == _message().to_mapping()


@pytest.mark.parametrize(
    "name, text, blocked, extra",
    [
        ("c.toml", "[server]\n", ("tomllib", "tomli"), "duho[config]"),
        ("c.yaml", "server: {}\n", ("yaml",), "duho[yaml]"),
    ],
)
def test_a_file_that_needs_a_missing_extra_is_a_configuration_error(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    text: str,
    blocked: "_ty.Tuple[str, ...]",
    extra: str,
) -> None:
    """duho's own line names its extra, and pydhcp declares neither library."""
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    _block(monkeypatch, *blocked)

    with pytest.raises(DHCPConfigError) as error:
        load_config(path)

    assert extra in str(error.value)
    assert error.value.path == str(path)
    assert error.value.__cause__ is None and error.value.__suppress_context__


def test_a_json_or_ini_file_needs_no_format_extra(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _block(monkeypatch, "yaml", "tomllib", "tomli", "tomli_w", "pktcap")
    (tmp_path / "c.json").write_text('{"server": {}}', encoding="utf-8")
    (tmp_path / "c.ini").write_text("[server]\n", encoding="utf-8")

    assert load_config(tmp_path / "c.json") == {"server": {}}
    assert load_config(tmp_path / "c.ini") == {"server": {}}


def test_reading_a_settings_file_without_duho_names_the_cli_extra(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "c.json").write_text('{"server": {}}', encoding="utf-8")
    _block(monkeypatch, "duho")

    with pytest.raises(ImportError) as error:
        load_config(tmp_path / "c.json")

    assert _the_command_for("cli") in str(error.value)


def _write_packet(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "packet.hex"
    path.write_text(bytes(_message().encode()).hex(), encoding="ascii")
    return path


@pytest.mark.parametrize(
    "fmt, blocked, line",
    [
        ("yaml", ("pktcap",), 'pip install "pydhcp[pktcap]"'),
        ("ini", ("pktcap",), 'pip install "pydhcp[pktcap]"'),
        ("yaml", ("yaml",), 'pip install "pktcap[yaml]"'),
        ("toml", ("tomli_w",), 'pip install "pktcap[toml]"'),
    ],
)
def test_a_packet_format_without_its_extra_is_one_line_and_status_1(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fmt: str,
    blocked: "_ty.Tuple[str, ...]",
    line: str,
) -> None:
    if "pktcap" not in blocked:
        pytest.importorskip("pktcap")
    path = _write_packet(tmp_path)
    _block(monkeypatch, *blocked)

    status = main(["packet", "--decode", "--format", fmt, "--input", str(path)])

    captured = capsys.readouterr()
    assert status == 1
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 1 and lines[0].startswith("pydhcp: error:")
    assert line in lines[0]


@pytest.mark.parametrize(
    "name, text, blocked, extra",
    [
        ("c.toml", "[nosuchsection]\n", ("tomllib", "tomli"), "duho[config]"),
        ("c.yaml", "nosuchsection: {}\n", ("yaml",), "duho[yaml]"),
    ],
)
def test_a_configuration_file_without_its_extra_is_a_wrong_invocation(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    name: str,
    text: str,
    blocked: "_ty.Tuple[str, ...]",
    extra: str,
) -> None:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    _block(monkeypatch, *blocked)

    status = main(["--config", str(path), "server", "--listen", "127.0.0.1:0"])

    err = capsys.readouterr().err
    assert status == 2
    assert extra in err and str(path) in err
    assert len(err.splitlines()) == 1


def test_the_command_line_without_duho_says_which_extra_and_returns_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _block(monkeypatch, "duho")

    status = main(["--help"])

    captured = capsys.readouterr()
    assert status == 1
    assert captured.out == ""
    assert captured.err.splitlines() == [
        f"pydhcp: error: the command line needs the 'cli' extra: {_the_command_for('cli')}"
    ]


def test_a_command_class_without_duho_is_an_import_error_naming_the_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pydhcp.cli

    _block(monkeypatch, "duho")
    monkeypatch.delitem(vars(pydhcp.cli), "Server", raising=False)

    with pytest.raises(ImportError) as error:
        getattr(pydhcp.cli, "Server")

    assert _the_command_for("cli") in str(error.value)
    with pytest.raises(AttributeError):
        getattr(pydhcp.cli, "NoSuchCommand")


def test_a_failure_inside_duho_is_not_taken_for_a_missing_extra(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "duho.py").write_text(
        "import a_module_nobody_ships\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "duho")

    with pytest.raises(ModuleNotFoundError, match="a_module_nobody_ships"):
        main(["--help"])


# -- nothing loads until it is used (a child process: this one has loaded them) ------

_BLOCKER = textwrap.dedent("""
    import sys

    BLOCKED = {blocked!r}


    class Blocker:
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in BLOCKED:
                raise ModuleNotFoundError("No module named " + repr(name), name=name)


    if BLOCKED:
        sys.meta_path.insert(0, Blocker())
    """)


def _program(
    tmp_path: pathlib.Path, body: str, blocked: "_ty.Sequence[str]" = ()
) -> pathlib.Path:
    path = tmp_path / "program.py"
    text = _BLOCKER.format(blocked=tuple(blocked)) + textwrap.dedent(body)
    path.write_text(text, encoding="utf-8")
    return path


def test_importing_the_package_loads_no_optional_module(tmp_path: pathlib.Path) -> None:
    program = _program(
        tmp_path,
        """
        import json

        OPTIONAL = {optional!r}


        def loaded():
            return sorted(
                name for name in sys.modules if name.split(".")[0] in OPTIONAL
            )


        import pydhcp
        import pydhcp.cli
        import pydhcp.packet.structured
        from pydhcp import DHCPClient

        after_import = loaded()
        DHCPClient(listen="127.0.0.1:0").build_discover(bytes(6)).to_text("json")
        print(json.dumps([after_import, loaded()]))
        """.format(optional=OPTIONAL),
    )

    result = run_cli(program=program)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [[], []]


def test_the_package_imports_and_its_json_works_with_every_extra_absent(
    tmp_path: pathlib.Path,
) -> None:
    program = _program(
        tmp_path,
        """
        import pydhcp
        import pydhcp.cli
        from pydhcp import DHCPClient, DHCPMessage

        message = DHCPClient(listen="127.0.0.1:0").build_discover(bytes(6))
        text = message.to_text("json")
        assert DHCPMessage.from_text(text, "json").to_mapping() == message.to_mapping()
        print("imported")
        """,
        blocked=OPTIONAL,
    )

    result = run_cli(program=program)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "imported"


def test_the_process_without_duho_prints_the_hint_and_exits_non_zero(
    tmp_path: pathlib.Path,
) -> None:
    program = _program(
        tmp_path,
        """
        import runpy

        runpy.run_module("pydhcp", run_name="__main__")
        """,
        blocked=OPTIONAL,
    )

    result = run_cli("--help", program=program)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.splitlines() == [
        f"pydhcp: error: the command line needs the 'cli' extra: {_the_command_for('cli')}"
    ]


def test_a_run_that_names_no_settings_file_loads_no_reader(
    tmp_path: pathlib.Path,
) -> None:
    """`duho.config`, and with it every parser behind it, is imported when a file is read."""
    program = _program(
        tmp_path,
        """
        import json
        import sys

        from pydhcp.cli import main

        before = sorted(n for n in sys.modules if n.startswith("duho.config"))
        status = main(["packet", "--decode", "--input", sys.argv[1]])
        after = sorted(n for n in sys.modules if n.startswith("duho.config"))
        print(json.dumps([status, before, after]), file=sys.stderr)
        """,
    )
    packet = tmp_path / "packet.hex"
    packet.write_text(bytes(_message().encode()).hex(), encoding="ascii")

    result = run_cli(str(packet), program=program)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stderr.splitlines()[-1]) == [0, [], []]
