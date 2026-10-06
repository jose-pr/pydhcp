"""Where the command's settings come from: argument, environment, file, default.

duho applies the order to every declared field of every command. Each level is
tested as a process, with the environment passed to the child and the commands
replaced by a program that prints their resolved fields, so no socket is opened
and nothing is patched into this process. The configuration file's errors go
through `main` with every format and every mistake.
"""

from __future__ import annotations

import io
import json
import pathlib
import typing as _ty

import pytest

from cli_process import SHOW_SETTINGS, run_cli
from pydhcp._config import _tomllib
from pydhcp.cli import main
from pydhcp.cli._settings import traceback_requested

# -- the four levels, for every command ---------------------------------------------

#: command -> the arguments every run needs, the fields as the class declares them,
#: then what each level sets: the file's section, the environment, the arguments, and
#: the value each one makes the field. A field the file cannot carry is not in `file`.
LAYERS: "dict[str, dict[str, _ty.Any]]" = {
    "server": {
        "base": [],
        "default": {
            "listen": None,
            "per_interface": False,
            "lease_file": None,
            "config": None,
            "config_format": None,
        },
        "file": {
            "listen": "127.0.0.1:2001",
            "per_interface": True,
            "lease_file": "from-file.json",
        },
        "env": {
            "PYDHCP_SERVER_LISTEN": "127.0.0.1:2002",
            "PYDHCP_SERVER_PER_INTERFACE": "0",
            "PYDHCP_SERVER_LEASE_FILE": "from-env.json",
        },
        "arg": [
            "--listen",
            "127.0.0.1:2003",
            "--per-interface",
            "--lease-file",
            "from-arg.json",
        ],
        "after": {
            "file": {
                "listen": "127.0.0.1:2001",
                "per_interface": True,
                "lease_file": "from-file.json",
            },
            "env": {
                "listen": "127.0.0.1:2002",
                "per_interface": False,
                "lease_file": "from-env.json",
            },
            "arg": {
                "listen": "127.0.0.1:2003",
                "per_interface": True,
                "lease_file": "from-arg.json",
            },
        },
    },
    "relay": {
        "base": [],
        "needed": ["--server", "192.0.2.9"],
        "default": {
            "listen": None,
            "server": ["192.0.2.9"],
            "max_hops": 4,
            "insert_relay_agent_info": False,
            "circuit_id": None,
            "remote_id": None,
            "per_interface": False,
        },
        "file": {
            "listen": "127.0.0.1:2001",
            "server": ["192.0.2.1"],
            "max_hops": 5,
            "insert_relay_agent_info": True,
            "circuit_id": "aa",
            "remote_id": "bb",
            "per_interface": True,
        },
        "env": {
            "PYDHCP_RELAY_LISTEN": "127.0.0.1:2002",
            "PYDHCP_RELAY_SERVER": "192.0.2.2,192.0.2.3:6768",
            "PYDHCP_RELAY_MAX_HOPS": "6",
            "PYDHCP_RELAY_INSERT_RELAY_AGENT_INFO": "no",
            "PYDHCP_RELAY_CIRCUIT_ID": "cc",
            "PYDHCP_RELAY_REMOTE_ID": "dd",
            "PYDHCP_RELAY_PER_INTERFACE": "off",
        },
        "arg": [
            "--listen",
            "127.0.0.1:2003",
            "--server",
            "192.0.2.4",
            "--max-hops",
            "7",
            "--insert-relay-agent-info",
            "--circuit-id",
            "ee",
            "--remote-id",
            "ff",
            "--per-interface",
        ],
        "after": {
            "file": {
                "listen": "127.0.0.1:2001",
                "server": ["192.0.2.1"],
                "max_hops": 5,
                "insert_relay_agent_info": True,
                "circuit_id": "aa",
                "remote_id": "bb",
                "per_interface": True,
            },
            "env": {
                "listen": "127.0.0.1:2002",
                "server": ["192.0.2.2", "192.0.2.3:6768"],
                "max_hops": 6,
                "insert_relay_agent_info": False,
                "circuit_id": "cc",
                "remote_id": "dd",
                "per_interface": False,
            },
            "arg": {
                "listen": "127.0.0.1:2003",
                "server": ["192.0.2.4"],
                "max_hops": 7,
                "insert_relay_agent_info": True,
                "circuit_id": "ee",
                "remote_id": "ff",
                "per_interface": True,
            },
        },
    },
    "capture": {
        "base": [],
        "default": {
            "listen": None,
            "packet_filter": None,
            "packet_format": None,
            "output": "-",
            "per_capture": False,
            "max_files": None,
            "count": None,
            "hook": None,
            "hook_fail_fast": False,
            "per_interface": False,
        },
        "file": {
            "listen": "127.0.0.1:2001",
            "packet_filter": "msg_type=DHCPDISCOVER",
            "packet_format": "yaml",
            "output": "from-file.yaml",
            "per_capture": True,
            "max_files": 11,
            "count": 5,
            "hook": "mod:from_file",
            "hook_fail_fast": True,
            "per_interface": True,
        },
        "env": {
            "PYDHCP_CAPTURE_LISTEN": "127.0.0.1:2002",
            "PYDHCP_CAPTURE_FILTER": "msg_type=DHCPREQUEST",
            "PYDHCP_CAPTURE_RECORD_FORMAT": "json",
            "PYDHCP_CAPTURE_OUTPUT": "from-env.json",
            "PYDHCP_CAPTURE_PER_CAPTURE": "no",
            "PYDHCP_CAPTURE_MAX_FILES": "12",
            "PYDHCP_CAPTURE_COUNT": "6",
            "PYDHCP_CAPTURE_HOOK": "mod:from_env",
            "PYDHCP_CAPTURE_HOOK_FAIL_FAST": "false",
            "PYDHCP_CAPTURE_PER_INTERFACE": "no",
        },
        "arg": [
            "--listen",
            "127.0.0.1:2003",
            "--filter",
            "msg_type=DHCPINFORM",
            "--format",
            "yaml",
            "--output",
            "from-arg.yaml",
            "--per-capture",
            "--max-files",
            "13",
            "--count",
            "7",
            "--hook",
            "mod:from_arg",
            "--hook-fail-fast",
            "--per-interface",
        ],
        "after": {
            "file": {
                "listen": "127.0.0.1:2001",
                "packet_filter": "msg_type=DHCPDISCOVER",
                "packet_format": "yaml",
                "output": "from-file.yaml",
                "per_capture": True,
                "max_files": 11,
                "count": 5,
                "hook": "mod:from_file",
                "hook_fail_fast": True,
                "per_interface": True,
            },
            "env": {
                "listen": "127.0.0.1:2002",
                "packet_filter": "msg_type=DHCPREQUEST",
                "packet_format": "json",
                "output": "from-env.json",
                "per_capture": False,
                "max_files": 12,
                "count": 6,
                "hook": "mod:from_env",
                "hook_fail_fast": False,
                "per_interface": False,
            },
            "arg": {
                "listen": "127.0.0.1:2003",
                "packet_filter": "msg_type=DHCPINFORM",
                "packet_format": "yaml",
                "output": "from-arg.yaml",
                "per_capture": True,
                "max_files": 13,
                "count": 7,
                "hook": "mod:from_arg",
                "hook_fail_fast": True,
                "per_interface": True,
            },
        },
    },
    # `packet` and `interfaces` take no configuration file, so they have no `file` level.
    "packet": {
        "base": ["--decode"],
        "default": {"input": "-", "output": "-", "packet_format": "json"},
        "file": None,
        "env": {
            "PYDHCP_PACKET_INPUT": "from-env.hex",
            "PYDHCP_PACKET_OUTPUT": "from-env.yaml",
            "PYDHCP_PACKET_FORMAT": "yaml",
        },
        "arg": [
            "--input",
            "from-arg.hex",
            "--output",
            "from-arg.ini",
            "--format",
            "ini",
        ],
        "after": {
            "env": {
                "input": "from-env.hex",
                "output": "from-env.yaml",
                "packet_format": "yaml",
            },
            "arg": {
                "input": "from-arg.hex",
                "output": "from-arg.ini",
                "packet_format": "ini",
            },
        },
    },
    "interfaces": {
        "base": [],
        "default": {"output_format": "text"},
        "file": None,
        "env": {"PYDHCP_INTERFACES_FORMAT": "json"},
        "arg": ["--format", "text"],
        "after": {
            "env": {"output_format": "json"},
            "arg": {"output_format": "text"},
        },
    },
}


@pytest.fixture(scope="module")
def program(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    path = tmp_path_factory.mktemp("settings") / "show_settings.py"
    path.write_bytes(SHOW_SETTINGS.encode("utf-8"))
    return path


def _resolve(
    program: pathlib.Path,
    command: str,
    *,
    config: "_ty.Optional[pathlib.Path]" = None,
    env: "_ty.Optional[_ty.Mapping[str, str]]" = None,
    argv: "_ty.Sequence[str]" = (),
) -> "dict[str, _ty.Any]":
    arguments = [command, *argv]
    if config is not None:
        arguments += ["--config", str(config)]
    done = run_cli(*arguments, env=env, program=program)
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    return _ty.cast("dict[str, _ty.Any]", json.loads(done.stdout))


def _check(resolved: "dict[str, _ty.Any]", expected: "dict[str, _ty.Any]") -> None:
    assert {name: resolved[name] for name in expected} == expected


def _file(tmp_path: pathlib.Path, command: str) -> pathlib.Path:
    path = tmp_path / "pydhcp.json"
    path.write_text(json.dumps({command: LAYERS[command]["file"]}), encoding="utf-8")
    return path


@pytest.mark.parametrize("command", list(LAYERS))
def test_a_field_with_no_setting_has_its_default(
    program: pathlib.Path, command: str
) -> None:
    spec = LAYERS[command]
    _check(
        _resolve(program, command, argv=[*spec["base"], *spec.get("needed", [])]),
        spec["default"],
    )


@pytest.mark.parametrize("command", [c for c in LAYERS if LAYERS[c]["file"]])
def test_the_file_beats_the_default(
    program: pathlib.Path, tmp_path: pathlib.Path, command: str
) -> None:
    spec = LAYERS[command]
    resolved = _resolve(program, command, config=_file(tmp_path, command))
    _check(resolved, spec["after"]["file"])


@pytest.mark.parametrize("command", list(LAYERS))
def test_the_environment_beats_the_file_and_the_default(
    program: pathlib.Path, tmp_path: pathlib.Path, command: str
) -> None:
    spec = LAYERS[command]
    config = _file(tmp_path, command) if spec["file"] else None
    resolved = _resolve(
        program, command, config=config, env=spec["env"], argv=spec["base"]
    )
    _check(resolved, spec["after"]["env"])


@pytest.mark.parametrize("command", list(LAYERS))
def test_an_argument_beats_the_environment_the_file_and_the_default(
    program: pathlib.Path, tmp_path: pathlib.Path, command: str
) -> None:
    spec = LAYERS[command]
    config = _file(tmp_path, command) if spec["file"] else None
    resolved = _resolve(
        program,
        command,
        config=config,
        env=spec["env"],
        argv=[*spec["base"], *spec["arg"]],
    )
    _check(resolved, spec["after"]["arg"])


def test_every_declared_field_of_every_command_has_a_variable() -> None:
    """The table above names a variable for each field a command declares."""
    from pydhcp.cli import App

    from pydhcp.cli._settings import _NOT_SETTINGS

    for command in App._subcommands_ or ():
        spec = LAYERS[str(command._parsername_)]
        fields = {
            b.name
            for b in command._getargs_()
            if b.name not in _NOT_SETTINGS and b.name not in ("decode", "encode")
        }
        assert fields <= set(spec["default"]), (command, fields - set(spec["default"]))
        assert len(spec["env"]) == len(fields), command


def test_the_configuration_file_can_be_named_by_the_environment(
    program: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    path = _file(tmp_path, "server")
    resolved = _resolve(program, "server", env={"PYDHCP_CONFIG": str(path)})
    assert resolved["listen"] == "127.0.0.1:2001"
    assert resolved["config"] == str(path)


def test_the_option_beats_the_variable_for_the_file_itself(
    program: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    named = _file(tmp_path, "server")
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"server": {"listen": "127.0.0.1:2009"}}), "utf-8")
    resolved = _resolve(
        program,
        "server",
        config=other,
        env={"PYDHCP_CONFIG": str(named)},
    )
    assert resolved["listen"] == "127.0.0.1:2009"


def test_there_is_no_default_location_for_the_file(
    program: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """A daemon does not pick up a file nobody named, wherever it looks first."""
    home = tmp_path / "home"
    (home / ".config" / "pydhcp").mkdir(parents=True)
    for place in (
        home / ".config" / "pydhcp" / "config.json",
        tmp_path / "pydhcp.json",
    ):
        place.write_text(json.dumps({"server": {"listen": "127.0.0.1:2005"}}), "utf-8")
    resolved = _resolve(
        program,
        "server",
        env={"HOME": str(home), "APPDATA": str(home), "XDG_CONFIG_HOME": str(home)},
    )
    assert resolved["listen"] is None


def test_a_bad_environment_value_names_the_variable() -> None:
    done = run_cli("server", env={"PYDHCP_SERVER_PER_INTERFACE": "maybe"})
    assert done.returncode == 2
    assert "PYDHCP_SERVER_PER_INTERFACE" in done.stderr
    assert "Traceback" not in done.stderr


def test_a_bad_number_in_the_environment_names_the_variable() -> None:
    done = run_cli("relay", "-s", "192.0.2.1", env={"PYDHCP_RELAY_MAX_HOPS": "many"})
    assert done.returncode == 2
    assert "PYDHCP_RELAY_MAX_HOPS" in done.stderr


# -- PYDHCP_TRACEBACK ----------------------------------------------------------------


@pytest.mark.parametrize("text", ["1", "true", "TRUE", "Yes", "on", " ON "])
def test_traceback_accepts_the_true_words_in_any_case(text: str) -> None:
    assert traceback_requested({"PYDHCP_TRACEBACK": text}) is True


@pytest.mark.parametrize("text", ["0", "false", "False", "NO", "off", ""])
def test_traceback_accepts_the_false_words_and_empty(text: str) -> None:
    assert traceback_requested({"PYDHCP_TRACEBACK": text}) is False
    assert traceback_requested({}) is False


def test_traceback_zero_does_not_enable_tracebacks() -> None:
    done = run_cli(
        "server", "--listen", "127.0.0.1:notaport", env={"PYDHCP_TRACEBACK": "0"}
    )
    assert done.returncode == 2
    assert "Traceback" not in done.stderr
    assert done.stderr.startswith("pydhcp: error:")


def test_traceback_one_enables_tracebacks() -> None:
    done = run_cli(
        "server", "--listen", "127.0.0.1:notaport", env={"PYDHCP_TRACEBACK": "1"}
    )
    assert "Traceback" in done.stderr
    assert done.returncode == 1


def test_traceback_with_any_other_text_is_an_error_naming_the_variable() -> None:
    done = run_cli("interfaces", env={"PYDHCP_TRACEBACK": "maybe"})
    assert done.returncode == 2
    assert "PYDHCP_TRACEBACK" in done.stderr and "maybe" in done.stderr
    assert "Traceback" not in done.stderr


# -- the configuration file: every format, every mistake ----------------------------

SECRET = "hunter2-SECRET"


def _write(tmp_path: pathlib.Path, name: str, text: str) -> pathlib.Path:
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))
    return path


def _refused(capsys: pytest.CaptureFixture[str], *argv: str, status: int = 2) -> str:
    """Run `pydhcp argv...`: it must be refused with one line and no traceback."""
    assert main(list(argv)) == status
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 1, captured.err
    assert lines[0].startswith("pydhcp: error: ")
    assert "Traceback" not in captured.err
    assert SECRET not in captured.err
    return lines[0]


MALFORMED = [
    pytest.param(
        "bad.json",
        '{"server": {"token": "' + SECRET + '", "listen": "127.0.0.1:1"',
        id="json",
    ),
    pytest.param(
        "bad.yaml",
        "server:\n  token: " + SECRET + "\n  listen: [127.0.0.1:1\n",
        id="yaml",
    ),
    pytest.param("bad.ini", "token = " + SECRET + "\n[server]\n", id="ini"),
    pytest.param(
        "bad.toml",
        "[server\ntoken = '" + SECRET + "'\n",
        id="toml",
        marks=pytest.mark.skipif(_tomllib is None, reason="no TOML reader"),
    ),
]


@pytest.mark.parametrize("name, text", MALFORMED)
def test_a_malformed_file_is_one_line_naming_the_file_and_where(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str], name: str, text: str
) -> None:
    path = _write(tmp_path, name, text)

    line = _refused(capsys, "server", "--config", str(path))

    assert line.startswith(f"pydhcp: error: {path}:")
    rest = line[len(f"pydhcp: error: {path}:") :]
    assert rest.split(":")[0].isdigit(), line  # the line number


@pytest.mark.parametrize(
    "name, text, word",
    [
        ("l.json", "[1, 2]", "mapping"),
        ("l.yaml", "- 1\n- 2\n", "mapping"),
        ("s.yaml", "server: 127.0.0.1:6767\n", "'server' must be a mapping"),
        ("n.yaml", "server: 5\n", "'server' must be a mapping"),
        ("t.yaml", "sever:\n  listen: 127.0.0.1:6767\n", "unknown section 'sever'"),
        (
            "o.yaml",
            "server:\n  listen: 127.0.0.1:6767\nstray: 1\n",
            "unknown section 'stray'",
        ),
        (
            "k.yaml",
            "server:\n  lisen: 127.0.0.1:6767\n",
            "unknown key 'lisen' in section 'server'",
        ),
        (
            "r.yaml",
            "relay:\n  server: 192.0.2.1\n",
            "section 'relay' belongs to another command",
        ),
        ("c.json", '{"server": {"config": "x.json"}}', "unknown key 'config'"),
        ("s.conf", "[server]\nlisten = 127.0.0.1:6767\n", "'.conf'"),
        ("s", "{}", "cannot tell the configuration format"),
    ],
)
def test_a_file_that_names_what_the_command_does_not_have_is_refused_by_name(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    text: str,
    word: str,
) -> None:
    path = _write(tmp_path, name, text)

    line = _refused(capsys, "server", "--config", str(path))

    assert str(path) in line
    assert word in line


def test_a_file_that_is_not_utf8_is_refused(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "latin.ini"
    path.write_bytes(b"[server]\nlisten = caf\xe9\n")

    line = _refused(capsys, "server", "--config", str(path))

    assert "not valid UTF-8" in line and str(path) in line


def test_a_missing_file_is_a_failed_run_naming_it(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "absent.yaml"

    line = _refused(capsys, "server", "--config", str(path), status=1)

    assert "absent.yaml" in line


def test_a_duplicate_section_or_key_in_an_ini_file_is_refused(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    section = _write(tmp_path, "a.ini", "[server]\nlisten = a\n[server]\n")
    key = _write(tmp_path, "b.ini", "[server]\nlisten = a\nlisten = b\n")

    assert "defined twice" in _refused(capsys, "server", "--config", str(section))
    assert "defined twice" in _refused(capsys, "server", "--config", str(key))


def test_a_percent_sign_in_an_ini_value_is_text(
    program: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    path = _write(tmp_path, "pct.ini", "[server]\nlease_file = C:\\leases\\100%.json\n")

    resolved = _resolve(program, "server", config=path)

    assert resolved["lease_file"] == "C:\\leases\\100%.json"


def test_a_byte_order_mark_is_accepted(
    program: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + b'{"server": {"listen": "127.0.0.1:2001"}}')

    assert _resolve(program, "server", config=path)["listen"] == "127.0.0.1:2001"


def test_an_empty_yaml_file_is_an_empty_configuration(
    program: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    path = _write(tmp_path, "empty.yaml", "")

    assert _resolve(program, "server", config=path)["listen"] is None


def test_every_command_that_runs_reads_the_file(
    program: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """`relay` and `capture` read a file too, and each refuses the other's section."""
    path = _write(
        tmp_path, "relay.yaml", "relay:\n  server: [192.0.2.1]\n  max_hops: 9\n"
    )

    resolved = _resolve(program, "relay", config=path)

    assert resolved["server"] == ["192.0.2.1"] and resolved["max_hops"] == 9


def test_the_format_can_be_named_when_the_name_says_nothing(
    program: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    path = _write(tmp_path, "server.conf", "[server]\nlisten = 127.0.0.1:2001\n")

    done = run_cli(
        "server", "--config", str(path), "--config-format", "ini", program=program
    )

    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["listen"] == "127.0.0.1:2001"


def test_standard_input_is_the_file_when_it_is_named_dash(
    program: pathlib.Path,
) -> None:
    text = json.dumps({"server": {"listen": "127.0.0.1:2001"}})

    done = run_cli(
        "server",
        "--config",
        "-",
        "--config-format",
        "json",
        program=program,
        input=text,
    )

    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["listen"] == "127.0.0.1:2001"


def test_standard_input_needs_a_format(capsys: pytest.CaptureFixture[str]) -> None:
    line = _refused(capsys, "server", "--config", "-")

    assert "standard input needs a format" in line and "<stdin>" in line


def test_standard_input_is_checked_like_a_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "sys.stdin",
        io.TextIOWrapper(io.BytesIO(("token: " + SECRET + "\n[").encode("utf-8"))),
    )

    line = _refused(capsys, "server", "--config", "-", "--config-format", "yaml")

    assert line.startswith("pydhcp: error: <stdin>:")


def test_a_config_option_is_a_path(tmp_path: pathlib.Path) -> None:
    from pydhcp.cli import App

    parsed = App._parser_().parse_args(["server", "--config", "x.yaml"])
    assert isinstance(parsed.config, pathlib.Path)
    parsed = App._parser_().parse_args(["packet", "--decode", "-i", "a", "-o", "b"])
    assert isinstance(parsed.input, pathlib.Path)
    assert isinstance(parsed.output, pathlib.Path)


# -- the variables are documented ---------------------------------------------------


def _every_variable() -> "set[str]":
    from pydhcp.cli import App
    from pydhcp.cli._settings import CONFIG_ENV, CONFIG_FORMAT_ENV, TRACEBACK_ENV

    names = {CONFIG_ENV, CONFIG_FORMAT_ENV, TRACEBACK_ENV, "PYDHCP_MCP"}
    for command in App._subcommands_ or ():
        names |= {b.env for b in command._getargs_() if b.env}
    # What a command hook is given.
    names |= {
        "PYDHCP_CAPTURE_CLIENT_ID",
        "PYDHCP_CAPTURE_MSG_TYPE",
        "PYDHCP_CAPTURE_XID",
        "PYDHCP_CAPTURE_FORMAT",
    }
    return names


@pytest.mark.parametrize(
    "document", ["src/pydhcp/AGENTS.md", "README.md"], ids=["header", "readme"]
)
def test_every_variable_the_command_reads_is_documented(document: str) -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    text = (root / document).read_text(encoding="utf-8")

    assert [name for name in sorted(_every_variable()) if name not in text] == []


def test_the_layer_table_names_every_variable_a_field_declares() -> None:
    from pydhcp.cli import App
    from pydhcp.cli._settings import CONFIG_ENV, CONFIG_FORMAT_ENV

    declared = {
        b.env for command in App._subcommands_ or () for b in command._getargs_()
    } - {None, CONFIG_ENV, CONFIG_FORMAT_ENV}
    assert {name for spec in LAYERS.values() for name in spec["env"]} == declared
