"""Where the command's settings come from: argument, environment, file, default.

duho applies the order to every declared field of every command. Each level is
tested as a process, with the environment passed to the child and the commands
replaced by a program that prints their resolved fields, so no socket is opened
and nothing is patched into this process. The configuration file's errors go
through `main` with every format and every mistake.
"""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import sys
import typing as _ty

import pytest

from cli_process import SHOW_SETTINGS, run_cli

from pydhcp.cli import main

# the unit under test is not exported from a public module
from pydhcp.cli._settings import traceback_requested

#: Python 3.11 reads TOML itself; before it the `toml` extra's `tomli` does.
HAS_TOML_READER = (
    sys.version_info >= (3, 11) or importlib.util.find_spec("tomli") is not None
)

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
            "lenient_reply_ports": False,
            "config": None,
            "config_format": None,
        },
        "file": {
            "listen": "127.0.0.1:2001",
            "per_interface": True,
            "lease_file": "from-file.json",
            "lenient_reply_ports": True,
        },
        "env": {
            "PYDHCP_SERVER_LISTEN": "127.0.0.1:2002",
            "PYDHCP_SERVER_PER_INTERFACE": "0",
            "PYDHCP_SERVER_LEASE_FILE": "from-env.json",
            "PYDHCP_SERVER_LENIENT_REPLY_PORTS": "no",
        },
        "arg": [
            "--listen",
            "127.0.0.1:2003",
            "--per-interface",
            "--lease-file",
            "from-arg.json",
            "--lenient-reply-ports",
        ],
        "after": {
            "file": {
                "listen": "127.0.0.1:2001",
                "per_interface": True,
                "lease_file": "from-file.json",
                "lenient_reply_ports": True,
            },
            "env": {
                "listen": "127.0.0.1:2002",
                "per_interface": False,
                "lease_file": "from-env.json",
                "lenient_reply_ports": False,
            },
            "arg": {
                "listen": "127.0.0.1:2003",
                "per_interface": True,
                "lease_file": "from-arg.json",
                "lenient_reply_ports": True,
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
            "filter": None,
            "format": None,
            "output": "-",
            "per_record": False,
            "max_files": 1000,
            "datagrams": False,
            "append": False,
            "interface": None,
            "count": None,
            "duration": None,
            "hook": None,
            "hook_fail_fast": False,
            "hook_timeout": 10.0,
            "per_interface": False,
            "read": None,
            "load": None,
        },
        "file": {
            "listen": "127.0.0.1:2001",
            "filter": "msg_type=DHCPDISCOVER",
            "format": "yaml",
            "output": "from-file.yaml",
            "per_record": True,
            "max_files": 11,
            "datagrams": True,
            "append": True,
            "interface": "eth-from-file",
            "count": 5,
            "duration": 4.5,
            "hook": "mod:from_file",
            "hook_fail_fast": True,
            "hook_timeout": 3.5,
            "per_interface": True,
            "read": "from-file.pcap",
            "load": ["file_plugin"],
        },
        "env": {
            "PKTCAP_LOAD": "env_plugin",
            "PYDHCP_CAPTURE_LISTEN": "127.0.0.1:2002",
            "PYDHCP_CAPTURE_FILTER": "msg_type=DHCPREQUEST",
            "PYDHCP_CAPTURE_FORMAT": "json",
            "PYDHCP_CAPTURE_OUTPUT": "from-env.json",
            "PYDHCP_CAPTURE_PER_RECORD": "no",
            "PYDHCP_CAPTURE_MAX_FILES": "12",
            "PYDHCP_CAPTURE_DATAGRAMS": "no",
            "PYDHCP_CAPTURE_APPEND": "no",
            "PYDHCP_CAPTURE_INTERFACE": "eth-from-env",
            "PYDHCP_CAPTURE_COUNT": "6",
            "PYDHCP_CAPTURE_DURATION": "5.5",
            "PYDHCP_CAPTURE_HOOK": "mod:from_env",
            "PYDHCP_CAPTURE_HOOK_FAIL_FAST": "false",
            "PYDHCP_CAPTURE_HOOK_TIMEOUT": "4.5",
            "PYDHCP_CAPTURE_PER_INTERFACE": "no",
            "PYDHCP_CAPTURE_READ": "from-env.pcap",
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
            "--per-record",
            "--max-files",
            "13",
            "--datagrams",
            "--append",
            "--count",
            "7",
            "--duration",
            "6.5",
            "--hook",
            "mod:from_arg",
            "--hook-fail-fast",
            "--hook-timeout",
            "5.5",
            "--per-interface",
            "--load",
            "arg_plugin",
        ],
        "after": {
            "file": {
                "listen": "127.0.0.1:2001",
                "filter": "msg_type=DHCPDISCOVER",
                "format": "yaml",
                "output": "from-file.yaml",
                "per_record": True,
                "max_files": 11,
                "datagrams": True,
                "append": True,
                "interface": "eth-from-file",
                "count": 5,
                "duration": 4.5,
                "hook": "mod:from_file",
                "hook_fail_fast": True,
                "hook_timeout": 3.5,
                "per_interface": True,
                "read": "from-file.pcap",
                "load": ["file_plugin"],
            },
            "env": {
                "load": ["env_plugin"],
                "listen": "127.0.0.1:2002",
                "filter": "msg_type=DHCPREQUEST",
                "format": "json",
                "output": "from-env.json",
                "per_record": False,
                "max_files": 12,
                "datagrams": False,
                "append": False,
                "interface": "eth-from-env",
                "count": 6,
                "duration": 5.5,
                "hook": "mod:from_env",
                "hook_fail_fast": False,
                "hook_timeout": 4.5,
                "per_interface": False,
                "read": "from-env.pcap",
            },
            "arg": {
                "listen": "127.0.0.1:2003",
                "filter": "msg_type=DHCPINFORM",
                "format": "yaml",
                "output": "from-arg.yaml",
                "per_record": True,
                "max_files": 13,
                "datagrams": True,
                "append": True,
                "count": 7,
                "duration": 6.5,
                "hook": "mod:from_arg",
                "hook_fail_fast": True,
                "hook_timeout": 5.5,
                "per_interface": True,
                "load": ["arg_plugin"],
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
    "replay": {
        "base": [],
        "needed": ["--input", "x.pcap", "--to", "192.0.2.9"],
        "default": {
            "input": "x.pcap",
            "to": "192.0.2.9",
            "speed": 1.0,
            "no_delay": False,
            "max_delay": 5.0,
            "limit": None,
            "filter": None,
            "source_port": None,
            "broadcast": False,
            "json_out": False,
            "load": None,
        },
        "file": None,
        "env": {
            "PKTCAP_LOAD": "env_plugin",
            "PYDHCP_REPLAY_INPUT": "from-env.pcap",
            "PYDHCP_REPLAY_TO": "192.0.2.2",
            "PYDHCP_REPLAY_SPEED": "2.5",
            "PYDHCP_REPLAY_NO_DELAY": "yes",
            "PYDHCP_REPLAY_MAX_DELAY": "7.5",
            "PYDHCP_REPLAY_LIMIT": "6",
            "PYDHCP_REPLAY_FILTER": "sport=68",
            "PYDHCP_REPLAY_SOURCE_PORT": "6868",
            "PYDHCP_REPLAY_BROADCAST": "yes",
            "PYDHCP_REPLAY_JSON_OUT": "yes",
        },
        "arg": [
            "--input",
            "from-arg.pcap",
            "--to",
            "192.0.2.3:6767",
            "--speed",
            "3",
            "--max-delay",
            "8",
            "--limit",
            "7",
            "--filter",
            "sport=6868",
            "--source-port",
            "6869",
            "--broadcast",
            "--json",
            "--load",
            "arg_plugin",
        ],
        "after": {
            "env": {
                "load": ["env_plugin"],
                "input": "from-env.pcap",
                "to": "192.0.2.2",
                "speed": 2.5,
                "no_delay": True,
                "max_delay": 7.5,
                "limit": 6,
                "filter": "sport=68",
                "source_port": 6868,
                "broadcast": True,
                "json_out": True,
            },
            "arg": {
                "input": "from-arg.pcap",
                "to": "192.0.2.3:6767",
                "speed": 3.0,
                "no_delay": False,
                "max_delay": 8.0,
                "limit": 7,
                "filter": "sport=6868",
                "source_port": 6869,
                "broadcast": True,
                "json_out": True,
                "load": ["arg_plugin"],
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

    # private: the unit under test is not re-exported from a public module; the unit under test is not exported from a public module
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
    pytest.param("bad.ini", "token = " + SECRET + "\n[server]\n", id="ini"),
    pytest.param(
        "bad.toml",
        "[server\ntoken = '" + SECRET + "'\n",
        id="toml",
        marks=pytest.mark.skipif(not HAS_TOML_READER, reason="no TOML reader"),
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
        ("s.json", '{"server": "127.0.0.1:6767"}', "'server' must be a mapping"),
        ("n.json", '{"server": 5}', "'server' must be a mapping"),
        (
            "t.json",
            '{"sever": {"listen": "127.0.0.1:6767"}}',
            "unknown section 'sever'",
        ),
        (
            "o.json",
            '{"server": {"listen": "127.0.0.1:6767"}, "stray": 1}',
            "unknown section 'stray'",
        ),
        (
            "k.json",
            '{"server": {"lisen": "127.0.0.1:6767"}}',
            "unknown key 'lisen' in section 'server'",
        ),
        (
            "r.json",
            '{"relay": {"server": "192.0.2.1"}}',
            "section 'relay' belongs to another command",
        ),
        ("c.yaml", "server: {}\n", "cannot tell the configuration format"),
        ("c.yml", "server: {}\n", "cannot tell the configuration format"),
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
    path = tmp_path / "absent.json"

    line = _refused(capsys, "server", "--config", str(path), status=1)

    assert "absent.json" in line


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


def test_every_command_that_runs_reads_the_file(
    program: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """`relay` and `capture` read a file too, and each refuses the other's section."""
    path = _write(
        tmp_path, "relay.json", '{"relay": {"server": ["192.0.2.1"], "max_hops": 9}}'
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

    line = _refused(capsys, "server", "--config", "-", "--config-format", "ini")

    assert line.startswith("pydhcp: error: <stdin>:")


def test_a_config_option_is_a_path(tmp_path: pathlib.Path) -> None:
    from pydhcp.cli import App

    parsed = App._parser_().parse_args(["server", "--config", "x.toml"])
    assert isinstance(parsed.config, pathlib.Path)
    parsed = App._parser_().parse_args(["packet", "--decode", "-i", "a", "-o", "b"])
    assert isinstance(parsed.input, pathlib.Path)
    assert isinstance(parsed.output, pathlib.Path)


# -- the variables are documented ---------------------------------------------------


def _every_variable() -> "set[str]":
    from pydhcp.cli import App

    # private: the unit under test is not re-exported from a public module
    from pydhcp.cli._settings import CONFIG_ENV, CONFIG_FORMAT_ENV, TRACEBACK_ENV

    names = {CONFIG_ENV, CONFIG_FORMAT_ENV, TRACEBACK_ENV, "PYDHCP_MCP"}
    for command in App._subcommands_ or ():
        names |= {b.env for b in command._getargs_() if b.env}
    # What a command hook is given: pktcap's, named for the fields `capture` supplies.
    names |= {
        "PKTCAP_HOOK_CLIENT_ID",
        "PKTCAP_HOOK_MSG_TYPE",
        "PKTCAP_HOOK_XID",
        "PKTCAP_HOOK_FORMAT",
    }
    return names


@pytest.mark.parametrize(
    "documents",
    [["src/pydhcp/AGENTS.md", "src/pydhcp/cli/AGENTS.md"], ["README.md"]],
    ids=["headers", "readme"],
)
def test_every_variable_the_command_reads_is_documented(documents: "list[str]") -> None:
    root = pathlib.Path(__file__).resolve().parents[2]
    text = "\n".join((root / d).read_text(encoding="utf-8") for d in documents)

    assert [name for name in sorted(_every_variable()) if name not in text] == []


def test_the_layer_table_names_every_variable_a_field_declares() -> None:
    from pydhcp.cli import App

    # private: the unit under test is not re-exported from a public module
    from pydhcp.cli._settings import CONFIG_ENV, CONFIG_FORMAT_ENV

    declared = {
        b.env for command in App._subcommands_ or () for b in command._getargs_()
    } - {None, CONFIG_ENV, CONFIG_FORMAT_ENV}
    assert {name for spec in LAYERS.values() for name in spec["env"]} == declared
