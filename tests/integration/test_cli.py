from __future__ import annotations

import io
import json
import logging
import os
import pathlib
import sys

import netimps
import pytest

from pydhcp import DHCPMessage
from pydhcp.cli import App, Packet, Relay, main

# the relay command's parser is not public
from pydhcp.cli._relay import _parse_server_address

# the loader behind the command line is not public
from pydhcp._config import load_config
from pydhcp.packet import DHCPMessageType
from ipaddress import IPv4Address as IPv4
from helpers import build_request


def _sample_packet() -> DHCPMessage:
    return build_request(DHCPMessageType.DHCPDISCOVER)


def test_cmd_packet_decode_from_stdin_json(capsys, monkeypatch) -> None:
    packet = _sample_packet()
    cmd = Packet(
        mode=True,
        packet_format="json",
        input=pathlib.Path("-"),
        output=pathlib.Path("-"),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(packet.encode().hex()))

    cmd()

    assert json.loads(capsys.readouterr().out) == packet.to_mapping()


def test_cmd_packet_decode_summary(capsys, monkeypatch) -> None:
    packet = _sample_packet()
    cmd = Packet(
        mode=True,
        packet_format="summary",
        input=pathlib.Path("-"),
        output=pathlib.Path("-"),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(packet.encode().hex()))

    cmd()

    output = capsys.readouterr().out
    assert output.startswith("BOOTREQUEST XID=12345678\n")
    assert "Src:" not in output and "Dst:" not in output
    assert "OPTIONS:" in output


def test_cmd_packet_malformed_exits_with_error(capsys, monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("00"))

    assert main(["packet", "--decode"]) == 1

    err = capsys.readouterr().err
    assert err.startswith("pydhcp: error: cannot process the packet: ")
    assert "too short for DHCP fixed header" in err


def test_cmd_packet_encode_from_file(tmp_path) -> None:
    packet = _sample_packet()
    source = tmp_path / "packet.json"
    source.write_text(packet.to_text("json"), encoding="utf-8")
    output = tmp_path / "packet.hex"
    cmd = Packet(mode=False, packet_format="json", input=source, output=output)

    cmd()

    assert output.read_text(encoding="utf-8") == packet.encode().hex()


def test_packet_cli_main_encode_from_stdin(monkeypatch, capsys) -> None:
    packet = _sample_packet()
    monkeypatch.setattr("sys.stdin", io.StringIO(packet.to_text("json")))

    status = main(["packet", "--encode", "--input", "-", "--format", "json"])

    assert status == 0
    assert capsys.readouterr().out.strip() == packet.encode().hex()


def test_capture_cli_main_help_lists_capture(capsys) -> None:
    assert main(["--help"]) == 0
    assert "capture" in capsys.readouterr().out


def test_capture_cli_main_capture_help(capsys) -> None:
    assert main(["capture", "--help"]) == 0

    output = capsys.readouterr().out
    assert "--filter" in output
    assert "--output" in output
    assert "--hook" in output
    assert "--count" in output


def test_load_config(tmp_path):
    config_file = tmp_path / "config.json"
    config_data = {"server": {"listen": "127.0.0.1:6767"}}
    config_file.write_text(json.dumps(config_data))

    loaded = load_config(str(config_file))
    assert loaded == config_data


def test_load_ini_config(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("[server]\nlisten = 127.0.0.1:6767\n")

    loaded = load_config(str(config_file))
    assert loaded == {"server": {"listen": "127.0.0.1:6767"}}


def test_parse_server_address_host_only():
    """A bare host now arrives at DHCPRelay already carrying the default port.

    It used to be handed through as the raw string and defaulted inside
    `_normalize_server_address`; the value reaching the relay is the same
    upstream either way.
    """
    assert _parse_server_address("192.0.2.1") == ("192.0.2.1", 67)


def test_parse_server_address_host_port():
    assert _parse_server_address("192.0.2.1:6767") == ("192.0.2.1", 6767)


def test_parse_server_address_shares_the_listener_parser():
    """Three host:port parsers disagreed; this one is no longer its own.

    Measured on the old CLI parser, which split on a lone ':': `[::1]:6767` has
    three, so the whole bracketed string fell through unparsed as a host, while
    `netimps.split_host` read the same text as ('::1', 6767). Note this
    does not make an IPv6 upstream *work* -- `relay._normalize_server_address`
    still calls IPv4() on whatever it gets -- it makes one syntax mean one
    thing.
    """
    assert _parse_server_address("[::1]:6767") == netimps.split_host("[::1]:6767")


def test_parse_server_address_rejects_a_bare_port():
    """An empty host is the wildcard in a listen address, not somewhere to forward to. The old parser turned
    `--server :6767` into ('0.0.0.0', 6767) and relayed into the void."""
    with pytest.raises(ValueError, match="upstream host"):
        _parse_server_address(":6767")


@pytest.mark.parametrize(
    "value, message",
    [
        ("192.0.2.1:+67", "invalid port"),
        ("192.0.2.1: 67", "invalid port"),
        ("192.0.2.1:6_7", "invalid port"),
        ("[192.0.2.1]:67", "bracketed but not an IPv6 address"),
    ],
)
def test_parse_server_address_refuses_a_malformed_port_or_bracket(value, message):
    """The rule is `host:port` with ASCII digits for the port, brackets only
    round an IPv6 literal; `--server` shares it with `--listen`."""
    with pytest.raises(ValueError, match=message):
        _parse_server_address(value)


@pytest.mark.parametrize("listen", ["127.0.0.1:+6767", "[127.0.0.1]:6767"])
def test_relay_listen_flag_refuses_what_the_listener_refuses(listen):
    """`--listen` goes to the same parser as `DHCPListener(listen=)`: the
    command fails with a `ValueError` before it announces anything or binds."""
    with pytest.raises(ValueError):
        Relay(listen=listen, server=("192.0.2.1",))()


def test_relay_cli_relay_help(capsys) -> None:
    # `--help` is status 0. Without this the test passed on the exit code argparse
    # uses for a *usage error* too, so a `relay` subcommand that refused to
    # parse and printed its usage to stdout looked identical to a working one.
    assert main(["relay", "--help"]) == 0
    captured = capsys.readouterr()
    assert "--server" in captured.out
    assert "--max-hops" in captured.out


def test_app_parses_relay_subcommand() -> None:
    parser = App._parser_()
    instance = parser.parse_args(["relay", "--server", "192.0.2.1"])
    assert isinstance(instance, Relay)
    assert tuple(instance.server) == ("192.0.2.1",)


def test_relay_server_default_is_not_shared_between_instances() -> None:
    """`server` must not default to a mutable object owned by the class.

    It used to be `[]`, so `a.server is b.server is Relay.server` and a single
    `.append` rewrote the default that every parser built afterwards would hand
    out. A tuple cannot be appended to at all.
    """
    a = Relay()
    b = Relay()
    assert a.server == () and b.server == ()

    with pytest.raises(AttributeError):
        a.server.append("192.0.2.1")

    a.server = ("192.0.2.1",)
    assert b.server == ()
    assert Relay().server == ()


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["--server", "192.0.2.1"], ("192.0.2.1",)),
        (["-s", "192.0.2.1", "-s", "192.0.2.2"], ("192.0.2.1", "192.0.2.2")),
        (["-s", "192.0.2.1,192.0.2.2:6768"], ("192.0.2.1", "192.0.2.2:6768")),
    ],
)
def test_relay_server_flag_collects_one_or_many(argv, expected) -> None:
    parser = App._parser_()
    instance = parser.parse_args(["relay", *argv])
    assert tuple(instance.server) == expected


@pytest.mark.parametrize("subcommand", ["server", "relay", "capture"])
def test_per_interface_is_reachable_from_every_listening_subcommand(
    subcommand: str,
) -> None:
    """Both DHCPServer and DHCPRelay take `per_interface`; only capture exposed it.

    A supported knob with no CLI route is unreachable -- and `--config` exists
    only on `server`, so relay had no second route either.
    """
    parser = App._parser_()
    needed = ["--server", "192.0.2.1"] if subcommand == "relay" else []
    instance = parser.parse_args([subcommand, "--per-interface", *needed])
    assert instance.per_interface is True
    assert parser.parse_args([subcommand, *needed]).per_interface is False


def test_relay_refuses_the_insert_flag_without_an_id() -> None:
    """The constructor says so before anything is bound or announced."""
    with pytest.raises(ValueError, match="circuit_id or remote_id"):
        Relay(server=("192.0.2.1",), insert_relay_agent_info=True)()


def test_relay_id_misuse_is_reported_as_a_clean_cli_error(monkeypatch, capsys) -> None:
    """main() renders a ValueError as `pydhcp: error:`, status 2, not a traceback."""
    monkeypatch.delenv("PYDHCP_TRACEBACK", raising=False)

    status = main(["relay", "-s", "192.0.2.1", "--circuit-id", "0a01"])

    assert status == 2
    err = capsys.readouterr().err
    assert err.startswith("pydhcp: error:")
    assert "--circuit-id" in err and "--insert-relay-agent-info" in err


@pytest.mark.parametrize("fmt", ["toml", "ini"])
def test_capture_rejects_toml_and_ini_for_multi_record_output(
    fmt, tmp_path, capsys
) -> None:
    """Concatenated records are unreadable in both: TOML has no document
    separator and configparser raises DuplicateSectionError on a second
    section. One record per file is valid.

    The rejection happens when the writer is built, before anything is read or
    bound: the capture file named here does not exist, and had the rejection come
    later the status would be the missing file's, 1.
    """
    if fmt == "toml":
        pytest.importorskip("tomli_w")
    status = main(
        [
            "capture",
            "--read",
            str(tmp_path / "absent.pcap"),
            "--format",
            fmt,
            "--output",
            str(tmp_path / ("caps." + fmt)),
        ]
    )
    err = capsys.readouterr().err
    assert status == 2
    assert err.startswith("pydhcp: error:") and fmt in err and "per_record" in err


def test_verbosity_flags_reach_the_library_logger() -> None:
    """-v has to raise the level of 'pydhcp', which is where the library logs.

    duho resolves the logger on the parsed subcommand instance, so the name has
    to be set there. Set only on App, -v raised a logger named after the
    subcommand ('server', 'relay', ...) and `pydhcp server -v` showed nothing
    from the server at all -- only the undocumented `--loglevel pydhcp:DEBUG`
    worked.
    """
    for argv in (
        ["server", "-v"],
        ["relay", "-v", "-s", "192.0.2.1"],
        ["capture", "-v"],
        ["interfaces", "-v"],
        ["packet", "-v", "--decode"],
    ):
        parsed = App._parser_().parse_args(argv)
        assert parsed._logger_.name == "pydhcp", argv
        assert parsed._set_loglevels_() == {"pydhcp": logging.DEBUG}, argv


def test_missing_ini_config_is_an_error_like_every_other_format(tmp_path) -> None:
    """ConfigParser.read() ignores a path that does not exist, so a typo'd
    --config silently started a server on its defaults -- while the same typo in
    a .toml or .json path raised."""
    # the loader behind the command line is not public
    from pydhcp._config import load_config

    for suffix in (".ini", ".json", ".toml"):
        with pytest.raises((FileNotFoundError, OSError)):
            load_config(str(tmp_path / ("missing" + suffix)))


def test_user_errors_do_not_print_a_traceback(monkeypatch, capsys) -> None:
    """A mistyped port is a user error, not a crash. duho lets exceptions out of
    the command, so these arrived as tracebacks -- including the privileged-port
    hint the listener carefully builds."""
    monkeypatch.delenv("PYDHCP_TRACEBACK", raising=False)
    status = main(["server", "--listen", "127.0.0.1:notaport"])

    # A malformed `--listen` is a wrong invocation, and is refused before the
    # command announces that it is starting.
    assert status == 2
    err = capsys.readouterr().err
    assert err.startswith("pydhcp: error:")
    assert "Traceback" not in err
    assert "Starting" not in err


# --- the program has to call itself what the user typed ---


def _run_module(*argv):
    """Run `python -m pydhcp ...` with this test run's import path.

    The subprocess does not inherit however pytest made `pydhcp` importable --
    an editable install on one machine, a rootdir injection on another -- so
    pass the package's own location explicitly. Without this the test passed on
    a machine with pydhcp installed and failed on one without it.
    """
    import os
    import subprocess
    import sys

    import pydhcp

    src = os.path.dirname(os.path.dirname(os.path.abspath(pydhcp.__file__)))
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([src, env.get("PYTHONPATH", "")]).rstrip(
        os.pathsep
    )
    return subprocess.run(
        [sys.executable, "-m", "pydhcp", *argv],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )


def test_cli_names_itself_pydhcp_not_its_class():
    """duho names the program after the class, which was `App`.

    That appeared in every usage line, every argparse error and `--version` --
    a name that is nowhere the user installed, typed, or could look up.
    """
    for argv in (["--help"], ["--nope"]):
        result = _run_module(*argv)
        output = result.stdout + result.stderr
        assert "usage: pydhcp" in output, output[:200]
        assert "App" not in output, output[:200]


def test_python_dash_m_pydhcp_works():
    """`python -m pydhcp` failed with "No module named pydhcp.__main__".

    The console script is only on PATH after an install; `python -m` is what
    works from a checkout, in a container, or when the interpreter has to be
    named explicitly -- which is when someone is already debugging something.
    """
    # `--help`, not `--version`: `_version_ = AUTO` resolves from installed
    # package metadata, which is absent when running from a checkout, so duho
    # drops the flag entirely there. The point of this test is that the module
    # entry point exists at all.
    result = _run_module("--help")

    assert result.returncode == 0, result.stderr
    assert "No module named" not in result.stderr
    assert "usage: pydhcp" in result.stdout
