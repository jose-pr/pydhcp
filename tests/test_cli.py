from __future__ import annotations

import argparse
import io
import json
import logging
import os
import pathlib
import sys
import ipaddress
from unittest.mock import MagicMock, patch

import pytest
from datetime import datetime, timedelta, timezone

from pydhcp import (
    CaptureEvent,
    DHCPMessage,
    DHCPOptions,
    NetworkInterface,
    DHCPRequestContext,
)
from pydhcp.cli import App, Capture, Interfaces, Packet, Relay, Server, main

# the hook loader is not public
from pydhcp.cli._capture_hook import _load_capture_hook

# the relay command's parser is not public
from pydhcp.cli._relay import _parse_server_address

# the loader behind the command line is not public
from pydhcp._config import load_config
from pydhcp.packet import DHCPMessageType, DHCPFlags, HardwareAddressType, DHCPOpcode
from pydhcp.options import DHCPOptionCode
from netimps import MACAddress
from ipaddress import IPv4Address as IPv4
from pydhcp import SocketAddress
from conftest import build_request


def test_cmd_interfaces(capsys, monkeypatch) -> None:
    """`assert mock_print.called` was the whole test: the header alone satisfied
    it, so an `interfaces` that enumerated nothing, or printed the wrong field
    for every adapter, passed. Enumeration is stubbed because the real one
    depends on the host -- what is under test is the rendering."""
    monkeypatch.setattr(
        "pydhcp.cli._interfaces.host_ip_interfaces",
        lambda *args, **kwargs: iter(
            [
                NetworkInterface(
                    "eth0",
                    ipaddress.IPv4Interface("10.0.0.5/24"),
                    MACAddress(b"\x00\x11\x22\x33\x44\x55"),
                ),
                NetworkInterface("lo", ipaddress.IPv4Interface("127.0.0.1/8")),
            ]
        ),
    )

    assert main(["interfaces"]) == 0

    assert capsys.readouterr().out.splitlines() == [
        "eth0\t10.0.0.5\t00-11-22-33-44-55\t10.0.0.0/24",
        "lo\t127.0.0.1\t-\t127.0.0.0/8",
    ]


def _sample_packet() -> DHCPMessage:
    return build_request(DHCPMessageType.DHCPDISCOVER)


def _capture_event() -> CaptureEvent:
    return CaptureEvent(
        message=_sample_packet(),
        context=DHCPRequestContext(
            transport=MagicMock(),
            interface=NetworkInterface("lo", ipaddress.IPv4Interface("127.0.0.1/24")),
            client=SocketAddress("127.0.0.1", 68),
            client_mac=b"\x00\x11\x22\x33\x44\x55",
            local_ip=IPv4("127.0.0.1"),
        ),
        captured_at=datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc),
    )


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


def test_load_capture_hook_python_function(tmp_path, monkeypatch) -> None:
    module = tmp_path / "hooks.py"
    module.write_text(
        "seen = []\ndef on_capture(event):\n    seen.append(event.message_type)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    hook = _load_capture_hook("hooks:on_capture", "json", False)
    assert hook is not None
    hook(_capture_event())

    assert sys.modules["hooks"].seen == ["DHCPDISCOVER"]


def _write_hook(directory, name: str, label: str):
    """A real program that records its stdin and a marker in `directory`.

    A script is the program on POSIX and a `.cmd` file on Windows; either is
    started the way the command hook starts it, by path, with no mock.
    """
    if os.name == "nt":
        program = directory / (name + ".cmd")
        text = (
            "@echo off\r\n"
            'findstr "^" > "%~dp0' + label + '.stdin"\r\n'
            'echo %PYDHCP_CAPTURE_MSG_TYPE%> "%~dp0' + label + '.type"\r\n'
        )
    else:
        program = directory / name
        text = (
            "#!/bin/sh\n"
            'cat > "$(dirname "$0")/' + label + '.stdin"\n'
            'echo "$PYDHCP_CAPTURE_MSG_TYPE" > "$(dirname "$0")/' + label + '.type"\n'
        )
    program.write_bytes(text.encode("utf-8"))
    if os.name != "nt":
        program.chmod(0o755)
    return program


def _suffix() -> str:
    return ".cmd" if os.name == "nt" else ""


def test_load_capture_hook_command_gets_stdin_and_env(tmp_path, monkeypatch) -> None:
    _write_hook(tmp_path, "hook-command", "ran")
    monkeypatch.chdir(tmp_path)

    hook = _load_capture_hook("./hook-command" + _suffix(), "json", False)
    assert hook is not None
    hook(_capture_event())

    assert json.loads((tmp_path / "ran.stdin").read_text())["xid"] == 0x12345678
    assert (tmp_path / "ran.type").read_text().strip() == "DHCPDISCOVER"


def test_a_relative_hook_path_is_fixed_when_the_hook_is_loaded(
    tmp_path, monkeypatch
) -> None:
    """`./name` names the file in the working directory when it is loaded, and a
    later change of directory does not move it."""
    here = tmp_path / "here"
    elsewhere = tmp_path / "elsewhere"
    here.mkdir()
    elsewhere.mkdir()
    _write_hook(here, "hook", "ran")
    monkeypatch.chdir(here)
    hook = _load_capture_hook("./hook" + _suffix(), "json", False)
    assert hook is not None

    monkeypatch.chdir(elsewhere)
    hook(_capture_event())

    assert (here / "ran.type").read_text().strip() == "DHCPDISCOVER"


@pytest.mark.skipif(
    os.name == "nt",
    reason="a bare name is searched in the working directory on Windows",
)
def test_a_relative_hook_path_does_not_start_the_program_of_that_name_on_path(
    tmp_path, monkeypatch
) -> None:
    """`str(Path("./logger"))` is `logger`, and a name with no directory is looked
    up on PATH on POSIX: `--hook ./logger` started /usr/bin/logger."""
    on_path = tmp_path / "bin"
    cwd = tmp_path / "cwd"
    on_path.mkdir()
    cwd.mkdir()
    _write_hook(on_path, "hook", "from-path")
    _write_hook(cwd, "hook", "from-cwd")
    monkeypatch.setenv("PATH", str(on_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.chdir(cwd)

    hook = _load_capture_hook("./hook", "json", False)
    assert hook is not None
    hook(_capture_event())

    assert (cwd / "from-cwd.type").exists()
    assert not (on_path / "from-path.type").exists()


@pytest.mark.skipif(os.name == "nt", reason="PATH lookup of a script needs PATHEXT")
def test_a_bare_hook_name_is_looked_up_on_path(tmp_path, monkeypatch) -> None:
    on_path = tmp_path / "bin"
    cwd = tmp_path / "cwd"
    on_path.mkdir()
    cwd.mkdir()
    _write_hook(on_path, "pydhcp-test-hook", "from-path")
    monkeypatch.setenv("PATH", str(on_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.chdir(cwd)

    hook = _load_capture_hook("pydhcp-test-hook", "json", False)
    assert hook is not None
    hook(_capture_event())

    assert (on_path / "from-path.type").exists()


@pytest.mark.skipif(
    os.name == "nt",
    reason="a bare name is searched in the working directory on Windows",
)
def test_a_bare_name_that_is_only_in_the_working_directory_says_to_use_a_path(
    tmp_path, monkeypatch
) -> None:
    _write_hook(tmp_path, "pydhcp-test-local-hook", "ran")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match=r"\./pydhcp-test-local-hook"):
        _load_capture_hook("pydhcp-test-local-hook", "json", False)


@pytest.mark.skipif(os.name == "nt", reason="Windows has no executable bit")
def test_a_hook_that_is_not_executable_is_refused_at_start(
    tmp_path, monkeypatch
) -> None:
    program = _write_hook(tmp_path, "hook", "ran")
    program.chmod(0o644)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="not executable"):
        _load_capture_hook("./hook", "json", False)


def test_cmd_capture_uses_fake_capture_and_count(monkeypatch, capsys) -> None:
    """`--count N` writes N records and then stops the capture.

    `stopped` was set by the fake and never read, and one event was offered
    against a `count` of 1 -- so nothing distinguished "stopped after the
    first" from "there was only ever one". Three events against a count of two
    is the smallest arrangement where a `--count` that never fires, or fires on
    the wrong record, changes the result.
    """
    events = []
    for xid in (0xAAAA0001, 0xAAAA0002, 0xAAAA0003):
        event = _capture_event()
        event.message.xid = xid
        events.append(event)

    captures = []

    class FakeCapture:
        def __init__(
            self, listen, packet_filter, sink, hook, hook_fail_fast, per_interface
        ):
            self.sink = sink
            self.hook = hook
            self.stopped = False
            self.delivered = []
            # Part of the contract the CLI reads after serve_forever() returns, to tell
            # a hook failure from an ordinary shutdown.
            self.hook_error = None
            captures.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

        def serve_forever(self):
            # A real listener stops feeding the sink once shutdown() is called;
            # without honouring it here, `--count` could not be observed.
            for event in events:
                if self.stopped:
                    return
                self.delivered.append(event.message.xid)
                self.sink(event)
                if self.hook is not None:
                    self.hook(event)

        def shutdown(self):
            self.stopped = True

    monkeypatch.setattr("pydhcp.cli._capture.DHCPCapture", FakeCapture)
    cmd = Capture(
        listen="127.0.0.1:6767",
        packet_filter="msg_type=DHCPDISCOVER",
        packet_format="json",
        output="-",
        count=2,
        hook=None,
        hook_fail_fast=False,
        per_interface=False,
    )

    cmd()

    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [record["xid"] for record in records] == [0xAAAA0001, 0xAAAA0002]
    assert [record["options"]["DHCP_MESSAGE_TYPE"] for record in records] == [
        "DHCPDISCOVER",
        "DHCPDISCOVER",
    ]
    assert len(captures) == 1
    # shutdown() was actually called, and on the second record rather than later.
    assert captures[0].stopped is True
    assert captures[0].delivered == [0xAAAA0001, 0xAAAA0002]


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


@patch("pydhcp.cli._server.DHCPServer")
def test_cmd_server(mock_dhcp_server_cls):
    mock_server = MagicMock()
    mock_dhcp_server_cls.return_value = mock_server

    cmd = Server(config=None, listen="127.0.0.1:6767")
    cmd()

    mock_dhcp_server_cls.assert_called_with(
        listen="127.0.0.1:6767", per_interface=False, lease_backend=None
    )
    assert mock_server.serve_forever.called


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
    `listener._split_host_port` read the same text as ('::1', 6767). Note this
    does not make an IPv6 upstream *work* -- `relay._normalize_server_address`
    still calls IPv4() on whatever it gets -- it makes one syntax mean one
    thing.
    """
    # the listen-argument parser is not public
    from pydhcp.listener._spec import _split_host_port

    assert _parse_server_address("[::1]:6767") == _split_host_port("[::1]:6767")


def test_parse_server_address_rejects_a_bare_port():
    """`_split_host_port` defaults an empty host to the wildcard, which is a
    listen address, not somewhere to forward to. The old parser turned
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


@patch("pydhcp.cli._relay.DHCPRelay")
def test_cmd_relay(mock_dhcp_relay_cls):
    mock_relay = MagicMock()
    mock_dhcp_relay_cls.return_value = mock_relay

    cmd = Relay(
        listen="127.0.0.1:6767",
        server=("192.0.2.1", "192.0.2.2:6768"),
        max_hops=10,
        insert_relay_agent_info=True,
        circuit_id="aabb",
        remote_id=None,
    )
    cmd()

    mock_dhcp_relay_cls.assert_called_with(
        listen="127.0.0.1:6767",
        server_addresses=[("192.0.2.1", 67), ("192.0.2.2", 6768)],
        max_hops=10,
        insert_relay_agent_info=True,
        circuit_id=b"\xaa\xbb",
        remote_id=None,
        per_interface=False,
    )
    assert mock_relay.serve_forever.called


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


@patch("pydhcp.cli._server.DHCPServer")
def test_cmd_server_forwards_per_interface(mock_dhcp_server_cls) -> None:
    Server(config=None, listen="127.0.0.1:6767", per_interface=True)()

    mock_dhcp_server_cls.assert_called_with(
        listen="127.0.0.1:6767", per_interface=True, lease_backend=None
    )


@patch("pydhcp.cli._relay.DHCPRelay")
def test_cmd_relay_forwards_per_interface(mock_dhcp_relay_cls) -> None:
    Relay(server=("192.0.2.1",), per_interface=True)()

    assert mock_dhcp_relay_cls.call_args.kwargs["per_interface"] is True


@pytest.mark.parametrize(
    "flag, value",
    [("circuit_id", "0a01"), ("remote_id", "0b02")],
)
@patch("pydhcp.cli._relay.DHCPRelay")
def test_relay_rejects_ids_without_insert_flag(
    mock_dhcp_relay_cls, flag: str, value: str
) -> None:
    """The help text promised this; nothing enforced it.

    `_insert_relay_agent_info` returns early when the flag is off, so the ids
    were silently discarded and upstream servers saw no option 82.
    """
    cmd = Relay(server=("192.0.2.1",), **{flag: value})
    with pytest.raises(ValueError) as error:
        cmd()

    message = str(error.value)
    assert f"--{flag.replace('_', '-')}" in message
    assert "--insert-relay-agent-info" in message
    assert not mock_dhcp_relay_cls.called


@patch("pydhcp.cli._relay.DHCPRelay")
def test_relay_accepts_ids_with_insert_flag(mock_dhcp_relay_cls) -> None:
    Relay(
        server=("192.0.2.1",),
        insert_relay_agent_info=True,
        circuit_id="0a01",
        remote_id="0b02",
    )()

    kwargs = mock_dhcp_relay_cls.call_args.kwargs
    assert kwargs["insert_relay_agent_info"] is True
    assert kwargs["circuit_id"] == b"\x0a\x01"
    assert kwargs["remote_id"] == b"\x0b\x02"


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
def test_capture_rejects_toml_and_ini_for_multi_record_output(fmt, capsys) -> None:
    """Concatenated records are unreadable in both: TOML has no document
    separator and configparser raises DuplicateSectionError on a second
    [message]. per-capture writes one record per file, which is valid.

    The rejection has to happen before binding. Without it this call does not
    raise at all -- it opens sockets and captures until interrupted, which is
    why this test is not run against the pre-fix tree.
    """
    if fmt == "toml":
        pytest.importorskip("tomli_w")
    command = Capture()
    command.packet_format = fmt
    command.output = pathlib.Path("caps." + fmt)
    with pytest.raises(ValueError) as error:
        command()
    message = str(error.value)
    assert "per-capture" in message and fmt in message
    assert main(["capture", "--format", fmt, "--output", "caps." + fmt]) == 2
    assert "per-capture" in capsys.readouterr().err


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


def test_explicit_listen_beats_the_config_file(tmp_path, monkeypatch) -> None:
    """CLI over config, as every other tool does. The other order gave no way to
    override a shared config for a single run."""
    config = tmp_path / "server.json"
    config.write_text(json.dumps({"server": {"listen": "127.0.0.1:47001"}}), "utf-8")
    captured = {}

    class FakeServer:
        def __init__(self, listen, per_interface=False, lease_backend=None):
            captured["listen"] = listen
            captured["per_interface"] = per_interface
            self.lease_backend = lease_backend

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

        def serve_forever(self):
            raise KeyboardInterrupt

    monkeypatch.setattr("pydhcp.cli._server.DHCPServer", FakeServer)

    assert main(["server", "--config", str(config), "--listen", "127.0.0.1:47002"]) == 0
    assert (
        captured["listen"] == "127.0.0.1:47002"
    ), "the config overrode an explicit flag"

    # and without the flag the config is still used
    assert main(["server", "--config", str(config)]) == 0
    assert captured["listen"] == "127.0.0.1:47001"


def test_missing_ini_config_is_an_error_like_every_other_format(tmp_path) -> None:
    """ConfigParser.read() ignores a path that does not exist, so a typo'd
    --config silently started a server on its defaults -- while the same typo in
    a .yaml or .json path raised."""
    # the loader behind the command line is not public
    from pydhcp._config import load_config

    for suffix in (".ini", ".json", ".yaml"):
        with pytest.raises((FileNotFoundError, OSError)):
            load_config(str(tmp_path / ("missing" + suffix)))


def test_hook_module_is_importable_from_the_working_directory(tmp_path, monkeypatch):
    """The documented `--hook myhooks:on_capture` form.

    A console script's sys.path[0] is its own Scripts directory, so a module
    next to the user was not importable and capture refused to start.
    """
    (tmp_path / "myhooks.py").write_text(
        "seen = []\ndef on_capture(event):\n    seen.append(1)\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delitem(sys.modules, "myhooks", raising=False)
    # cwd is deliberately NOT on sys.path, as it is not for a console script
    monkeypatch.setattr(
        sys, "path", [p for p in sys.path if p not in ("", str(tmp_path))]
    )

    hook = _load_capture_hook("myhooks:on_capture", "json", False)

    assert hook is not None
    hook(_capture_event())
    assert sys.modules["myhooks"].seen == [1]
    # and the directory is not left on sys.path afterwards
    assert str(tmp_path) not in sys.path


def test_windows_drive_letter_hook_path_is_not_read_as_a_module() -> None:
    r"""C:\hooks\export.exe has exactly one ':' and was reported as
    "No module named 'C'"."""
    with pytest.raises(ValueError, match="does not exist"):
        _load_capture_hook(r"C:\hooks\does-not-exist.exe", "json", False)


def test_capture_destination_port_is_the_port_received_on() -> None:
    """dst_port is a documented filter key, but destination always had port 0,
    so a filter using it silently matched nothing."""
    import socket as _socket

    from pydhcp.listener import UDPTransport

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    bound_port = sock.getsockname()[1]
    try:
        event = CaptureEvent(
            message=_sample_packet(),
            context=DHCPRequestContext(
                transport=UDPTransport(sock),
                interface=NetworkInterface(
                    "lo", ipaddress.IPv4Interface("127.0.0.1/24")
                ),
                client=SocketAddress("127.0.0.1", 68),
                client_mac=b"\x00\x11\x22\x33\x44\x55",
                local_ip=IPv4("127.0.0.1"),
            ),
            captured_at=datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc),
        )

        assert event.destination.port == bound_port

        from pydhcp.capture import compile_capture_filter

        assert compile_capture_filter(f"dst_port={bound_port}")(event)
        assert not compile_capture_filter("dst_port=1")(event)
    finally:
        sock.close()


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
