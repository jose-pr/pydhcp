from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
import ipaddress
from unittest.mock import MagicMock, patch

import pytest
from datetime import datetime, timedelta, timezone

from pydhcp import (
    CaptureEvent,
    DhcpMessage,
    DhcpOptions,
    NetworkInterface,
    RequestContext,
)
from pydhcp.cli import (
    App,
    Capture,
    Interfaces,
    Packet,
    Relay,
    Server,
    _infer_capture_format,
    _load_capture_hook,
    _parse_server_address,
    _write_capture_record,
    main,
)
from pydhcp.config import load_config
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.packet.structured import dump_message
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4, SocketAddress


def test_cmd_interfaces():
    with patch("builtins.print") as mock_print:
        Interfaces()()
        assert mock_print.called


def _sample_packet() -> DhcpMessage:
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    return DhcpMessage(
        op=OpCode.BOOTREQUEST,
        htype=HardwareAddressType.ETHERNET,
        hlen=6,
        hops=0,
        xid=0x12345678,
        secs=timedelta(seconds=0),
        flags=Flags.UNICAST,
        ciaddr=IPv4("0.0.0.0"),
        yiaddr=IPv4("0.0.0.0"),
        siaddr=IPv4("0.0.0.0"),
        giaddr=IPv4("0.0.0.0"),
        chaddr=b"\x00\x11\x22\x33\x44\x55",
        sname="",
        file="",
        options=options,
    )


def _capture_event() -> CaptureEvent:
    return CaptureEvent(
        message=_sample_packet(),
        context=RequestContext(
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
    cmd = Packet(mode=True, packet_format="json", input="-", output="-")
    monkeypatch.setattr("sys.stdin", io.StringIO(packet.encode().hex()))

    cmd()

    assert json.loads(capsys.readouterr().out) == packet.to_mapping()


def test_cmd_packet_decode_summary(capsys, monkeypatch) -> None:
    packet = _sample_packet()
    cmd = Packet(mode=True, packet_format="summary", input="-", output="-")
    monkeypatch.setattr("sys.stdin", io.StringIO(packet.encode().hex()))

    cmd()

    output = capsys.readouterr().out
    assert "BOOTREQUEST XID=12345678 Src: capture Dst: decoded" in output
    assert "OPTIONS:" in output


def test_cmd_packet_malformed_exits_with_error(capsys, monkeypatch) -> None:
    cmd = Packet(mode=True, packet_format="json", input="-", output="-")
    monkeypatch.setattr("sys.stdin", io.StringIO("00"))

    with pytest.raises(SystemExit) as exc_info:
        cmd()

    assert exc_info.value.code == 1
    assert "too short for DHCP fixed header" in capsys.readouterr().err


def test_cmd_packet_encode_from_file(tmp_path) -> None:
    packet = _sample_packet()
    source = tmp_path / "packet.json"
    source.write_text(dump_message(packet, "json"), encoding="utf-8")
    output = tmp_path / "packet.hex"
    cmd = Packet(
        mode=False, packet_format="json", input=str(source), output=str(output)
    )

    cmd()

    assert output.read_text(encoding="utf-8") == packet.encode().hex()


def test_packet_cli_main_encode_from_stdin(monkeypatch, capsys) -> None:
    packet = _sample_packet()
    monkeypatch.setattr(
        "sys.argv",
        ["pydhcp", "packet", "--encode", "--input", "-", "--format", "json"],
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(dump_message(packet, "json")))

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == packet.encode().hex()


def test_capture_format_inference() -> None:
    assert _infer_capture_format("-", None) == "json"
    assert _infer_capture_format("capture.yml", None) == "yaml"
    assert _infer_capture_format("capture.toml", None) == "toml"
    assert _infer_capture_format("capture.ini", "json") == "json"


def test_write_capture_record_to_stdout(capsys) -> None:
    state = {"first": True}

    _write_capture_record(
        _capture_event(),
        output="-",
        output_mode="stream",
        packet_format="json",
        state=state,
    )

    assert json.loads(capsys.readouterr().out)["xid"] == 0x12345678


def test_write_capture_record_single_file_appends(tmp_path) -> None:
    output = tmp_path / "captures.json"
    state = {"first": True}

    _write_capture_record(
        _capture_event(),
        output=output,
        output_mode="single",
        packet_format="json",
        state=state,
    )
    _write_capture_record(
        _capture_event(),
        output=output,
        output_mode="single",
        packet_format="json",
        state=state,
    )

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["xid"] for line in lines] == [0x12345678, 0x12345678]


def test_write_capture_record_per_capture_pattern(tmp_path) -> None:
    pattern = tmp_path / "{client_id}" / "{timestamp}_{msg_type}.{format}"

    _write_capture_record(
        _capture_event(),
        output=pattern,
        output_mode="per-capture",
        packet_format="json",
        state={"first": True},
    )

    files = list(tmp_path.rglob("*.json"))
    assert len(files) == 1
    assert "DHCPDISCOVER" in files[0].name
    assert json.loads(files[0].read_text(encoding="utf-8"))["op"] == "BOOTREQUEST"


def test_write_capture_record_rejects_stdout_per_capture() -> None:
    with pytest.raises(ValueError):
        _write_capture_record(
            _capture_event(),
            output="-",
            output_mode="per-capture",
            packet_format="json",
            state={"first": True},
        )


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


def test_load_capture_hook_command_gets_stdin_and_env(tmp_path, monkeypatch) -> None:
    command = tmp_path / "hook-command"
    command.write_text("", encoding="utf-8")
    calls = []

    def fake_run(args, input, text, capture_output, env, timeout=None):
        calls.append((args, input, text, capture_output, env, timeout))
        return argparse.Namespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr("pydhcp.cli.subprocess.run", fake_run)

    hook = _load_capture_hook(str(command), "json", False)
    assert hook is not None
    hook(_capture_event())

    args, payload, text, capture_output, env, timeout = calls[0]
    assert args == [str(command)]
    # the hook runs on the receive thread, so it must not be able to hang it
    assert timeout is not None and timeout > 0
    assert json.loads(payload)["xid"] == 0x12345678
    assert text is True
    assert capture_output is True
    assert env["PYDHCP_CAPTURE_MSG_TYPE"] == "DHCPDISCOVER"


def test_cmd_capture_uses_fake_capture_and_count(monkeypatch, capsys) -> None:
    events = [_capture_event()]

    class FakeCapture:
        def __init__(
            self, listen, packet_filter, sink, hook, hook_fail_fast, per_interface
        ):
            self.sink = sink
            self.hook = hook
            self.stopped = False
            # Part of the contract the CLI reads after listen() returns, to tell
            # a hook failure from an ordinary shutdown.
            self.hook_error = None

        def bind(self):
            pass

        def listen(self):
            self.sink(events[0])
            if self.hook is not None:
                self.hook(events[0])

        def stop(self):
            self.stopped = True

    monkeypatch.setattr("pydhcp.cli.DhcpCapture", FakeCapture)
    cmd = Capture(
        listen="127.0.0.1:6767",
        packet_filter="msg_type=DHCPDISCOVER",
        packet_format="json",
        output="-",
        output_mode="stream",
        count=1,
        hook=None,
        hook_fail_fast=False,
        per_interface=False,
    )

    cmd()

    assert (
        json.loads(capsys.readouterr().out)["options"]["DHCP_MESSAGE_TYPE"]
        == "DHCPDISCOVER"
    )


def test_capture_cli_main_help_lists_capture(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.argv", ["pydhcp", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0
    assert "capture" in capsys.readouterr().out


def test_capture_cli_main_capture_help(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.argv", ["pydhcp", "capture", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    output = capsys.readouterr().out
    assert exc_info.value.code == 0
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


@patch("pydhcp.cli.DhcpServer")
def test_cmd_server(mock_dhcp_server_cls):
    mock_server = MagicMock()
    mock_dhcp_server_cls.return_value = mock_server

    cmd = Server(config=None, listen="127.0.0.1:6767")
    cmd()

    mock_dhcp_server_cls.assert_called_with(listen="127.0.0.1:6767")
    assert mock_server.bind.called
    assert mock_server.listen.called


def test_parse_server_address_host_only():
    assert _parse_server_address("192.0.2.1") == "192.0.2.1"


def test_parse_server_address_host_port():
    assert _parse_server_address("192.0.2.1:6767") == ("192.0.2.1", 6767)


@patch("pydhcp.cli.DhcpRelay")
def test_cmd_relay(mock_dhcp_relay_cls):
    mock_relay = MagicMock()
    mock_dhcp_relay_cls.return_value = mock_relay

    cmd = Relay(
        listen="127.0.0.1:6767",
        server=["192.0.2.1", "192.0.2.2:6768"],
        max_hops=10,
        insert_relay_agent_info=True,
        circuit_id="aabb",
        remote_id=None,
    )
    cmd()

    mock_dhcp_relay_cls.assert_called_with(
        listen="127.0.0.1:6767",
        server_addresses=["192.0.2.1", ("192.0.2.2", 6768)],
        max_hops=10,
        insert_relay_agent_info=True,
        circuit_id=b"\xaa\xbb",
        remote_id=None,
    )
    assert mock_relay.bind.called
    assert mock_relay.listen.called


def test_relay_cli_relay_help(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["pydhcp", "relay", "--help"])
    with pytest.raises(SystemExit):
        main()
    captured = capsys.readouterr()
    assert "--server" in captured.out
    assert "--max-hops" in captured.out


def test_app_parses_relay_subcommand() -> None:
    parser = App._parser_()
    instance = parser.parse_args(["relay", "--server", "192.0.2.1"])
    assert isinstance(instance, Relay)
    assert instance.server == ["192.0.2.1"]


def test_yaml_capture_survives_a_second_run(tmp_path) -> None:
    """The 'first record' flag is per process, but the file is opened for append.

    A second run's first record used to be written straight onto the last record
    of the first with no '---', so YAML merged the two mappings and the earlier
    record silently disappeared on load: four records written, three loaded.
    """
    import yaml

    output = tmp_path / "captures.yaml"
    for _run in range(2):
        state = {"first": True}  # fresh per run, exactly as the CLI builds it
        for _record in range(2):
            _write_capture_record(
                _capture_event(),
                output=output,
                output_mode="single",
                packet_format="yaml",
                state=state,
            )

    documents = [d for d in yaml.safe_load_all(output.read_text(encoding="utf-8")) if d]
    assert len(documents) == 4, "a record was merged away across runs"


def test_capture_rejects_toml_and_ini_for_multi_record_output(capsys) -> None:
    """Concatenated records are unreadable in both: TOML has no document
    separator and configparser raises DuplicateSectionError on a second
    [message]. per-capture writes one record per file, which is valid.

    The rejection has to happen before binding. Without it this call does not
    raise at all -- it opens sockets and captures until interrupted, which is
    why this test is not run against the pre-fix tree.
    """
    import pathlib

    import pytest

    from pydhcp.cli import Capture

    for fmt in ("toml", "ini"):
        command = Capture()
        command.packet_format = fmt
        command.output = pathlib.Path("caps." + fmt)
        command.output_mode = "single"
        with pytest.raises(SystemExit) as exit_info:
            command()
        assert exit_info.value.code == 1
        message = capsys.readouterr().err
        assert "per-capture" in message and fmt in message


def test_capture_allows_toml_per_capture(tmp_path) -> None:
    """One record per file is the shape these formats do support."""
    # Writing TOML is the `toml` extra's job, not a base install's -- without the
    # skip this fails on any environment that has only [dev], which is exactly
    # what a contributor gets from the documented setup command.
    pytest.importorskip("tomli_w")
    pattern = tmp_path / "{timestamp}_{msg_type}.{format}"

    _write_capture_record(
        _capture_event(),
        output=pattern,
        output_mode="per-capture",
        packet_format="toml",
        state={"first": True},
    )

    written = list(tmp_path.glob("*.toml"))
    assert len(written) == 1


def test_capture_stdout_stream_flushes_each_record(monkeypatch) -> None:
    """Piped into `jq` or `tee`, stdout is block-buffered: a live capture showed
    nothing for ~8 KB or until it exited, and lost whatever was buffered if it
    was killed."""
    import io

    class CountingStdout(io.StringIO):
        flushes = 0

        def flush(self) -> None:
            type(self).flushes += 1

    stdout = CountingStdout()
    monkeypatch.setattr(sys, "stdout", stdout)

    for _ in range(3):
        _write_capture_record(
            _capture_event(),
            output=None,
            output_mode="stream",
            packet_format="json",
            state={"first": True},
        )

    assert CountingStdout.flushes >= 3, "records are not flushed as they are written"


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
        ["relay", "-v"],
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
        def __init__(self, listen):
            captured["listen"] = listen

        def bind(self):
            pass

        def listen(self):
            raise KeyboardInterrupt

        def stop(self):
            pass

    monkeypatch.setattr("pydhcp.cli.DhcpServer", FakeServer)

    command = Server()
    command.config = str(config)
    command.listen = "127.0.0.1:47002"
    command()
    assert (
        captured["listen"] == "127.0.0.1:47002"
    ), "the config overrode an explicit flag"

    # and without the flag the config is still used
    command = Server()
    command.config = str(config)
    command.listen = None
    command()
    assert captured["listen"] == "127.0.0.1:47001"


def test_missing_ini_config_is_an_error_like_every_other_format(tmp_path) -> None:
    """ConfigParser.read() ignores a path that does not exist, so a typo'd
    --config silently started a server on its defaults -- while the same typo in
    a .yaml or .json path raised."""
    from pydhcp.config import load_config

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

    from pydhcp.listener import UdpTransport

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    bound_port = sock.getsockname()[1]
    try:
        event = CaptureEvent(
            message=_sample_packet(),
            context=RequestContext(
                transport=UdpTransport(sock),
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
    monkeypatch.setattr(
        "sys.argv", ["pydhcp", "server", "--listen", "127.0.0.1:notaport"]
    )

    with pytest.raises(SystemExit) as exit_info:
        main()

    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("pydhcp: error:")
    assert "Traceback" not in err


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


# --- a client must not decide how many files land on the operator's disk ---


def _capture_event_with_client_id(client_id: bytes):
    """A capture event whose client identifier the 'client' chose."""
    import datetime as _dt
    import ipaddress
    from datetime import timedelta
    from unittest.mock import Mock

    from pydhcp.capture import CaptureEvent
    from pydhcp.listener import RequestContext
    from pydhcp.network import IPv4, NetworkInterface, SocketAddress
    from pydhcp.options import DhcpOptionCode, DhcpOptions
    from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
    from pydhcp.packet.message import DhcpMessage

    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    options[DhcpOptionCode.CLIENT_IDENTIFIER] = bytearray(client_id)
    message = DhcpMessage(
        OpCode.BOOTREQUEST,
        HardwareAddressType.ETHERNET,
        6,
        0,
        0x1234,
        timedelta(0),
        Flags.UNICAST,
        IPv4("0.0.0.0"),
        IPv4("0.0.0.0"),
        IPv4("0.0.0.0"),
        IPv4("0.0.0.0"),
        b"\x00\x11\x22\x33\x44\x55",
        "",
        "",
        options,
    )
    context = RequestContext(
        transport=Mock(),
        interface=NetworkInterface(
            "eth0", ipaddress.IPv4Interface("10.0.0.1/24"), None
        ),
        client=SocketAddress(IPv4("10.0.0.50"), 68),
        client_mac=b"\x00\x11\x22\x33\x44\x55",
    )
    return CaptureEvent(message, context, _dt.datetime.now(tz=_dt.timezone.utc))


def test_per_capture_file_count_is_bounded(tmp_path, caplog):
    """The filename pattern interpolates values the client chooses.

    Measured before the cap: 5,000 forged client identifiers produced 5,000
    files. An unauthenticated sender decided how much of the operator's disk to
    use, and `capture` is exactly what an operator leaves running.
    """
    import logging

    from pydhcp import cli

    pattern = str(tmp_path / "{client_id}.{format}")
    state: dict = {"first": True}

    with caplog.at_level(logging.WARNING, logger="pydhcp"):
        for index in range(cli.MAX_PER_CAPTURE_FILES + 50):
            cli._write_capture_record(
                _capture_event_with_client_id(b"\xff" + index.to_bytes(4, "big")),
                output=pattern,
                output_mode="per-capture",
                packet_format="json",
                state=state,
            )

    assert len(list(tmp_path.iterdir())) == cli.MAX_PER_CAPTURE_FILES
    assert state["per_capture_refused"] == 50
    # reported once, not once per refused packet -- the thing filling the disk
    # is a flood, so a line each would hand over the log as a second target
    reports = [r for r in caplog.records if "per-capture files" in r.getMessage()]
    assert len(reports) == 1, len(reports)


def test_a_pattern_the_client_cannot_influence_is_not_limited(tmp_path):
    """A fixed pattern overwrites one file, so the cap must not apply to it.

    Counting distinct paths rather than writes is what keeps this case free:
    the same name is rewritten, and rewriting is always allowed.
    """
    from pydhcp import cli

    pattern = str(tmp_path / "capture.{format}")
    state: dict = {"first": True}

    for index in range(cli.MAX_PER_CAPTURE_FILES + 200):
        cli._write_capture_record(
            _capture_event_with_client_id(b"\xff" + index.to_bytes(4, "big")),
            output=pattern,
            output_mode="per-capture",
            packet_format="json",
            state=state,
        )

    assert [p.name for p in tmp_path.iterdir()] == ["capture.json"]
    assert state.get("per_capture_refused", 0) == 0
