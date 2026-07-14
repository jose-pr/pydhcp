from __future__ import annotations

import argparse
import io
import json
import os
import sys
import ipaddress
from unittest.mock import MagicMock, patch

import pytest
from datetime import datetime, timedelta, timezone

from pydhcp import CaptureEvent, DhcpMessage, DhcpOptions, NetworkInterface, RequestContext
from pydhcp.cli import (
    _infer_capture_format,
    _load_capture_hook,
    _parse_server_address,
    _write_capture_record,
    cmd_capture,
    cmd_interfaces,
    cmd_packet,
    cmd_relay,
    cmd_server,
    main,
)
from pydhcp.config import load_config
from pydhcp.packet import DhcpMessageType, Flags, HardwareAddressType, OpCode
from pydhcp.packet.structured import dump_message
from pydhcp.options import DhcpOptionCode
from pydhcp.network import IPv4, SocketAddress


def test_cmd_interfaces():
    # Verify it runs without exceptions
    args = argparse.Namespace()
    with patch("builtins.print") as mock_print:
        cmd_interfaces(args)
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
    args = argparse.Namespace(
        mode="decode",
        packet_format="json",
        input="-",
        output="-",
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(packet.encode().hex()))

    cmd_packet(args)

    assert json.loads(capsys.readouterr().out) == packet.to_mapping()


def test_cmd_packet_decode_summary(capsys, monkeypatch) -> None:
    packet = _sample_packet()
    args = argparse.Namespace(
        mode="decode",
        packet_format="summary",
        input="-",
        output="-",
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(packet.encode().hex()))

    cmd_packet(args)

    output = capsys.readouterr().out
    assert "BOOTREQUEST XID=12345678 Src: capture Dst: decoded" in output
    assert "OPTIONS:" in output


def test_cmd_packet_malformed_exits_with_error(capsys, monkeypatch) -> None:
    args = argparse.Namespace(
        mode="decode",
        packet_format="json",
        input="-",
        output="-",
    )
    monkeypatch.setattr("sys.stdin", io.StringIO("00"))

    with pytest.raises(SystemExit) as exc_info:
        cmd_packet(args)

    assert exc_info.value.code == 1
    assert "too short for DHCP fixed header" in capsys.readouterr().err


def test_cmd_packet_encode_from_file(tmp_path) -> None:
    packet = _sample_packet()
    source = tmp_path / "packet.json"
    source.write_text(dump_message(packet, "json"), encoding="utf-8")
    output = tmp_path / "packet.hex"
    args = argparse.Namespace(
        mode="encode",
        packet_format="json",
        input=str(source),
        output=str(output),
    )

    cmd_packet(args)

    assert output.read_text(encoding="utf-8") == packet.encode().hex()


def test_packet_cli_main_encode_from_stdin(monkeypatch, capsys) -> None:
    packet = _sample_packet()
    monkeypatch.setattr(
        "sys.argv",
        ["pydhcp", "packet", "--encode", "--input", "-", "--format", "json"],
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(dump_message(packet, "json")))

    main()

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

    _write_capture_record(_capture_event(), output=output, output_mode="single", packet_format="json", state=state)
    _write_capture_record(_capture_event(), output=output, output_mode="single", packet_format="json", state=state)

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
    module.write_text("seen = []\ndef on_capture(event):\n    seen.append(event.message_type)\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))

    hook = _load_capture_hook("hooks:on_capture", "json", False)
    assert hook is not None
    hook(_capture_event())

    assert sys.modules["hooks"].seen == ["DHCPDISCOVER"]


def test_load_capture_hook_command_gets_stdin_and_env(tmp_path, monkeypatch) -> None:
    command = tmp_path / "hook-command"
    command.write_text("", encoding="utf-8")
    calls = []

    def fake_run(args, input, text, capture_output, env):
        calls.append((args, input, text, capture_output, env))
        return argparse.Namespace(returncode=0, stderr="")

    monkeypatch.setattr("pydhcp.cli.subprocess.run", fake_run)

    hook = _load_capture_hook(str(command), "json", False)
    assert hook is not None
    hook(_capture_event())

    args, payload, text, capture_output, env = calls[0]
    assert args == [str(command)]
    assert json.loads(payload)["xid"] == 0x12345678
    assert text is True
    assert capture_output is True
    assert env["PYDHCP_CAPTURE_MSG_TYPE"] == "DHCPDISCOVER"


def test_cmd_capture_uses_fake_capture_and_count(monkeypatch, capsys) -> None:
    events = [_capture_event()]

    class FakeCapture:
        def __init__(self, listen, packet_filter, sink, hook, hook_fail_fast, per_interface):
            self.sink = sink
            self.hook = hook
            self.stopped = False

        def bind(self):
            pass

        def listen(self):
            self.sink(events[0])
            if self.hook is not None:
                self.hook(events[0])

        def stop(self):
            self.stopped = True

    monkeypatch.setattr("pydhcp.cli.DhcpCapture", FakeCapture)
    args = argparse.Namespace(
        listen="127.0.0.1:6767",
        packet_filter="msg_type=DHCPDISCOVER",
        packet_format="json",
        output=argparse.Namespace(__str__=lambda self: "-"),
        output_mode="stream",
        count=1,
        hook=None,
        hook_fail_fast=False,
        log_level=None,
        per_interface=False,
    )
    args.output = "-"

    cmd_capture(args)

    assert json.loads(capsys.readouterr().out)["options"]["DHCP_MESSAGE_TYPE"] == "DHCPDISCOVER"


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

    args = argparse.Namespace(config=None, listen="127.0.0.1:6767", log_level=None)
    cmd_server(args)

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

    args = argparse.Namespace(
        listen="127.0.0.1:6767",
        server=["192.0.2.1", "192.0.2.2:6768"],
        max_hops=10,
        insert_relay_agent_info=True,
        circuit_id="aabb",
        remote_id=None,
        log_level=None,
    )
    cmd_relay(args)

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
