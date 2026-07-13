import argparse
import io
import json
from unittest.mock import MagicMock, patch

import pytest
from datetime import timedelta

from pydhcp import DhcpMessage, DhcpOptions
from pydhcp.cli import cmd_interfaces, cmd_packet, cmd_server, main
from pydhcp.config import load_config
from pydhcp.structured import dump_message
from pydhcp.enum import OpCode, HardwareAddressType, Flags, DhcpOptionCode, DhcpMessageType
from pydhcp.netutils import IPv4


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


def test_cmd_packet_decode_from_stdin_json(capsys, monkeypatch) -> None:
    packet = _sample_packet()
    args = argparse.Namespace(
        mode="decode",
        packet_format="json",
        input_text=None,
        input_file=None,
        stdin=True,
        output_file=None,
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(packet.encode().hex()))

    cmd_packet(args)

    assert json.loads(capsys.readouterr().out) == packet.to_mapping()


def test_cmd_packet_decode_summary(capsys, monkeypatch) -> None:
    packet = _sample_packet()
    args = argparse.Namespace(
        mode="decode",
        packet_format="summary",
        input_text=None,
        input_file=None,
        stdin=True,
        output_file=None,
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(packet.encode().hex()))

    cmd_packet(args)

    output = capsys.readouterr().out
    assert "BOOTREQUEST XID=12345678 Src: capture Dst: decoded" in output
    assert "OPTIONS:" in output


def test_cmd_packet_malformed_exits_with_error(capsys) -> None:
    args = argparse.Namespace(
        mode="decode",
        packet_format="json",
        input_text="00",
        input_file=None,
        stdin=False,
        output_file=None,
    )

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
        input_text=None,
        input_file=source,
        stdin=False,
        output_file=output,
    )

    cmd_packet(args)

    assert output.read_text(encoding="utf-8") == packet.encode().hex()


def test_packet_cli_main_encode_from_stdin(monkeypatch, capsys) -> None:
    packet = _sample_packet()
    monkeypatch.setattr(
        "sys.argv",
        ["pydhcp", "packet", "--encode", "--stdin", "--json"],
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(dump_message(packet, "json")))

    main()

    assert capsys.readouterr().out.strip() == packet.encode().hex()


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
