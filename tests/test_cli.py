import argparse
import pytest
from unittest.mock import MagicMock, patch
import json
import os

from datetime import timedelta

from pydhcp import DhcpMessage, DhcpOptions
from pydhcp.cli import cmd_interfaces, cmd_packet, cmd_server, cmd_bench
from pydhcp.config import load_config
from pydhcp.enum import OpCode, HardwareAddressType, Flags, DhcpOptionCode, DhcpMessageType
from pydhcp.netutils import IPv4


def test_cmd_interfaces():
    # Verify it runs without exceptions
    args = argparse.Namespace()
    with patch("builtins.print") as mock_print:
        cmd_interfaces(args)
        assert mock_print.called


def test_cmd_packet_success():
    options = DhcpOptions()
    options[DhcpOptionCode.DHCP_MESSAGE_TYPE] = DhcpMessageType.DHCPDISCOVER
    packet = DhcpMessage(
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
    args = argparse.Namespace(decode=packet.encode().hex())
    with patch("builtins.print") as mock_print:
        cmd_packet(args)
        assert mock_print.called


def test_cmd_packet_failure():
    args = argparse.Namespace(decode="invalid_hex")
    with pytest.raises(SystemExit):
        cmd_packet(args)


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
