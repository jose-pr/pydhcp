import argparse
import pytest
from unittest.mock import MagicMock, patch
import json
import os

from pydhcp.cli import cmd_interfaces, cmd_packet, cmd_server, cmd_bench
from pydhcp.config import load_config


def test_cmd_interfaces():
    # Verify it runs without exceptions
    args = argparse.Namespace()
    with patch("builtins.print") as mock_print:
        cmd_interfaces(args)
        assert mock_print.called


def test_cmd_packet_success():
    args = argparse.Namespace(decode="01010600123456780000000000000000000000000000000000000000001122334455" + "0"*384 + "63825363350101ff")
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


@patch("pydhcp.cli.DhcpServer")
def test_cmd_server(mock_dhcp_server_cls):
    mock_server = MagicMock()
    mock_dhcp_server_cls.return_value = mock_server
    
    args = argparse.Namespace(config=None, listen="127.0.0.1:6767")
    cmd_server(args)
    
    mock_dhcp_server_cls.assert_called_with(listen="127.0.0.1:6767")
    assert mock_server.bind.called
    assert mock_server.listen.called
