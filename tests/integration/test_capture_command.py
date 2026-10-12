"""`pydhcp capture` and `pydhcp replay` are pktcap's commands with DHCP's defaults.

Each case runs the command as a process. What a record holds comes from the octets the
test sent or wrote, read back with `json`, not from the code that wrote them.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import typing as _ty
import uuid

import pytest

pktcap = pytest.importorskip("pktcap")

from capture_input import build, datagrams
from cli_process import SRC, Running, environment, free_port, run_cli
from helpers import FixedLeaseServer, build_request, running
from hook_programs import cli_hook
from pydhcp import DHCPMessage
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType


def _discover(xid: int, client_id: bytes = b"\x01\xaa\xbb") -> bytes:
    message = build_request(xid=xid)
    message.options[DHCPOptionCode.CLIENT_IDENTIFIER] = client_id
    return bytes(message.encode())


def _send(port: int, *data: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
        for item in data:
            out.sendto(item, ("127.0.0.1", port))


@pytest.fixture
def recorded(tmp_path: pathlib.Path) -> pathlib.Path:
    build.capture_file(tmp_path / "recorded.pcap", datagrams())
    return tmp_path / "recorded.pcap"


def _lines(output: bytes) -> "list[_ty.Dict[str, _ty.Any]]":
    return [json.loads(line) for line in output.decode("utf-8").splitlines()]


# -- a capture from a socket -----------------------------------------------------------


def test_a_discover_sent_to_the_listening_port_is_a_record_with_the_dhcp_layer() -> (
    None
):
    port = free_port()
    command = Running("capture", "-v", "--listen", f"127.0.0.1:{port}", "--count", "1")
    command.listening()
    _send(port, _discover(0x0A0B0C0D))

    assert command.finish() == 0, "\n".join(command.stderr)
    (record,) = [json.loads(line) for line in command.stdout]
    assert [layer["layer"] for layer in record["layers"]] == ["ipv4", "udp", "dhcp"]
    assert record["layers"][1]["destination_port"] == port
    dhcp = record["layers"][2]
    assert dhcp["xid"] == 0x0A0B0C0D and dhcp["message_type"] == "DHCPDISCOVER"
    assert dhcp["client_id"] == "01:AA:BB"
    assert dhcp["message"]["xid"] == 0x0A0B0C0D
    assert command.stderr[-1] == "1 frames read, 1 written"


def test_a_datagram_that_is_no_message_is_not_a_record(tmp_path: pathlib.Path) -> None:
    port = free_port()
    command = Running("capture", "-v", "--listen", f"127.0.0.1:{port}", "--count", "1")
    command.listening()
    _send(port, b"not dhcp at all", _discover(7))

    assert command.finish() == 0, "\n".join(command.stderr)
    (record,) = [json.loads(line) for line in command.stdout]
    assert record["layers"][-1]["xid"] == 7
    assert command.stderr[-1] == "2 frames read, 1 written, 1 skipped, 1 malformed"


def test_a_second_listen_port_is_read_as_dhcp_too() -> None:
    first, second = free_port(), free_port()
    command = Running(
        "capture", "-v", "-l", f"127.0.0.1:{first},127.0.0.1:{second}", "--count", "2"
    )
    command.listening()
    _send(first, _discover(1))
    _send(second, _discover(2))

    assert command.finish() == 0, "\n".join(command.stderr)
    xids = sorted(json.loads(line)["layers"][-1]["xid"] for line in command.stdout)
    assert xids == [1, 2]


# -- a capture from a file -------------------------------------------------------------


def test_a_filter_on_a_dhcp_key_selects_by_what_the_message_says(
    recorded: pathlib.Path,
) -> None:
    done = run_cli(
        "capture",
        "--read",
        str(recorded),
        "--filter",
        "msg_type=DHCPOFFER and xid=0x89BCF31A",
    )

    assert done.returncode == 0, done.stderr
    records = _lines(done.stdout.encode("utf-8"))
    offers = [
        d
        for d in datagrams()
        if DHCPMessage.decode(d).message_type == DHCPMessageType.DHCPOFFER
        and DHCPMessage.decode(d).xid == 0x89BCF31A
    ]
    assert len(records) == len(offers) == 2
    for record in records:
        message = record["layers"][-1]["message"]
        assert message["xid"] == 0x89BCF31A and message["yiaddr"] == "10.99.0.100"
        assert message["options"]["DHCP_MESSAGE_TYPE"] == "DHCPOFFER"


def test_the_summary_line_is_what_text_prints(recorded: pathlib.Path) -> None:
    done = run_cli(
        "capture", "--read", str(recorded), "--format", "text", "--count", "2"
    )

    assert done.returncode == 0, done.stderr
    first, second = done.stdout.splitlines()
    assert first.endswith("dhcp: DHCPDISCOVER xid=89BCF31A client=01:02:00:00:99:00:02")
    assert second.endswith(
        "dhcp: DHCPOFFER xid=89BCF31A client=01:02:00:00:99:00:02 "
        "yiaddr=10.99.0.100 giaddr=10.99.0.1"
    )


def test_a_file_per_record_is_named_by_the_clients_type_and_xid(
    recorded: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    pattern = tmp_path / "out" / "{client_id}" / "{xid}_{msg_type}.{format}"

    done = run_cli(
        "capture",
        "--read",
        str(recorded),
        "--output",
        str(pattern),
        "--per-record",
        "--format",
        "json",
        "--count",
        "2",
    )

    assert done.returncode == 0, done.stderr
    assert sorted(
        p.relative_to(tmp_path / "out").as_posix()
        for p in (tmp_path / "out").rglob("*.json")
    ) == [
        "01_02_00_00_99_00_02/89BCF31A_DHCPDISCOVER.json",
        "01_02_00_00_99_00_02/89BCF31A_DHCPOFFER.json",
    ]


def test_a_hook_is_given_the_record_and_the_clients_values(
    recorded: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    hook = cli_hook(
        tmp_path,
        "keep",
        """
        import json
        import os
        import sys

        seen = {
            "stdin": sys.stdin.buffer.read().decode("utf-8"),
            "env": {k: v for k, v in os.environ.items() if k.startswith("PKTCAP_HOOK_")},
        }
        (HERE / "seen.json").write_text(json.dumps(seen), encoding="utf-8")
        """,
    )

    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "pydhcp",
            "capture",
            "--read",
            str(recorded),
            "--hook",
            hook.command,
            "--count",
            "1",
            "--output",
            str(tmp_path / "all.json"),
        ],
        capture_output=True,
        env=environment(hook.env),
        stdin=subprocess.DEVNULL,
        timeout=120,
    )

    assert done.returncode == 0, done.stderr
    seen = json.loads((tmp_path / "seen.json").read_text(encoding="utf-8"))
    assert seen["env"] == {
        "PKTCAP_HOOK_CLIENT_ID": "01_02_00_00_99_00_02",
        "PKTCAP_HOOK_MSG_TYPE": "DHCPDISCOVER",
        "PKTCAP_HOOK_XID": "89BCF31A",
        "PKTCAP_HOOK_FORMAT": "json",
    }
    record = json.loads(seen["stdin"])
    assert record["layers"][-1]["message"]["xid"] == 0x89BCF31A
    assert (tmp_path / "all.json").read_text(encoding="utf-8") == seen["stdin"]


# -- the sources exclude each other ------------------------------------------------------


@pytest.mark.parametrize(
    "other", [["--interface", "eth0"], ["--read", "x.pcap"]], ids=["interface", "read"]
)
def test_listen_with_another_source_is_a_wrong_invocation(other: "list[str]") -> None:
    done = run_cli("capture", "--listen", "127.0.0.1:6767", *other)

    assert done.returncode == 2
    assert "not allowed with" in done.stderr


def test_interface_with_read_is_a_wrong_invocation() -> None:
    done = run_cli("capture", "--interface", "eth0", "--read", "x.pcap")

    assert done.returncode == 2 and "not allowed with" in done.stderr


# -- the removed names are refused, not ignored --------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["capture", "--per-capture"],
        ["capture", "-c", "3"],
        ["replay", "--server", "127.0.0.1", "--input", "x.pcap"],
        ["replay", "-s", "127.0.0.1", "--input", "x.pcap"],
    ],
)
def test_an_option_that_is_gone_is_refused(argv: "list[str]") -> None:
    done = run_cli(*argv)

    assert done.returncode == 2
    assert "unrecognized arguments" in done.stderr or "required" in done.stderr


@pytest.mark.parametrize(
    "command, old, new",
    [
        ("capture", "PYDHCP_CAPTURE_RECORD_FORMAT", "PYDHCP_CAPTURE_FORMAT"),
        ("capture", "PYDHCP_CAPTURE_PER_CAPTURE", "PYDHCP_CAPTURE_PER_RECORD"),
        ("replay", "PYDHCP_REPLAY_SERVER", "PYDHCP_REPLAY_TO"),
    ],
)
def test_a_variable_that_is_renamed_is_refused_naming_the_new_one(
    command: str, old: str, new: str
) -> None:
    done = run_cli(command, "--help-me-not", env={old: "x"})

    assert done.returncode == 2
    assert (
        done.stderr.strip()
        == f"pydhcp: error: {old} is not read: the variable is {new}"
    )


def test_a_renamed_variable_does_not_stop_another_command() -> None:
    done = run_cli("interfaces", "--format", "json", env={"PYDHCP_REPLAY_SERVER": "x"})

    assert done.returncode == 0, done.stderr


def test_a_short_flag_of_the_filter_is_f_and_format_has_none(
    recorded: pathlib.Path,
) -> None:
    done = run_cli("capture", "--read", str(recorded), "-f", "json", "--count", "1")

    assert done.returncode == 2
    assert "key=value" in done.stderr


# -- settings --------------------------------------------------------------------------------


def test_the_capture_section_of_a_settings_file_reaches_the_inherited_fields(
    recorded: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    out = tmp_path / "from-file.json"
    settings = tmp_path / "pydhcp.json"
    settings.write_text(
        json.dumps(
            {
                "capture": {
                    "filter": "msg_type=DHCPOFFER",
                    "output": str(out),
                    "count": 2,
                    "datagrams": True,
                }
            }
        ),
        encoding="utf-8",
    )

    done = run_cli("--config", str(settings), "capture", "--read", str(recorded))

    assert done.returncode == 0, done.stderr
    records = [
        json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 2
    assert all(record["source"].endswith(":67") for record in records)
    assert done.stderr.strip() == "6 frames read, 2 written, 4 skipped"


def test_the_old_names_of_the_settings_keys_are_refused(tmp_path: pathlib.Path) -> None:
    settings = tmp_path / "pydhcp.json"
    settings.write_text(
        json.dumps({"capture": {"per_capture": True}}), encoding="utf-8"
    )

    done = run_cli("--config", str(settings), "capture", "--read", "x.pcap")

    assert done.returncode == 2
    assert "unknown key 'per_capture' in section 'capture'" in done.stderr


@pytest.mark.parametrize("key", ["plugins", "plugin_config"])
def test_the_old_names_of_the_plugin_settings_are_unknown_keys(
    key: str, tmp_path: pathlib.Path
) -> None:
    settings = tmp_path / "pydhcp.json"
    settings.write_text(json.dumps({"capture": {key: "os"}}), encoding="utf-8")

    done = run_cli("--config", str(settings), "capture", "--read", "x.pcap")

    assert done.returncode == 2
    assert f"unknown key '{key}'" in done.stderr


_KEY_PLUGIN = """
from typing import NamedTuple


class MarkerLayer(NamedTuple):
    value: int


def pktcap_plugin(registry):
    registry.register_layer(
        MarkerLayer, keys={"stamp": lambda clause: (lambda layer: True)}
    )
"""


def test_the_capture_table_may_name_the_plugins_to_load(
    recorded: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """`load` is a setting like any other: the file the user named may carry it."""
    name = "marker_plugin_" + uuid.uuid4().hex[:10]
    directory = tmp_path / "plugins"
    directory.mkdir()
    (directory / (name + ".py")).write_bytes(_KEY_PLUGIN.encode("utf-8"))
    environment = {"PYTHONPATH": os.pathsep.join([SRC, str(directory)])}
    arguments = ["capture", "--read", str(recorded), "--filter", "stamp=1"]

    without = run_cli(*arguments, env=environment)
    assert without.returncode == 2 and "stamp" in without.stderr

    settings = tmp_path / "pydhcp.json"
    settings.write_text(json.dumps({"capture": {"load": [name]}}), encoding="utf-8")
    loaded = run_cli("--config", str(settings), *arguments, env=environment)

    assert loaded.returncode == 0, loaded.stderr
    assert "frames read, 0 written" in loaded.stderr


@pytest.mark.parametrize(
    "command",
    [
        ["capture", "--read", "x.pcap"],
        ["replay", "--input", "x.pcap", "--to", "192.0.2.9"],
    ],
)
def test_pktcap_config_is_not_an_option(command: "list[str]") -> None:
    """pktcap's commands have no settings file of their own to name."""
    done = run_cli(*command, "--pktcap-config", "none")

    assert done.returncode == 2
    assert "--pktcap-config" in done.stderr


def test_the_plugin_list_has_no_pydhcp_variable(recorded: pathlib.Path) -> None:
    """`PKTCAP_LOAD` is the list's variable: whatever else is set is read by nobody."""
    done = run_cli(
        "capture",
        "--read",
        str(recorded),
        "--count",
        "1",
        env={"PYDHCP_CAPTURE_PLUGINS": "os", "PYDHCP_CAPTURE_LOAD": "os"},
    )

    assert done.returncode == 0, done.stderr


def _hook_that_writes_a_marker(directory: pathlib.Path) -> "_ty.Any":
    return cli_hook(
        directory,
        "mark",
        """
        import sys

        sys.stdin.buffer.read()
        (HERE / "marker.txt").write_text("ran", encoding="ascii")
        """,
    )


def test_a_hook_comes_from_the_variable_and_from_the_file_the_user_named(
    recorded: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    hook = _hook_that_writes_a_marker(tmp_path)
    marker = tmp_path / "marker.txt"

    from_variable = run_cli(
        "capture",
        "--read",
        str(recorded),
        "--count",
        "1",
        env={**hook.env, "PYDHCP_CAPTURE_HOOK": hook.command},
    )
    assert from_variable.returncode == 0, from_variable.stderr
    assert marker.read_text(encoding="ascii") == "ran"
    marker.unlink()

    settings = tmp_path / "pydhcp.json"
    settings.write_text(
        json.dumps({"capture": {"hook": hook.command}}), encoding="utf-8"
    )
    from_file = run_cli(
        "--config",
        str(settings),
        "capture",
        "--read",
        str(recorded),
        "--count",
        "1",
        env=hook.env,
    )
    assert from_file.returncode == 0, from_file.stderr
    assert marker.read_text(encoding="ascii") == "ran"


def test_a_settings_file_nobody_named_is_never_read(
    recorded: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """A file called pydhcp.json in the working directory does not supply a hook."""
    hook = _hook_that_writes_a_marker(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    for name in ("pydhcp.json", "pydhcp.toml", "pydhcp.ini"):
        (work / name).write_text(
            json.dumps({"capture": {"hook": hook.command}}), encoding="utf-8"
        )

    done = run_cli(
        "capture", "--read", str(recorded), "--count", "1", cwd=work, env=hook.env
    )

    assert done.returncode == 0, done.stderr
    assert not (tmp_path / "marker.txt").exists()


def test_a_hook_cannot_be_named_by_a_tool_call(recorded: pathlib.Path) -> None:
    """Listing the layers a hook may come from does not open it to a tool call."""
    from duho import Cli
    from duho import mcp as duho_mcp

    from pydhcp.cli import Capture

    class Served(Capture):
        _parsername_ = "capture"
        _mcp_ = True

    class Root(Cli):
        _parsername_ = "pydhcp"
        _subcommands_ = [Served]

    result = duho_mcp.call_tool(
        Root,
        "pydhcp.capture",
        {"read": str(recorded), "count": 1, "hook": "echo"},
    )

    assert result["isError"] is True
    assert "cannot name a hook" in result["content"][0]["text"]
    assert Capture._mcp_ is False


# -- replay ----------------------------------------------------------------------------------


class _Recording(FixedLeaseServer):
    """A server that answers every client and keeps the identifiers it was asked by."""

    def __init__(self, *args: _ty.Any, **options: _ty.Any) -> None:
        super().__init__(*args, **options)
        self.asked: "list[int]" = []

    def acquire_lease(
        self,
        client_id: _ty.Any,
        server_id: _ty.Any,
        msg: DHCPMessage,
        **options: _ty.Any,
    ) -> _ty.Any:
        self.asked.append(msg.xid)
        return super().acquire_lease(client_id, server_id, msg, **options)


def test_replay_sends_the_requests_of_a_file_to_a_server_that_answers(
    tmp_path: pathlib.Path,
) -> None:
    """Two DISCOVERs and a reply in a file: the server is asked twice, answers a client
    on a loopback port, and is never sent the reply."""
    first = bytes(build_request(xid=0x11111111).encode())
    second = bytes(build_request(xid=0x22222222).encode())
    offer = bytes(
        build_request(DHCPMessageType.DHCPOFFER, xid=0x33333333, op=2).encode()
    )
    path = tmp_path / "heard.pcap"
    build.capture_file(path, [first, offer, second])
    replies = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    replies.bind(("127.0.0.1", 0))
    replies.settimeout(10)
    try:
        with running(_Recording(listen=[("127.0.0.1", 0)])) as server:
            server.REPLY_TO_CLIENT_PORT = replies.getsockname()[1]
            done = run_cli(
                "replay",
                "--input",
                str(path),
                "--to",
                f"127.0.0.1:{server.bound_addresses[0].port}",
                "--no-delay",
            )
            answers = [DHCPMessage.decode(replies.recvfrom(2048)[0]) for _ in range(2)]
            asked = list(server.asked)
    finally:
        replies.close()

    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "sent 2, partial 0"
    assert asked == [0x11111111, 0x22222222]
    assert [a.message_type for a in answers] == [DHCPMessageType.DHCPOFFER] * 2
    assert [a.xid for a in answers] == [0x11111111, 0x22222222]


def test_replay_sends_requests_only_and_prints_json_on_request(
    recorded: pathlib.Path,
) -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(10)
    try:
        done = run_cli(
            "replay",
            "--input",
            str(recorded),
            "--to",
            f"127.0.0.1:{receiver.getsockname()[1]}",
            "--no-delay",
            "--json",
        )
        heard = []
        while len(heard) < len([d for d in datagrams() if d[0] == 1]):
            heard.append(receiver.recvfrom(2048)[0])
    finally:
        receiver.close()

    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {"sent": len(heard), "partial": 0}
    assert heard == [d for d in datagrams() if d[0] == 1]
