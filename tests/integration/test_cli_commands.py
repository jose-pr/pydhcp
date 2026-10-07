"""The listening commands, run from an argument vector on real sockets.

Each test calls `pydhcp.cli.main(argv)` with a loopback address and port 0 (or a
port the test holds), and reads what the command did from what it logs and from
what its sockets do. Nothing of the project is replaced: the command builds the
real server, relay or capture, and Ctrl-C ends it.
"""

from __future__ import annotations

import json
import pathlib
import socket
import typing as _ty

import pytest

from command_run import run_command
from cli_process import free_port
from helpers import FixedLeaseServer, build_request, wait_until
from pydhcp import DHCPMessage
from pydhcp.options import DHCPOptionCode
from pydhcp.options import RelayAgentInformation


def _port(address: str) -> int:
    return int(address.rsplit(":", 1)[1])


# -- server -----------------------------------------------------------------------


def test_the_server_command_binds_what_listen_names() -> None:
    ran = run_command(["server", "-v", "--listen", "127.0.0.1:0"])

    assert ran.status == 0
    (address,) = ran.bound
    assert address.startswith("127.0.0.1:") and _port(address) != 0
    assert "Stopped listening due to Ctrl-C" in ran.records


def test_per_interface_binds_each_address_where_the_wildcard_would_serve_them_all() -> (
    None
):
    port = free_port()
    wildcard = run_command(["server", "-v", "--listen", f"0.0.0.0:{port}"])
    each = run_command(
        ["server", "-v", "--listen", f"0.0.0.0:{port}", "--per-interface"]
    )

    assert wildcard.bound == [f"0.0.0.0:{port}"]
    assert f"0.0.0.0:{port}" not in each.bound
    assert f"127.0.0.1:{port}" in each.bound


def test_without_the_flag_the_lease_store_is_not_a_file(tmp_path: pathlib.Path) -> None:
    ran = run_command(["server", "-v", "--listen", "127.0.0.1:0"])

    assert not any("Persisting leases" in text for text in ran.records)
    assert list(tmp_path.iterdir()) == []


def _bad_lease_file(directory: pathlib.Path, name: str) -> pathlib.Path:
    """A file that is not a lease file: a server that opens it moves it aside."""
    path = directory / name
    path.write_text("this is not json\n", encoding="utf-8")
    return path


def _was_opened(path: pathlib.Path) -> bool:
    return not path.exists() and any(
        p.name.startswith(path.name + ".corrupt") for p in path.parent.iterdir()
    )


def _ask(*files: pathlib.Path) -> "_ty.Callable[[list[str]], None]":
    """A DISCOVER to the server: its lease store opens on the first request."""

    def send(bound: "list[str]") -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(
                bytes(build_request().encode()), ("127.0.0.1", _port(bound[0]))
            )
        wait_until(
            lambda: _was_opened(files[0]), f"the server to open {files[0].name}", 10.0
        )

    return send


def test_the_flag_selects_a_file_backend(tmp_path: pathlib.Path) -> None:
    path = _bad_lease_file(tmp_path, "leases.json")

    ran = run_command(
        ["server", "-v", "--listen", "127.0.0.1:0", "--lease-file", str(path)],
        during=_ask(path),
    )

    assert ran.status == 0
    assert any(f"Persisting leases to {path}" == text for text in ran.records)
    assert _was_opened(path)


def test_the_config_file_can_set_it_too(tmp_path: pathlib.Path) -> None:
    leases = _bad_lease_file(tmp_path, "from-config.json")
    config = tmp_path / "pydhcp.json"
    config.write_text(
        json.dumps({"server": {"lease_file": str(leases)}}), encoding="utf-8"
    )

    ran = run_command(
        ["server", "-v", "--config", str(config), "--listen", "127.0.0.1:0"],
        during=_ask(leases),
    )

    assert ran.status == 0
    assert _was_opened(leases)
    assert not any("unsupported key" in text.lower() for text in ran.records)


def test_an_explicit_flag_beats_the_config_file(tmp_path: pathlib.Path) -> None:
    from_config = _bad_lease_file(tmp_path, "from-config.json")
    wanted = _bad_lease_file(tmp_path, "from-flag.json")
    config = tmp_path / "pydhcp.json"
    config.write_text(
        json.dumps({"server": {"lease_file": str(from_config)}}), encoding="utf-8"
    )

    ran = run_command(
        [
            "server",
            "-v",
            "--config",
            str(config),
            "--listen",
            "127.0.0.1:0",
            "--lease-file",
            str(wanted),
        ],
        during=_ask(wanted),
    )

    assert ran.status == 0
    assert _was_opened(wanted)
    assert not _was_opened(from_config)


def test_an_explicit_listen_beats_the_config_file(tmp_path: pathlib.Path) -> None:
    """CLI over config, as every other tool does: the other order gave no way to
    override a shared config for a single run."""
    held = free_port()
    config = tmp_path / "server.json"
    config.write_text(
        json.dumps({"server": {"listen": f"127.0.0.1:{held}"}}), encoding="utf-8"
    )

    flag = run_command(
        ["server", "-v", "--config", str(config), "--listen", "127.0.0.1:0"]
    )
    without = run_command(["server", "-v", "--config", str(config)])

    assert flag.status == 0 and _port(flag.bound[0]) != held
    assert without.status == 0 and without.bound == [f"127.0.0.1:{held}"]


def test_a_port_that_is_really_held_is_refused_with_a_message_not_a_trace(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]

        ran = run_command(["server", "-v", "--listen", f"127.0.0.1:{port}"])

    assert ran.status == 1
    assert ran.bound == []
    err = capsys.readouterr().err
    assert err.startswith("pydhcp: error:") and "Traceback" not in err


# -- relay ------------------------------------------------------------------------


def _forwarded(argv_extra: "list[str]", **fields: _ty.Any) -> "DHCPMessage":
    """Run `pydhcp relay` with an upstream socket of the test's, send the relay a
    DISCOVER, and return what the upstream received."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
        upstream.bind(("127.0.0.1", 0))
        upstream.settimeout(10.0)
        received: "list[bytes]" = []

        def send(bound: "list[str]") -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                request = build_request(xid=0x0A0B0C0D)
                client.sendto(bytes(request.encode()), ("127.0.0.1", _port(bound[0])))
            received.append(upstream.recvfrom(4096)[0])

        ran = run_command(
            [
                "relay",
                "-v",
                "--listen",
                "127.0.0.1:0",
                "--server",
                f"127.0.0.1:{upstream.getsockname()[1]}",
                *argv_extra,
            ],
            during=send,
        )
    assert ran.status == 0, ran
    if isinstance(ran.result, BaseException):
        raise ran.result
    return DHCPMessage.decode(memoryview(received[0]))


def test_the_relay_command_forwards_to_the_server_it_names_with_its_own_giaddr() -> (
    None
):
    message = _forwarded([])

    assert message.xid == 0x0A0B0C0D
    assert str(message.giaddr) == "127.0.0.1"
    assert DHCPOptionCode.RELAY_AGENT_INFORMATION not in message.options


def test_the_relay_command_inserts_the_agent_ids_it_is_given() -> None:
    message = _forwarded(
        ["--insert-relay-agent-info", "--circuit-id", "0a01", "--remote-id", "0b02"]
    )

    info = message.options.get(
        DHCPOptionCode.RELAY_AGENT_INFORMATION, decode=RelayAgentInformation
    )
    assert [(entry.code, bytes(entry.value)) for entry in info] == [
        (1, b"\x0a\x01"),
        (2, b"\x0b\x02"),
    ]


@pytest.mark.parametrize(
    "flag, value", [("--circuit-id", "0a01"), ("--remote-id", "0b02")]
)
def test_the_relay_command_refuses_ids_without_the_insert_flag(
    flag: str, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    ran = run_command(
        ["relay", "-v", "--listen", "127.0.0.1:0", "-s", "192.0.2.1", flag, value]
    )

    assert ran.status == 2 and ran.bound == []
    err = capsys.readouterr().err
    assert flag in err and "--insert-relay-agent-info" in err


def test_the_relay_command_with_per_interface_binds_each_address() -> None:
    port = free_port()
    ran = run_command(
        [
            "relay",
            "-v",
            "--listen",
            f"0.0.0.0:{port}",
            "-s",
            "192.0.2.1",
            "--per-interface",
        ]
    )

    assert f"0.0.0.0:{port}" not in ran.bound
    assert f"127.0.0.1:{port}" in ran.bound


# -- capture ----------------------------------------------------------------------


def _capture(pattern: str, directory: pathlib.Path, *extra: str):
    return run_command(
        [
            "capture",
            "-v",
            "--listen",
            "127.0.0.1:0",
            "--per-capture",
            "--output",
            str(directory / pattern),
            *extra,
        ]
    )


def test_a_good_pattern_reaches_the_capture(tmp_path: pathlib.Path) -> None:
    ran = _capture("{xid}.{format}", tmp_path)

    assert ran.status == 0 and len(ran.bound) == 1
    assert not any("only the last one is kept" in text for text in ran.records)


def test_capture_warns_once_when_records_will_overwrite(tmp_path: pathlib.Path) -> None:
    """A warning, deliberately, not an error: rewriting one file is also how a
    fixed pattern stays outside the file budget."""
    ran = _capture("{client_id}.{format}", tmp_path)

    assert ran.status == 0 and len(ran.bound) == 1
    warnings = [text for text in ran.records if "only the last one is kept" in text]
    assert len(warnings) == 1, ran.records


def test_capture_refuses_a_bad_pattern_before_binding(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ran = _capture("cap_{mac}.{format}", tmp_path)

    assert ran.status == 2 and ran.bound == []
    err = capsys.readouterr().err
    assert "{mac}" in err and "not a field" in err


def test_count_writes_that_many_records_and_then_stops(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Three datagrams against a `--count` of two is the smallest arrangement where
    a count that never fires, or fires on the wrong record, changes the result."""

    def send(bound: "list[str]") -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for xid in (0xAAAA0001, 0xAAAA0002, 0xAAAA0003):
                client.sendto(
                    bytes(build_request(xid=xid).encode()),
                    ("127.0.0.1", _port(bound[0])),
                )

    ran = run_command(
        [
            "capture",
            "-v",
            "--listen",
            "127.0.0.1:0",
            "--filter",
            "msg_type=DHCPDISCOVER",
            "--output",
            "-",
            "--count",
            "2",
        ],
        during=send,
        ends=True,
    )

    assert ran.status == 0 and "Stopped listening due to Ctrl-C" not in ran.records
    records = [json.loads(l) for l in capsys.readouterr().out.splitlines()]
    assert [record["xid"] for record in records] == [0xAAAA0001, 0xAAAA0002]
    assert [record["options"]["DHCP_MESSAGE_TYPE"] for record in records] == [
        "DHCPDISCOVER",
        "DHCPDISCOVER",
    ]


def _asks_from_own_port(
    answered: "list[int]",
) -> "_ty.Callable[[list[str]], None]":
    """A DISCOVER from an ephemeral port, then the port a reply arrives on."""

    def send(bound: "list[str]") -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(("127.0.0.1", 0))
            client.settimeout(5)
            client.sendto(
                bytes(build_request().encode()), ("127.0.0.1", _port(bound[0]))
            )
            DHCPMessage.decode(client.recvfrom(2048)[0])
            answered.append(client.getsockname()[1])

    return send


def test_lenient_reply_ports_answers_a_client_on_the_port_it_sent_from(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # private: the command builds the server where it reads the name; a loopback
    # interface is not servable, so the stand-in grants the one loopback lease.
    monkeypatch.setattr("pydhcp.cli._server.DHCPServer", FixedLeaseServer)
    answered: "list[int]" = []
    ran = run_command(
        ["server", "-v", "--listen", "127.0.0.1:0", "--lenient-reply-ports"],
        during=_asks_from_own_port(answered),
    )

    assert ran.status == 0, ran.result
    assert len(answered) == 1, ran.result


def test_the_server_answers_the_dhcp_client_port_without_the_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # private: as above.
    monkeypatch.setattr("pydhcp.cli._server.DHCPServer", FixedLeaseServer)
    answered: "list[int]" = []
    ran = run_command(
        ["server", "-v", "--listen", "127.0.0.1:0"],
        during=_asks_from_own_port(answered),
    )

    assert answered == []
    assert isinstance(ran.result, socket.timeout)
