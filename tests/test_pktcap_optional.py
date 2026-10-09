"""pktcap is an extra: without it the package imports, serves and decodes, and each
capture function and each capture command says which extra to install.

Every test runs a child interpreter in which importing `pktcap` raises (a finder at
the head of `sys.meta_path`), because this process has loaded it. The proof with
the distribution really absent is the `bare` job of the test workflow.
"""

from __future__ import annotations

import pathlib
import sys
import textwrap
import typing as _ty

import pytest

from cli_process import run_cli

TESTS = pathlib.Path(__file__).resolve().parent

#: The one line every capture function and command gives.
LINE = "captures need the 'pktcap' extra: pip install \"pydhcp[pktcap]\""

_BLOCKER = textwrap.dedent("""
    import sys

    sys.path.insert(0, {tests!r})


    class Blocker:
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] == "pktcap":
                raise ModuleNotFoundError("No module named " + repr(name), name=name)


    sys.meta_path.insert(0, Blocker())
    """)


def _program(
    tmp_path: pathlib.Path, body: str, *, blocked: bool = True
) -> pathlib.Path:
    path = tmp_path / "program.py"
    head = _BLOCKER.format(tests=str(TESTS)) if blocked else "import sys\n"
    path.write_text(head + textwrap.dedent(body), encoding="utf-8")
    return path


def test_the_package_the_command_line_and_the_capture_package_import_without_pktcap(
    tmp_path: pathlib.Path,
) -> None:
    program = _program(
        tmp_path,
        """
        import pydhcp
        import pydhcp.capture
        import pydhcp.cli
        from pydhcp import DHCPCapture, DHCPServer, compile_capture_filter
        from pydhcp.capture import DHCPLayer, pktcap_plugin

        assert "pktcap" not in sys.modules
        print("imported")
        """,
    )

    result = run_cli(program=program)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "imported"


def test_importing_the_package_loads_neither_pktcap_nor_asyncio(
    tmp_path: pathlib.Path,
) -> None:
    program = _program(
        tmp_path,
        """
        import pydhcp, pydhcp.cli, pydhcp.capture
        from pydhcp.capture import asniff_dhcp, sniff_dhcp

        assert "pktcap" not in sys.modules, "pktcap"
        assert "asyncio" not in sys.modules, "asyncio"
        print("clean")
        """,
        blocked=False,
    )

    result = run_cli(program=program)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "clean"


def test_a_server_answers_a_discover_without_pktcap(tmp_path: pathlib.Path) -> None:
    program = _program(
        tmp_path,
        """
        import socket

        from helpers import FixedLeaseServer, build_request, running
        from pydhcp import DHCPMessage
        from pydhcp.packet import DHCPMessageType

        with running(FixedLeaseServer(listen=[("127.0.0.1", 0)])) as server:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            client.settimeout(5.0)
            server.REPLY_TO_CLIENT_PORT = client.getsockname()[1]
            client.sendto(
                bytes(build_request(xid=0x01020304).encode()),
                ("127.0.0.1", server.bound_addresses[0].port),
            )
            offer = DHCPMessage.decode(client.recvfrom(2048)[0])
            client.close()
        assert offer.message_type == DHCPMessageType.DHCPOFFER
        assert "pktcap" not in sys.modules
        print("offered", offer.xid)
        """,
    )

    result = run_cli(program=program)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "offered 16909060"


def test_the_packet_command_decodes_to_json_without_pktcap(
    tmp_path: pathlib.Path,
) -> None:
    program = _program(
        tmp_path,
        """
        import runpy

        runpy.run_module("pydhcp", run_name="__main__")
        """,
    )
    from helpers import build_request

    hex_text = bytes(build_request(xid=0x0A0B0C0D).encode()).hex()

    result = run_cli("packet", "--decode", program=program, input=hex_text)

    assert result.returncode == 0, result.stderr
    assert '"xid": 168496141' in result.stdout


@pytest.mark.parametrize(
    "call",
    [
        'pydhcp.capture.dissect_dhcp(b"")',
        'pydhcp.capture.sniff_dhcp("127.0.0.1:0")',
        'pydhcp.capture.asniff_dhcp("127.0.0.1:0")',
        "pydhcp.capture.register_dhcp_dissector()",
        "pydhcp.capture.capture_dissector()",
        'pydhcp.capture.compile_capture_filter("xid=1")',
        'pydhcp.capture.read_capture("input.pcap")',
        'pydhcp.capture.replay_capture("input.pcap", "127.0.0.1")',
        'pydhcp.capture.DHCPCaptureWriter("out.json")',
        'pydhcp.DHCPCapture(listen="127.0.0.1:0")',
    ],
)
def test_each_capture_function_gives_the_line_naming_the_extra(
    tmp_path: pathlib.Path, call: str
) -> None:
    program = _program(
        tmp_path,
        f"""
        import pydhcp, pydhcp.capture

        try:
            {call}
        except ImportError as error:
            print(error)
        else:
            print("no error")
        """,
    )

    result = run_cli(program=program)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [LINE]


@pytest.mark.parametrize(
    "argv",
    [
        ("capture", "--read", "x.pcap"),
        ("capture", "--help"),
        ("replay", "--input", "x.pcap", "--server", "127.0.0.1"),
        ("replay", "--help"),
    ],
)
def test_each_capture_command_gives_the_line_and_status_1(
    tmp_path: pathlib.Path, argv: "_ty.Tuple[str, ...]"
) -> None:
    program = _program(
        tmp_path,
        """
        import runpy

        runpy.run_module("pydhcp", run_name="__main__")
        """,
    )

    result = run_cli(*argv, program=program)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.splitlines() == [f"pydhcp: error: {LINE}"]


def test_the_other_commands_run_without_pktcap(tmp_path: pathlib.Path) -> None:
    program = _program(
        tmp_path,
        """
        import runpy

        runpy.run_module("pydhcp", run_name="__main__")
        """,
    )

    for argv in (
        ("--help",),
        ("server", "--help"),
        ("relay", "--help"),
        ("interfaces",),
    ):
        result = run_cli(*argv, program=program)
        assert result.returncode == 0, (argv, result.stderr)
    listed = run_cli("--help", program=program).stdout
    assert "server" in listed and "packet" in listed


def test_a_command_class_without_pktcap_is_an_import_error_naming_the_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pydhcp.cli

    monkeypatch.setitem(sys.modules, "pktcap", None)
    for name in ("Capture", "Replay"):
        monkeypatch.delitem(vars(pydhcp.cli), name, raising=False)
        with pytest.raises(ImportError) as error:
            getattr(pydhcp.cli, name)
        assert str(error.value) == LINE


def test_a_failure_inside_pktcap_is_not_taken_for_a_missing_extra(
    tmp_path: pathlib.Path,
) -> None:
    (tmp_path / "pktcap.py").write_text(
        "import a_module_nobody_ships\n", encoding="utf-8"
    )
    program = _program(
        tmp_path,
        f"""
        sys.path.insert(0, {str(tmp_path)!r})
        import pydhcp.capture

        try:
            pydhcp.capture.capture_dissector()
        except ModuleNotFoundError as error:
            print(error.name)
        """,
        blocked=False,
    )

    result = run_cli(program=program)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "a_module_nobody_ships"
