"""The loopback examples run, as a reader runs them, and do what their text says.

`examples/capture.py` listens on 127.0.0.1:6767 and prints each DISCOVER it
hears; `examples/client.py` sends one from 127.0.0.1:6768. The other two examples
serve the wildcard on the DHCP ports, which a test does not bind: they are
imported by `tests/test_examples.py`.
"""

from __future__ import annotations

import json
import pathlib
import socket
import subprocess
import sys
import threading
import time

import pytest

from cli_process import environment

EXAMPLES = pathlib.Path(__file__).resolve().parents[2] / "examples"
PORTS = (6767, 6768)


def _free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


pytestmark = pytest.mark.skipif(
    not all(_free(port) for port in PORTS),
    reason="the examples name ports 6767 and 6768 and one is held on this host",
)


def _documents(lines: "list[str]") -> "list[dict[str, object]]":
    """The JSON documents among the lines the capture example printed."""
    text = chr(10).join(lines)
    found: "list[dict[str, object]]" = []
    decoder = json.JSONDecoder()
    position = text.find("{")
    while position != -1:
        try:
            value, end = decoder.raw_decode(text, position)
        except ValueError:
            break
        found.append(value)
        position = text.find("{", end)
    return found


def _start(name: str) -> "subprocess.Popen[str]":
    env = environment({"PYTHONUNBUFFERED": "1"})
    return subprocess.Popen(
        [sys.executable, str(EXAMPLES / name)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )


def test_the_client_example_sends_what_the_capture_example_prints() -> None:
    capture = _start("capture.py")
    heard: "list[str]" = []
    try:
        assert capture.stdout is not None

        def read() -> None:
            for line in capture.stdout:  # type: ignore[union-attr]
                heard.append(line.rstrip("\r\n"))

        reader = threading.Thread(target=read, daemon=True)
        reader.start()

        sent = ""
        deadline = time.monotonic() + 60
        # The capture example logs nothing when it is ready, so the client is run
        # until the capture has printed what it heard.
        while time.monotonic() < deadline and not _documents(heard):
            done = subprocess.run(
                [sys.executable, str(EXAMPLES / "client.py")],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=environment(),
                timeout=60,
            )
            assert done.returncode == 0, done.stderr
            sent = done.stdout.strip()
            time.sleep(0.5)
        assert sent.startswith("sent DHCPDISCOVER xid="), sent
        xid = int(sent.rsplit("=", 1)[1], 16)

        documents = _documents(heard)
        assert documents, heard
        assert xid in [document["xid"] for document in documents], (xid, heard)
        assert all(
            d["options"]["DHCP_MESSAGE_TYPE"] == "DHCPDISCOVER" for d in documents
        )
        assert any(line.split(" ")[1:2] == ["DHCPDISCOVER"] for line in heard), heard
    finally:
        if capture.poll() is None:
            capture.kill()
        capture.wait()
        for stream in (capture.stdout, capture.stderr):
            if stream is not None:
                stream.close()
