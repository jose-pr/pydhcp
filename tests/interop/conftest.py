"""Probes and fixtures for the interoperability tests.

A plain `pytest` run reports every test here as skipped, with the reason, unless
the host is Linux, the process is root and `ip netns` works; a test that needs a
peer program skips when that program is not installed.
"""

from __future__ import annotations

import json
import os
import pathlib
import platform
import shutil
import typing as _ty

import pytest

from . import _lab

CASES = pathlib.Path(__file__).resolve().parents[1] / "conformance" / "cases"

_REASON = _lab.unavailable()


@pytest.fixture
def lab(
    tmp_path: pathlib.Path, request: pytest.FixtureRequest
) -> _ty.Iterator[_lab.Lab]:
    """A lab whose namespaces and processes are gone when the test ends.

    With `PYDHCP_INTEROP_LOGS` set to a directory, each test leaves what its
    processes printed and what the taps saw in a subdirectory of that name.
    """
    if _REASON is not None:
        pytest.skip(_REASON)
    instance = _lab.Lab(tmp_path / "lab")
    try:
        yield instance
    finally:
        try:
            instance.close()
        finally:
            keep = os.environ.get("PYDHCP_INTEROP_LOGS")
            if keep:
                shutil.copytree(
                    instance.work,
                    pathlib.Path(keep) / request.node.name,
                    dirs_exist_ok=True,
                )


def need(*programs: str) -> None:
    """Skip the test unless every named program is installed."""
    missing = [name for name in programs if _lab.which(name) is None]
    if missing:
        pytest.skip("not installed: " + ", ".join(missing))


def peer_version(program: str, *flags: str) -> str:
    import subprocess

    found = _lab.which(program)
    assert found is not None
    done = subprocess.run([found, *flags], capture_output=True, text=True)
    return (done.stdout + done.stderr).strip().splitlines()[0]


def _private_strings() -> _ty.List[bytes]:
    """What must never appear in a recorded case: this machine's names."""
    names = {platform.node(), platform.node().split(".")[0]}
    for variable in ("USER", "LOGNAME", "SUDO_USER", "USERNAME"):
        value = os.environ.get(variable)
        if value and value != "root":
            names.add(value)
    return [name.encode() for name in names if len(name) >= 3]


def record_case(
    name: str,
    description: str,
    peer: str,
    taps: _ty.Mapping[str, _lab.Tap],
    roles: _ty.Mapping[str, str],
) -> None:
    """Save the datagrams a scenario exchanged as a replayable case.

    Does nothing unless `PYDHCP_RECORD_CASES` is set, so a test run never edits
    the checkout. `roles` maps a hardware address on the wire to who sent it
    (`client`, `server`, `relay`); a role named `pydhcp-...` marks a datagram
    this library produced, which the replay test re-encodes byte for byte.
    """
    if not os.environ.get("PYDHCP_RECORD_CASES"):
        return
    datagrams = []
    for segment, tap in taps.items():
        for frame in tap.frames():
            sender = roles.get(frame.src_mac)
            assert (
                sender is not None
            ), f"frame from an unlabelled sender {frame.src_mac}"
            datagrams.append(
                {
                    "segment": segment,
                    "sender": sender,
                    "src": f"{frame.src_ip}:{frame.sport}",
                    "dst": f"{frame.dst_ip}:{frame.dport}",
                    "payload": frame.payload.hex(),
                }
            )
    blob = json.dumps(datagrams).encode()
    for private in _private_strings():
        assert private not in blob, "a recorded case holds a name from this machine"
    target = CASES / name
    target.mkdir(parents=True, exist_ok=True)
    document = {"description": description, "peer": peer, "datagrams": datagrams}
    (target / "case.json").write_bytes(
        (json.dumps(document, indent=1) + "\n").encode("utf-8")
    )
