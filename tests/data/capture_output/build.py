"""What `pydhcp capture` writes for a fixed input, as a process, octet for octet.

`INPUT` is the 50 datagrams recorded under `tests/conformance/transcripts/`
(transcript directories sorted by name, then index), the two messages in `tests/data/`, and
one DISCOVER carrying a 255-octet client identifier. A recorded scenario writes the
input as a pcap file with fixed times and addresses (`capture_file`) and starts
`pydhcp capture --read` on it, so a record holds the same octets on every run, and
keeps what the command wrote: its standard output, the files and their names, its
status. `run` is the live form for the tests that want a socket: it starts the command
on a loopback port and sends the input from one socket in order.

`expected/` holds what the command wrote, with a line feed ending every line on
every platform. `python build.py write` rewrites it from the code in the tree.

Every input holds only private addresses and locally administered hardware
addresses: a recorded transcript already does, and the two messages in `tests/data/`
carry a placeholder address whose first octet is made locally administered here.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import typing as _ty

HERE = pathlib.Path(__file__).resolve().parent
TESTS = HERE.parent.parent
TRANSCRIPTS = TESTS / "conformance" / "transcripts"
EXPECTED = HERE / "expected"

if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from cli_process import environment, free_port  # noqa: E402

#: How `pydhcp capture` is told to write one file for each record.
PER_RECORD: "tuple[str, ...]" = ("--per-record",)

#: The most a scenario waits for the command to end by itself.
RUN_SECONDS = 120.0


def recorded() -> "list[bytes]":
    """Every datagram of every recorded transcript: transcripts by name, then index."""
    found = []
    for path in sorted(TRANSCRIPTS.glob("*/transcript.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        found.extend(bytes.fromhex(d["payload"]) for d in case["datagrams"])
    return found


def stored() -> "list[bytes]":
    """The two messages in `tests/data/`, their hardware address made locally administered."""
    found = []
    for path in sorted((TESTS / "data").glob("message_before_*.bin")):
        data = bytearray(path.read_bytes())
        data[28] |= 0x02  # the first octet of chaddr
        found.append(bytes(data))
    return found


def long_identifier() -> bytes:
    """A DISCOVER whose client identifier is 255 octets, which no file name holds."""
    from pydhcp import DHCPMessage
    from pydhcp.options import DHCPOptionCode

    message = DHCPMessage.decode(recorded()[0])
    message.xid = 0x0A0B0C0D
    message.options[DHCPOptionCode.CLIENT_IDENTIFIER] = bytes([1]) + bytes(
        range(1, 255)
    )
    return bytes(message.encode())


def datagrams() -> "list[bytes]":
    return [*recorded(), *stored(), long_identifier()]


def distinct_clients(count: int) -> "list[bytes]":
    """The first `count` datagrams, each from a client no earlier one came from."""
    from pydhcp import DHCPMessage
    from pydhcp.exceptions import NoClientIdentityError

    seen: "set[str]" = set()
    chosen = []
    for data in datagrams():
        try:
            who = DHCPMessage.decode(data).get_client_id()
        except NoClientIdentityError:
            who = "UNKNOWN"
        if who not in seen:
            seen.add(who)
            chosen.append(data)
        if len(chosen) == count:
            return chosen
    raise AssertionError(f"fewer than {count} distinct clients")


class Done(_ty.NamedTuple):
    status: int
    stdout: bytes
    stderr: "list[str]"


def capture_file(path: pathlib.Path, sent: "_ty.Sequence[bytes]") -> None:
    """`sent` as a pcap file: a request goes to port 67 and a reply to port 68.

    The times and the addresses are fixed (private ones), so what a command makes of
    the file is the same on every run.
    """
    import pktcap

    client = ("10.99.0.50", 68)
    server = ("10.99.0.1", 67)
    with pktcap.PcapWriter(path) as writer:
        for number, data in enumerate(sent):
            source, destination = (client, server) if data[0] == 1 else (server, client)
            writer.write(1_700_000_000.0 + number * 0.25, source, destination, data)


def run_file(
    argv: "_ty.Sequence[str]", sent: "_ty.Sequence[bytes]", directory: pathlib.Path
) -> Done:
    """`pydhcp capture --read FILE argv`, with `sent` written to FILE under `directory`."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "input.pcap"
    capture_file(path, sent)
    done = subprocess.run(
        [sys.executable, "-m", "pydhcp", "capture", "--read", str(path), *argv],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment(),
        timeout=RUN_SECONDS,
    )
    return Done(
        done.returncode,
        done.stdout,
        done.stderr.decode("utf-8", "replace").splitlines(),
    )


def run(
    argv: "_ty.Sequence[str]",
    sent: "_ty.Sequence[bytes]",
    env: "_ty.Optional[_ty.Mapping[str, str]]" = None,
) -> Done:
    """`pydhcp capture argv` on a free loopback port, fed `sent` in order."""
    port = free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "pydhcp",
            "capture",
            "-v",
            "--listen",
            f"127.0.0.1:{port}",
            *argv,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment(env),
    )
    assert process.stdout is not None and process.stderr is not None
    stdout: "list[bytes]" = []
    stderr: "list[str]" = []
    listening = threading.Event()

    def read_out() -> None:
        stdout.append(process.stdout.read())  # type: ignore[union-attr]

    def read_err() -> None:
        for line in process.stderr:  # type: ignore[union-attr]
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            stderr.append(text)
            if "Bound" in text:
                listening.set()

    threads = [threading.Thread(target=read_out), threading.Thread(target=read_err)]
    for thread in threads:
        thread.daemon = True
        thread.start()
    try:
        if not listening.wait(60):
            raise AssertionError("the command did not bind:\n" + "\n".join(stderr))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
            for data in sent:
                out.sendto(data, ("127.0.0.1", port))
        try:
            status = process.wait(RUN_SECONDS)
        except subprocess.TimeoutExpired:
            raise AssertionError(
                "the command did not end by itself:\n" + "\n".join(stderr)
            ) from None
        for thread in threads:
            thread.join(10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for thread in threads:
            thread.join(10)
        process.stdout.close()
        process.stderr.close()
    return Done(status, b"".join(stdout), stderr)


def _tree(root: pathlib.Path, prefix: str) -> "dict[str, bytes]":
    """Every file under `root`, by its path relative to it, under `prefix`."""
    return {
        f"{prefix}/{path.relative_to(root).as_posix()}": path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def build(work: pathlib.Path) -> "dict[str, bytes]":
    """Run every scenario under `work`; the files that make up `expected/`, by path."""

    sent = datagrams()
    half = len(sent) // 2
    files: "dict[str, bytes]" = {}
    statuses: "dict[str, int]" = {}
    inputs = work / "inputs"

    for name in ("json", "yaml", "text"):
        done = run_file(["--format", name], sent, inputs / f"stdout_{name}")
        statuses[f"stdout_{name}"] = done.status
        files[f"stdout_{name}.out"] = done.stdout

    for name in ("json", "yaml"):
        target = work / f"growing_{name}" / "nested" / f"all.{name}"
        for number, part in enumerate((sent[:half], sent[half:]), 1):
            done = run_file(
                ["--output", str(target), "--append"],
                part,
                inputs / f"growing_{name}_{number}",
            )
            statuses[f"growing_{name}_run{number}"] = done.status
        files[f"growing/all.{name}"] = target.read_bytes()

    for name in ("json", "yaml", "toml", "ini"):
        root = work / f"tree_{name}"
        pattern = str(root / "{client_id}" / "{xid}_{msg_type}.{format}")
        done = run_file(
            ["--output", pattern, *PER_RECORD, "--format", name],
            sent,
            inputs / f"tree_{name}",
        )
        statuses[f"tree_{name}"] = done.status
        files.update(_tree(root, f"tree_{name}"))

    # No --format: the ending of the pattern names the format.
    root = work / "tree_ending"
    done = run_file(
        ["--output", str(root / "{xid}_{msg_type}.ini"), *PER_RECORD],
        sent,
        inputs / "tree_ending",
    )
    statuses["tree_ending"] = done.status
    files.update(_tree(root, "tree_ending"))

    # A budget of three files and a fourth client: the fourth is refused and counted,
    # and the run ends with the file.
    root = work / "budget"
    done = run_file(
        [
            "--output",
            str(root / "{client_id}.{format}"),
            *PER_RECORD,
            "--format",
            "json",
            "--max-files",
            "3",
        ],
        distinct_clients(4),
        inputs / "budget",
    )
    files.update(_tree(root, "budget"))
    summary = {
        "statuses": statuses,
        "budget": {"status": done.status, "last_line": done.stderr[-1]},
    }
    files["summary.json"] = (
        json.dumps(summary, indent=1, sort_keys=True) + "\n"
    ).encode()
    return dict(sorted(files.items()))


def write(directory: pathlib.Path, files: "dict[str, bytes]") -> None:
    if directory.exists():
        shutil.rmtree(directory)
    for name, data in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main(argv: "_ty.Sequence[str]") -> int:
    if list(argv) != ["write"]:
        print(__doc__)
        return 2
    with tempfile.TemporaryDirectory() as work:
        write(EXPECTED, build(pathlib.Path(work)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
