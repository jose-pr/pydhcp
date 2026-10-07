"""What `pydhcp capture` writes for a fixed input, as a process, octet for octet.

`INPUT` is the 50 datagrams recorded under `tests/conformance/cases/` (case
directories sorted by name, then index), the two messages in `tests/data/`, and
one DISCOVER carrying a 255-octet client identifier. Each scenario starts
`pydhcp capture` on a loopback port, sends the input from one socket in order
and keeps what the command wrote: its standard output, the files and their
names, its status.

`expected/` holds what the command wrote, with a line feed ending every line on
every platform. `python build.py write` rewrites it from the code in the tree.

Every input holds only private addresses and locally administered hardware
addresses: a recorded case already does, and the two messages in `tests/data/`
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
import time
import typing as _ty

HERE = pathlib.Path(__file__).resolve().parent
TESTS = HERE.parent.parent
CASES = TESTS / "conformance" / "cases"
EXPECTED = HERE / "expected"

if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from cli_process import BIND_SECONDS, environment, free_port  # noqa: E402

#: How `pydhcp capture` is told to write one file for each record.
PER_CAPTURE: "tuple[str, ...]" = ("--per-capture",)

#: The most a scenario waits for the command to end by itself.
RUN_SECONDS = 120.0


def recorded() -> "list[bytes]":
    """Every datagram of every recorded case: cases by name, then index."""
    found = []
    for path in sorted(CASES.glob("*/case.json")):
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


def run(argv: "_ty.Sequence[str]", sent: "_ty.Sequence[bytes]") -> Done:
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
        env=environment(),
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
            if "Listening on" in text:
                listening.set()

    threads = [threading.Thread(target=read_out), threading.Thread(target=read_err)]
    for thread in threads:
        thread.daemon = True
        thread.start()
    try:
        if not listening.wait(60):
            raise AssertionError("the command did not bind:\n" + "\n".join(stderr))
        time.sleep(BIND_SECONDS)
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

    for name in ("json", "yaml"):
        done = run(["--format", name, "--count", str(len(sent))], sent)
        statuses[f"stdout_{name}"] = done.status
        files[f"stdout_{name}.out"] = done.stdout

    for name in ("json", "yaml"):
        target = work / f"growing_{name}" / "nested" / f"all.{name}"
        for number, part in enumerate((sent[:half], sent[half:]), 1):
            done = run(["--output", str(target), "--count", str(len(part))], part)
            statuses[f"growing_{name}_run{number}"] = done.status
        files[f"growing/all.{name}"] = target.read_bytes()

    for name in ("json", "yaml", "toml", "ini"):
        root = work / f"tree_{name}"
        pattern = str(root / "{client_id}" / "{xid}_{msg_type}.{format}")
        done = run(
            [
                "--output",
                pattern,
                *PER_CAPTURE,
                "--format",
                name,
                "--count",
                str(len(sent)),
            ],
            sent,
        )
        statuses[f"tree_{name}"] = done.status
        files.update(_tree(root, f"tree_{name}"))

    # No --format: the ending of the pattern names the format.
    root = work / "tree_ending"
    done = run(
        [
            "--output",
            str(root / "{xid}_{msg_type}.ini"),
            *PER_CAPTURE,
            "--count",
            str(len(sent)),
        ],
        sent,
    )
    statuses["tree_ending"] = done.status
    files.update(_tree(root, "tree_ending"))

    # A budget of three files and a fourth client: the run ends by itself.
    root = work / "budget"
    done = run(
        [
            "--output",
            str(root / "{client_id}.{format}"),
            *PER_CAPTURE,
            "--format",
            "json",
            "--max-files",
            "3",
        ],
        distinct_clients(4),
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
