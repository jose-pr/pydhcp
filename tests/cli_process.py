"""Run the `pydhcp` command as a process, as a user does.

What only a process shows: the exit status, standard output against standard
error, a closed pipe, a signal. The environment is the test run's own with every
`PYDHCP_` variable removed, so a developer's settings cannot leak into a test,
plus whatever the test passes.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import typing as _ty

import pydhcp

#: The directory that holds the package, so the child imports the tree under test.
SRC = os.path.dirname(os.path.dirname(os.path.abspath(pydhcp.__file__)))

#: A program that prints each command's resolved fields as one JSON object
#: instead of running it: the settings layers apply, the sockets are not opened.
SHOW_SETTINGS = """
import json
import sys

import pydhcp.cli as cli


def show(self):
    fields = {b.name: getattr(self, b.name) for b in type(self)._getargs_()}
    print(json.dumps(fields, default=str))


for command in (cli.Interfaces, cli.Server, cli.Relay, cli.Packet, cli.Capture):
    command.__call__ = show
raise SystemExit(cli.main(sys.argv[1:]))
"""


def environment(
    extra: "_ty.Optional[_ty.Mapping[str, str]]" = None,
) -> "dict[str, str]":
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYDHCP_")}
    env["PYTHONPATH"] = os.pathsep.join([SRC, env.get("PYTHONPATH", "")]).rstrip(
        os.pathsep
    )
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra or {})
    return env


def run_cli(
    *argv: str,
    env: "_ty.Optional[_ty.Mapping[str, str]]" = None,
    input: "_ty.Optional[str]" = None,
    cwd: "_ty.Optional[_ty.Union[str, os.PathLike[str]]]" = None,
    timeout: float = 60.0,
    program: "_ty.Optional[_ty.Union[str, os.PathLike[str]]]" = None,
) -> "subprocess.CompletedProcess[str]":
    """`python -m pydhcp argv...`, or `python program argv...`.

    Standard input is empty unless `input` is given.
    """
    command = (
        [sys.executable, "-m", "pydhcp"]
        if program is None
        else [sys.executable, str(program)]
    )
    return subprocess.run(
        [*command, *argv],
        capture_output=True,
        text=True,
        encoding="utf-8",
        input="" if input is None else input,
        env=environment(env),
        cwd=cwd,
        timeout=timeout,
    )


def free_port() -> int:
    """A UDP port on 127.0.0.1 nothing holds right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


#: How long after the listener's announcement a command is given to have bound.
BIND_SECONDS = 1.0


class Running:
    """`pydhcp argv...` started and left running.

    Start it with `-v` and `--listen 127.0.0.1:<free_port()>`: the listener
    announces that it is binding, and `listening()` waits for that line and for
    the bind that follows it. `finish()` waits for the command to
    end by itself and returns its status, killing it, and failing the caller's
    check, when it does not.
    """

    def __init__(
        self,
        *argv: str,
        env: "_ty.Optional[_ty.Mapping[str, str]]" = None,
        cwd: "_ty.Optional[_ty.Union[str, os.PathLike[str]]]" = None,
    ) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-m", "pydhcp", *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment(env),
            cwd=cwd,
        )
        self.stdout: "list[str]" = []
        self.stderr: "list[str]" = []
        self._listening = threading.Event()
        assert self.process.stdout is not None and self.process.stderr is not None
        self._threads = [
            threading.Thread(
                target=self._read, args=(self.process.stdout, self.stdout), daemon=True
            ),
            threading.Thread(
                target=self._read, args=(self.process.stderr, self.stderr), daemon=True
            ),
        ]
        for thread in self._threads:
            thread.start()

    def _read(self, stream: "_ty.IO[str]", into: "list[str]") -> None:
        for line in stream:
            into.append(line.rstrip("\r\n"))
            if "Listening on" in line:
                self._listening.set()

    def listening(self, timeout: float = 30.0) -> None:
        """Wait until the command has announced that it binds, and for the bind.

        The line is logged just before the bind. A test cannot probe the port
        instead: a bind of its own would hold the port for the moment the command
        wants it.
        """
        if not self._listening.wait(timeout):
            self.kill()
            raise AssertionError("the command did not bind:\n" + "\n".join(self.stderr))
        time.sleep(BIND_SECONDS)

    def finish(self, timeout: float = 30.0) -> int:
        try:
            status = self.process.wait(timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            raise AssertionError(
                "the command did not end by itself:\n" + "\n".join(self.stderr)
            ) from None
        for thread in self._threads:
            thread.join(10)
        return status

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
