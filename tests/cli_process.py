"""Run the `pydhcp` command as a process, as a user does.

What only a process shows: the exit status, standard output against standard
error, a closed pipe, a signal. The environment is the test run's own with every
`PYDHCP_` variable removed, so a developer's settings cannot leak into a test,
plus whatever the test passes.
"""

from __future__ import annotations

import os
import subprocess
import sys
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
