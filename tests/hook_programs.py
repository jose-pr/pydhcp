"""A real program to run as a `--hook` of `pydhcp capture`.

pktcap starts a hook by path with no argument, and refuses a `.cmd` file. Nothing here
replaces `subprocess`: the program is a file the system can start, or this interpreter.
"""

from __future__ import annotations

import os
import pathlib
import sys
import textwrap
import typing as _ty


class CliHook(_ty.NamedTuple):
    """A hook program for a `pydhcp capture` process: the command, and the environment it needs."""

    command: str
    #: Extra environment for the process that runs the command; empty on POSIX.
    env: "dict[str, str]"


_SITECUSTOMIZE = """\
import os
import runpy
import sys

# Started with no arguments and nothing else: the program the capture runs as a hook.
# The capture that starts it has arguments and leaves the variable for the hook.
_script = os.environ.get("PYDHCP_TEST_HOOK_SCRIPT") if sys.argv in ([""], []) else None
if _script:
    os.environ.pop("PYDHCP_TEST_HOOK_SCRIPT", None)
    try:
        runpy.run_path(_script, run_name="__main__")
        _code = 0
    except SystemExit as _stop:
        _code = _stop.code if isinstance(_stop.code, int) else int(bool(_stop.code))
    except BaseException:
        import traceback

        traceback.print_exc()
        _code = 1
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_code)
"""


def cli_hook(directory: pathlib.Path, name: str, source: str) -> CliHook:
    """A hook program that runs `source`, for `--hook`; its command and environment.

    On POSIX that is a `#!/bin/sh` launcher beside the script. On Windows there is no
    launcher that can be started by path, so the program is this interpreter, which with
    no argument would read its script from standard input: a `sitecustomize` module,
    found through `PYTHONPATH`, runs the script first and exits. Either way the script
    has its own directory as `HERE`, a `pathlib.Path`.
    """
    from cli_process import SRC

    script = directory / (name + ".py")
    script.write_bytes(
        (
            "import pathlib\nHERE = pathlib.Path(__file__).resolve().parent\n"
            + textwrap.dedent(source)
        ).encode("utf-8")
    )
    if os.name == "nt":
        site = directory / ("site-" + name)
        site.mkdir(exist_ok=True)
        (site / "sitecustomize.py").write_bytes(_SITECUSTOMIZE.encode("utf-8"))
        return CliHook(
            sys.executable,
            {
                "PYTHONPATH": os.pathsep.join([str(site), SRC]),
                "PYDHCP_TEST_HOOK_SCRIPT": str(script),
            },
        )
    launcher = directory / name
    launcher.write_bytes(
        f'#!/bin/sh\nexec "{sys.executable}" "{script}"\n'.encode("utf-8")
    )
    launcher.chmod(0o755)
    return CliHook(str(launcher), {})
