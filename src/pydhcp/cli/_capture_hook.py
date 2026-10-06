"""Loading a `pydhcp capture --hook`: a Python callable or an executable."""

from __future__ import annotations

import contextlib
import importlib
import os
import sys
import typing as _ty

from ..capture._command import command_hook
from ..capture._events import CaptureEvent


@contextlib.contextmanager
def _cwd_on_sys_path() -> "_ty.Iterator[None]":
    """Make `--hook myhooks:on_capture` work from the installed console script.

    A console script's `sys.path[0]` is its own Scripts directory, not the
    working directory, so the form the docs show could not import a module
    sitting next to the user.
    """
    cwd = os.getcwd()
    added = cwd not in sys.path
    if added:
        sys.path.insert(0, cwd)
    try:
        yield
    finally:
        if added:
            try:
                sys.path.remove(cwd)
            except ValueError:  # pragma: no cover - someone else removed it
                pass


def _load_capture_hook(
    hook: "_ty.Optional[str]", packet_format: str, fail_fast: bool
) -> "_ty.Optional[_ty.Callable[[CaptureEvent], None]]":
    if not hook:
        return None
    # A module reference is `package.module:function` -- never contains a path
    # separator. Deciding on the separator rather than on ':' alone keeps
    # "C:\hooks\export.exe" a path on every platform: it has exactly one ':', so
    # it used to be read as module "C" and reported as "No module named 'C'",
    # and splitdrive alone would only have fixed that on Windows.
    has_separator = "/" in hook or "\\" in hook
    if not has_separator and hook.count(":") == 1:
        module_name, function_name = hook.split(":", 1)
        with _cwd_on_sys_path():
            module = importlib.import_module(module_name)
        function = getattr(module, function_name, None)
        if not callable(function):
            raise ValueError(f"Capture hook {hook!r} does not resolve to a callable")
        return _ty.cast(_ty.Callable[[CaptureEvent], None], function)
    return command_hook(hook, packet_format=packet_format, fail_fast=fail_fast)
