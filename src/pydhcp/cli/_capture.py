"""`pydhcp capture`: record DHCP traffic, and where each record goes."""

from __future__ import annotations

import pathlib
import sys
import typing as _ty

import pktcap as _pktcap
from duho import Meta

from ..capture._events import CaptureEvent
from ..capture._sync import DHCPCapture
from ..capture._writer import MAX_CAPTURE_FILES, DHCPCaptureWriter
from ._capture_hook import _load_capture_hook
from ._common import CAPTURE_FORMATS, _arguments, _Configured, _Failed, closed_stdout
from ._settings import listen_value


def _probe(path: pathlib.Path) -> None:
    """Refuse an output file that cannot be appended to, before anything is bound.

    The file is created when it is absent, as the first record would create it.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8"):
            pass
    except OSError as error:
        raise ValueError(
            f"--output {path} cannot be written: {error.strerror or error}"
        ) from None


class _Ending:
    """Why the capture stopped before it was interrupted, and what it still owes."""

    def __init__(self) -> None:
        self.stopped = False
        self.over_budget = False
        self.failure: "_ty.Optional[Exception]" = None
        self.count = 0
        self.late = 0  # records that arrived after the budget ran out


class Capture(_Configured):
    """Capture DHCP packets"""

    _parsername_ = "capture"

    listen: _ty.Annotated[
        _ty.Optional[str], Meta(env="PYDHCP_CAPTURE_LISTEN", type=listen_value)
    ] = None
    "Listen address/port spec, for example '*', '127.0.0.1:6767,127.0.0.1:6768' or an interface ('eth1', 'eth1:67', 'aa-bb-cc-dd-ee-ff'). Default: every address, port 67"
    ("--listen", "-l")

    packet_filter: _ty.Annotated[
        _ty.Optional[str], Meta(env="PYDHCP_CAPTURE_FILTER", metavar="EXPRESSION")
    ] = None
    "Capture filter expression, for example 'msg_type=DHCPDISCOVER'. Default: every packet"
    ("--filter",)

    packet_format: _ty.Annotated[
        _ty.Optional[str],
        Meta(choices=CAPTURE_FORMATS, env="PYDHCP_CAPTURE_RECORD_FORMAT"),
    ] = None
    "Record format. Default: from the --output ending (.json, .jsonl, .yaml, .yml, .toml, .ini), else json"
    ("--format", "-f")

    output: _ty.Annotated[pathlib.Path, Meta(env="PYDHCP_CAPTURE_OUTPUT")] = (
        pathlib.Path("-")
    )
    "Capture output file (appended to), filename pattern with --per-capture, or '-' for stdout"
    ("--output", "-o")

    per_capture: _ty.Annotated[bool, Meta(env="PYDHCP_CAPTURE_PER_CAPTURE")] = False
    "Write one file per captured packet, named by the --output pattern: {client_id}, {timestamp}, {msg_type}, {xid}, {index} and {format}. Default: one growing file, or stdout"
    ("--per-capture",)

    count: _ty.Annotated[_ty.Optional[int], Meta(env="PYDHCP_CAPTURE_COUNT")] = None
    "Stop after N accepted packets. Default: run until interrupted"
    ("--count", "-c")

    hook: _ty.Annotated[_ty.Optional[str], Meta(env="PYDHCP_CAPTURE_HOOK")] = None
    "Python hook module:function, or an external command: a name with a directory (./hook, /opt/hook) is that file, found relative to the working directory at start-up; a bare name (hook) is looked up on PATH. Default: none"
    ("--hook",)

    hook_fail_fast: _ty.Annotated[bool, Meta(env="PYDHCP_CAPTURE_HOOK_FAIL_FAST")] = (
        False
    )
    "Stop capturing and exit non-zero on the first hook failure"
    ("--hook-fail-fast",)

    max_files: _ty.Annotated[
        _ty.Optional[int], Meta(env="PYDHCP_CAPTURE_MAX_FILES")
    ] = None
    "With --per-capture: end the capture, status 1, when a record needs more than this many distinct files. Default: 1000"
    ("--max-files",)

    per_interface: _ty.Annotated[bool, Meta(env="PYDHCP_CAPTURE_PER_INTERFACE")] = False
    "Bind one socket per interface address instead of the wildcard; on Linux such sockets hear no broadcast"
    ("--per-interface",)

    def _writer(self, output: str, max_files: int) -> DHCPCaptureWriter:
        stdout = output == "-"
        target = sys.stdout.buffer if stdout else output
        per_capture = self.per_capture
        try:
            try:
                return DHCPCaptureWriter(
                    target,
                    self.packet_format or ("json" if stdout else None),
                    per_capture=per_capture,
                    max_files=max_files,
                )
            except _pktcap.UnsupportedFormatError:  # an ending that names no format
                return DHCPCaptureWriter(
                    target, "json", per_capture=per_capture, max_files=max_files
                )
        except ImportError as error:
            raise ValueError(str(error)) from None

    def __call__(self) -> None:
        output = str(self.output)
        max_files = MAX_CAPTURE_FILES if self.max_files is None else self.max_files
        if self.max_files is not None and not self.per_capture:
            raise ValueError("--max-files only applies to --per-capture")
        if max_files < 1:
            raise ValueError(f"--max-files must be at least 1, got {max_files}")
        if self.per_capture and output == "-":
            raise ValueError("--per-capture requires --output to be a filename pattern")
        # Built before binding, so a mistake in the pattern or the format costs one
        # message and not one per packet.
        writer = self._writer(output, max_files)
        if not self.per_capture and output != "-":
            _probe(pathlib.Path(output))
        ending = _Ending()
        capture: DHCPCapture

        def sink(event: CaptureEvent) -> None:
            # The listener logs what a sink raises and carries on, so a record
            # that cannot be kept has to end the capture from here.
            if ending.stopped:
                ending.late += ending.over_budget
                return
            try:
                writer(event)
            except (OSError, ValueError) as error:
                ending.stopped, ending.failure = True, error
                capture.shutdown()
                return
            if writer.refused:
                ending.stopped = ending.over_budget = True
                capture.shutdown()
                return
            ending.count += 1
            if self.count is not None and ending.count >= self.count:
                ending.stopped = True
                capture.shutdown()

        hook = _load_capture_hook(self.hook, writer.format, self.hook_fail_fast)
        with _arguments():
            capture = DHCPCapture(
                listen="*" if self.listen is None else self.listen,
                packet_filter=self.packet_filter,
                sink=sink,
                hook=hook,
                hook_fail_fast=self.hook_fail_fast,
                per_interface=self.per_interface,
            )
        try:
            with writer, capture:
                capture.serve_forever()
        except KeyboardInterrupt:
            self._logger_.info("Stopped listening due to Ctrl-C")
        failure = ending.failure
        if isinstance(failure, OSError) and output == "-":
            closed = closed_stdout(failure)
            if closed is not None:
                raise closed
        if failure is not None:
            reason = getattr(failure, "strerror", None) or failure
            where = getattr(failure, "filename", None) or output
            raise _Failed(f"capture stopped: cannot write {where}: {reason}")
        if ending.over_budget:
            raise _Failed(
                f"capture stopped: {max_files} files written, the limit of "
                f"--max-files; {writer.refused + ending.late} records refused. "
                "The filename pattern includes a value the client chooses, so a "
                "flood of forged identifiers would otherwise fill the disk: raise "
                "--max-files, or use a pattern without {client_id}"
            )
        if capture.hook_error is not None:
            # --hook-fail-fast asked for this: say why it stopped, and do
            # not report success.
            raise _Failed(f"capture stopped: hook failed ({capture.hook_error})")
