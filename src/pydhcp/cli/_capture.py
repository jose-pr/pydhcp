"""`pydhcp capture`: record DHCP traffic, and where each record goes."""

from __future__ import annotations

import pathlib
import sys
import typing as _ty

import pktcap as _pktcap
from duho import Meta

from ..capture._events import CaptureHook
from ..capture._offline import capture_dissector, read_capture, unread_note
from ..capture._run import CaptureRun
from ..capture._sync import DHCPCapture
from ..capture._writer import MAX_CAPTURE_FILES, DHCPCaptureWriter
from ._capture_hook import _load_capture_hook
from ._common import CAPTURE_FORMATS, _arguments, _Failed, _Listening, closed_stdout


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


class Capture(_Listening):
    """Capture DHCP packets"""

    _parsername_ = "capture"
    # Not a tool: it does not return until it is stopped, and
    # starts a program per packet.
    _mcp_ = False

    packet_filter: _ty.Annotated[
        _ty.Optional[str], Meta(env="PYDHCP_CAPTURE_FILTER", metavar="EXPRESSION")
    ] = None
    "Capture filter expression, for example 'msg_type=DHCPDISCOVER'. Default: every packet"
    ("--filter",)

    packet_format: _ty.Annotated[
        _ty.Optional[str],
        Meta(choices=CAPTURE_FORMATS, env="PYDHCP_CAPTURE_RECORD_FORMAT"),
    ] = None
    "Output format: pcap or pcapng (the datagrams, readable by tcpdump and Wireshark), or json, yaml, toml, ini (one record for each message). Default: from the --output ending (.pcap, .cap, .pcapng, .json, .jsonl, .ndjson, .yaml, .yml, .toml, .ini), else json"
    ("--format", "-f")

    output: _ty.Annotated[pathlib.Path, Meta(env="PYDHCP_CAPTURE_OUTPUT")] = (
        pathlib.Path("-")
    )
    "Capture output file (a record file is appended to, a capture file replaced), filename pattern with --per-capture, or '-' for stdout"
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

    read: _ty.Annotated[_ty.Optional[pathlib.Path], Meta(env="PYDHCP_CAPTURE_READ")] = (
        None
    )
    "Read the DHCP messages of this pcap or pcapng capture file ('-' is standard input) instead of listening, and put them through the same filter, output and hook. Not with --listen. Default: listen"
    ("--read",)

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

    def _read(
        self, run: CaptureRun, hook: "_ty.Optional[CaptureHook]"
    ) -> "_ty.Optional[Exception]":
        """Put the messages of the capture file through the sink and the hook.

        Returns the hook failure that ended the run under `--hook-fail-fast`.
        """
        path = "-" if self.read is None else str(self.read)
        source = sys.stdin.buffer if path == "-" else path
        frames = capture_dissector()
        events = read_capture(
            source, packet_filter=self.packet_filter, dissector=frames
        )
        try:
            return run.drain(events, hook, fail_fast=self.hook_fail_fast)
        except _pktcap.CaptureFormatError as error:
            raise ValueError(f"{path}: {error}") from None
        finally:
            say = unread_note(path, frames)
            if say:
                print(say, file=sys.stderr)

    def __call__(self) -> None:
        output = str(self.output)
        max_files = MAX_CAPTURE_FILES if self.max_files is None else self.max_files
        if self.max_files is not None and not self.per_capture:
            raise ValueError("--max-files only applies to --per-capture")
        if max_files < 1:
            raise ValueError(f"--max-files must be at least 1, got {max_files}")
        if self.per_capture and output == "-":
            raise ValueError("--per-capture requires --output to be a filename pattern")
        if self.read is not None and self.listen is not None:
            raise ValueError(
                "--read reads a capture file and does not listen: drop --listen"
            )
        # Built before binding, so a mistake in the pattern or the format costs one
        # message and not one per packet.
        writer = self._writer(output, max_files)
        if not self.per_capture and output != "-":
            _probe(pathlib.Path(output))
        capture: _ty.Optional[DHCPCapture] = None
        run = CaptureRun(
            writer,
            lambda: capture.shutdown() if capture is not None else None,
            count=self.count,
        )
        # A capture file holds no text of a message: a hook reads it as JSON.
        hook_format = (
            writer.format if writer.format in _pktcap.RECORD_FORMATS else "json"
        )
        hook = _load_capture_hook(self.hook, hook_format, self.hook_fail_fast)
        hook_error: "_ty.Optional[BaseException]" = None
        with writer:
            if self.read is not None:
                hook_error = self._read(run, hook)
            else:
                with _arguments():
                    capture = DHCPCapture(
                        listen="*" if self.listen is None else self.listen,
                        packet_filter=self.packet_filter,
                        sink=run,
                        hook=hook,
                        hook_fail_fast=self.hook_fail_fast,
                        per_interface=self.per_interface,
                    )
                self._serve(capture)
                hook_error = capture.hook_error
        failure = run.failure
        if isinstance(failure, OSError) and output == "-":
            closed = closed_stdout(failure)
            if closed is not None:
                raise closed
        if failure is not None:
            reason = getattr(failure, "strerror", None) or failure
            where = getattr(failure, "filename", None) or output
            raise _Failed(f"capture stopped: cannot write {where}: {reason}")
        if run.over_budget:
            raise _Failed(
                f"capture stopped: {max_files} files written, the limit of "
                f"--max-files; {writer.refused + run.late} records refused. "
                "The filename pattern includes a value the client chooses, so a "
                "flood of forged identifiers would otherwise fill the disk: raise "
                "--max-files, or use a pattern without {client_id}"
            )
        if hook_error is not None:
            # --hook-fail-fast asked for this: say why it stopped, and do
            # not report success.
            raise _Failed(f"capture stopped: hook failed ({hook_error})")
