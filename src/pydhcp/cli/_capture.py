"""`pydhcp capture`: record DHCP traffic, and where each record goes."""

from __future__ import annotations

import logging as _logging
import pathlib
import typing as _ty

from duho import Meta

from ..capture._events import (
    UNIQUE_FILENAME_FIELDS,
    CaptureEvent,
    serialize_event,
    validate_filename_pattern,
)
from ..capture._sync import DHCPCapture
from ._common import CAPTURE_FORMATS, _arguments, _Configured, _Failed, write_line
from ._settings import listen_value
from ._capture_hook import _load_capture_hook

LOGGER = _logging.getLogger(__name__)


def _infer_capture_format(
    output: "_ty.Optional[_ty.Union[pathlib.Path, str]]",
    packet_format: "_ty.Optional[str]",
) -> str:
    if packet_format:
        return packet_format
    if output is not None and str(output) != "-":
        suffix = pathlib.Path(str(output)).suffix.lower()
        if suffix == ".json":
            return "json"
        if suffix in {".yaml", ".yml"}:
            return "yaml"
        if suffix == ".toml":
            return "toml"
        if suffix == ".ini":
            return "ini"
    return "json"


def _infer_output_mode(
    output: "_ty.Optional[_ty.Union[pathlib.Path, str]]",
    output_mode: "_ty.Optional[str]",
) -> str:
    if output_mode:
        return output_mode
    if output is None or str(output) == "-":
        return "stream"
    return "single"


def _stream_separator(packet_format: str, first: bool) -> str:
    """Return what must precede a record so the file stays parseable.

    YAML gets its `---` even on the first record of a run. The flag says "first
    for this process", but the file is opened for append: a second run's first
    record was written straight onto the last record of the first with no
    separator, so YAML merged the two mappings and the earlier record silently
    disappeared on load. A leading `---` is valid for the opening document too,
    which makes the output correct whether the file is new or appended to.
    """
    if packet_format == "json":
        return ""  # newline-delimited; a separator would break it
    return "---\n"


#: How many distinct files one `--output-mode per-capture` run may create, unless
#: `--max-files` says otherwise. The filename pattern interpolates values the
#: *client* chooses -- the client identifier above all -- so without a bound,
#: one unauthenticated sender decides how many files land on the operator's
#: disk. Measured: 5,000 forged identifiers produced 5,000 files.
MAX_PER_CAPTURE_FILES = 1000


class _BudgetFull(Exception):
    """The per-capture file budget is spent and this record needs a new file."""


def _per_capture_budget(state: "dict[str, _ty.Any]", path: pathlib.Path) -> bool:
    """Whether this run may still create `path`. Rewriting a file is always fine.

    Counted per run rather than per name so that a pattern *without* a
    client-chosen component -- which simply overwrites one file -- is not
    limited at all.
    """
    seen = state.setdefault("per_capture_files", set())
    if path in seen:
        return True
    if len(seen) < state.get("max_files", MAX_PER_CAPTURE_FILES):
        seen.add(path)
        return True
    state["per_capture_refused"] = state.get("per_capture_refused", 0) + 1
    return False


def _write_capture_record(
    event: CaptureEvent,
    *,
    output: "_ty.Optional[_ty.Union[pathlib.Path, str]]",
    output_mode: str,
    packet_format: str,
    state: "dict[str, _ty.Any]",
) -> str:
    """Write one record where `output` says; `_BudgetFull` when it needs a file past the budget.

    An `OSError` is a record that could not be written.
    """
    payload = serialize_event(event, packet_format)
    target = "-" if output is None else str(output)
    if output_mode == "per-capture":
        if target == "-":
            raise ValueError("--output-mode per-capture requires a filename pattern")
        path = pathlib.Path(event.format_filename(target, packet_format))
        if not _per_capture_budget(state, path):
            raise _BudgetFull
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8", errors="backslashreplace")
        return payload

    prefix = _stream_separator(packet_format, bool(state.get("first", True)))
    state["first"] = False
    record = prefix + payload
    if target == "-":
        write_line(record)
        return payload

    path = pathlib.Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", errors="backslashreplace") as handle:
        handle.write(record)
        if not record.endswith("\n"):
            handle.write("\n")
    return payload


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
    "Record format. Default: from the --output extension, else json"
    ("--format", "-f")

    output: _ty.Annotated[pathlib.Path, Meta(env="PYDHCP_CAPTURE_OUTPUT")] = (
        pathlib.Path("-")
    )
    "Capture output path, filename pattern, or '-' for stdout"
    ("--output", "-o")

    output_mode: _ty.Annotated[
        _ty.Optional[str],
        Meta(
            choices=("stream", "single", "per-capture"),
            env="PYDHCP_CAPTURE_OUTPUT_MODE",
        ),
    ] = None
    "Write a stream, one combined file, or one file per captured packet. Default: stream for '-', else single"
    ("--output-mode",)

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
    "With --output-mode per-capture: end the capture, status 1, when a record needs more than this many distinct files. Default: 1000"
    ("--max-files",)

    per_interface: _ty.Annotated[bool, Meta(env="PYDHCP_CAPTURE_PER_INTERFACE")] = False
    "Bind one socket per interface address instead of the wildcard; on Linux such sockets hear no broadcast"
    ("--per-interface",)

    def __call__(self) -> None:
        output = self.output
        output_mode = _infer_output_mode(output, self.output_mode)
        max_files = MAX_PER_CAPTURE_FILES if self.max_files is None else self.max_files
        if self.max_files is not None and output_mode != "per-capture":
            raise ValueError("--max-files only applies to --output-mode per-capture")
        if max_files < 1:
            raise ValueError(f"--max-files must be at least 1, got {max_files}")
        if output_mode == "per-capture":
            if str(output) == "-":
                raise ValueError(
                    "--output-mode per-capture requires --output to be a "
                    "filename pattern"
                )
            # Both checks run before binding, for the same reason the
            # capture filter is compiled eagerly: the pattern is only ever
            # expanded inside the receive handler, so a mistake there costs
            # one message per packet and no recording at all.
            used_fields = validate_filename_pattern(str(output))
            if not used_fields & UNIQUE_FILENAME_FIELDS:
                self._logger_.warning(
                    "--output pattern %s names neither {timestamp} nor {xid}, "
                    "so any two packets agreeing on the rest of it resolve to "
                    "the same file and only the last one is kept",
                    output,
                )
        packet_format = _infer_capture_format(output, self.packet_format)
        if packet_format in ("toml", "ini") and output_mode != "per-capture":
            # Concatenating records produces a file no parser will read: TOML
            # has no document separator, and a second [message] section is a
            # DuplicateSectionError to configparser. One record per file is
            # the only shape these formats have for this. Raised before
            # binding, so it fails immediately rather than after capturing.
            raise ValueError(
                f"--format {packet_format} cannot hold more than one packet in a "
                f"single file; use --output-mode per-capture with a filename "
                f"pattern, or --format json (newline-delimited) or yaml "
                f"(multi-document). Note the format is inferred from the "
                f"--output extension when --format is not given."
            )
        if output_mode != "per-capture" and str(output) != "-":
            _probe(output)

        state: "dict[str, _ty.Any]" = {
            "first": True,
            "count": 0,
            "max_files": max_files,
        }
        capture: DHCPCapture

        def sink(event: CaptureEvent) -> None:
            # The listener logs what a sink raises and carries on, so a record
            # that cannot be kept has to end the capture from here.
            if state.get("stopped"):
                if state.get("budget_full"):
                    state["per_capture_refused"] += 1
                return
            try:
                _write_capture_record(
                    event,
                    output=output,
                    output_mode=output_mode,
                    packet_format=packet_format,
                    state=state,
                )
            except _BudgetFull:
                state["stopped"] = state["budget_full"] = True
                capture.shutdown()
                return
            except (OSError, ValueError) as error:
                state["stopped"] = True
                state["failure"] = error
                capture.shutdown()
                return
            state["count"] += 1
            if self.count is not None and state["count"] >= self.count:
                state["stopped"] = True
                capture.shutdown()

        hook = _load_capture_hook(self.hook, packet_format, self.hook_fail_fast)
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
            with capture:
                capture.serve_forever()
        except KeyboardInterrupt:
            self._logger_.info("Stopped listening due to Ctrl-C")
        failure = state.get("failure")
        if isinstance(failure, BrokenPipeError):
            raise failure
        if failure is not None:
            reason = getattr(failure, "strerror", None) or failure
            where = getattr(failure, "filename", None) or output
            raise _Failed(f"capture stopped: cannot write {where}: {reason}")
        if state.get("budget_full"):
            raise _Failed(
                f"capture stopped: {max_files} files written, the limit of "
                f"--max-files; {state['per_capture_refused']} records refused. "
                "The filename pattern includes a value the client chooses, so a "
                "flood of forged identifiers would otherwise fill the disk: raise "
                "--max-files, or use a pattern without {client_id}"
            )
        if capture.hook_error is not None:
            # --hook-fail-fast asked for this: say why it stopped, and do
            # not report success.
            raise _Failed(f"capture stopped: hook failed ({capture.hook_error})")
