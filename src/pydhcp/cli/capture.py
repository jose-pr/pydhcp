"""`pydhcp capture`: record DHCP traffic, and where each record goes."""

from __future__ import annotations

import logging as _logging
import pathlib
import sys
import typing as _ty

from duho import Meta

from ..capture import (
    UNIQUE_FILENAME_FIELDS,
    CaptureEvent,
    DHCPCapture,
    validate_filename_pattern,
)
from ._common import CAPTURE_FORMATS, _Command
from .capture_hook import _load_capture_hook, _serialize_capture_event

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


#: How many distinct files one `--output-mode per-capture` run may create.
#: The filename pattern interpolates values the *client* chooses -- the client
#: identifier above all -- so without a bound, one unauthenticated sender
#: decides how many files land on the operator's disk. Measured: 5,000 forged
#: identifiers produced 5,000 files.
MAX_PER_CAPTURE_FILES = 1000


def _per_capture_budget(state: "dict[str, _ty.Any]", path: pathlib.Path) -> bool:
    """Whether this run may still create `path`. Rewriting a file is always fine.

    Counted per run rather than per name so that a pattern *without* a
    client-chosen component -- which simply overwrites one file -- is not
    limited at all.
    """
    seen = state.setdefault("per_capture_files", set())
    if path in seen:
        return True
    if len(seen) < MAX_PER_CAPTURE_FILES:
        seen.add(path)
        return True
    if not state.get("per_capture_full_reported"):
        state["per_capture_full_reported"] = True
        LOGGER.warning(
            f"Reached {MAX_PER_CAPTURE_FILES} per-capture files; not creating more. "
            "The filename pattern includes a value the client chooses, so a flood "
            "of forged identifiers would otherwise fill the disk. Raise "
            "MAX_PER_CAPTURE_FILES, or use a pattern without {client_id}."
        )
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
    payload = _serialize_capture_event(event, packet_format)
    target = "-" if output is None else str(output)
    if output_mode == "per-capture":
        if target == "-":
            raise ValueError("--output-mode per-capture requires a filename pattern")
        path = pathlib.Path(event.format_filename(target, packet_format))
        if not _per_capture_budget(state, path):
            return payload
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
        return payload

    prefix = _stream_separator(packet_format, bool(state.get("first", True)))
    state["first"] = False
    record = prefix + payload
    if target == "-":
        sys.stdout.write(record)
        if not record.endswith("\n"):
            sys.stdout.write("\n")
        # Flush per record: piped into `jq` or `tee`, stdout is block-buffered,
        # so a live capture showed nothing for ~8 KB or until it exited -- and
        # lost whatever was still buffered if it was killed.
        sys.stdout.flush()
        return payload

    path = pathlib.Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(record)
        if not record.endswith("\n"):
            handle.write("\n")
    return payload


class Capture(_Command):
    """Capture DHCP packets"""

    _parsername_ = "capture"

    listen: _ty.Optional[str] = None
    "Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'"
    ("--listen", "-l")

    packet_filter: _ty.Optional[str] = None
    "Capture filter expression"
    ("--filter",)

    packet_format: _ty.Annotated[_ty.Optional[str], Meta(choices=CAPTURE_FORMATS)] = (
        None
    )
    ("--format", "-f")

    output: pathlib.Path = pathlib.Path("-")
    "Capture output path, filename pattern, or '-' for stdout"
    ("--output", "-o")

    output_mode: _ty.Annotated[
        _ty.Optional[str], Meta(choices=("stream", "single", "per-capture"))
    ] = None
    "Write a stream, one combined file, or one file per captured packet"
    ("--output-mode",)

    count: _ty.Optional[int] = None
    "Stop after N accepted packets"
    ("--count", "-c")

    hook: _ty.Optional[str] = None
    "Python hook module:function, or an external command: a name with a directory (./hook, /opt/hook) is that file, found relative to the working directory at start-up; a bare name (hook) is looked up on PATH"
    ("--hook",)

    hook_fail_fast: bool = False
    "Stop capturing and exit non-zero on the first hook failure"
    ("--hook-fail-fast",)

    per_interface: bool = False
    "Bind one socket per interface address instead of the wildcard; on Linux such sockets hear no broadcast"
    ("--per-interface",)

    def __call__(self) -> None:
        try:
            output = self.output if self.output is not None else pathlib.Path("-")
            output_mode = _infer_output_mode(output, self.output_mode)
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
            state: "dict[str, _ty.Any]" = {"first": True, "count": 0}
            capture: DHCPCapture

            def sink(event: CaptureEvent) -> None:
                _write_capture_record(
                    event,
                    output=output,
                    output_mode=output_mode,
                    packet_format=packet_format,
                    state=state,
                )
                state["count"] += 1
                if self.count is not None and state["count"] >= self.count:
                    capture.stop()

            hook = _load_capture_hook(self.hook, packet_format, self.hook_fail_fast)
            capture = DHCPCapture(
                listen=self.listen or "*",
                packet_filter=self.packet_filter,
                sink=sink,
                hook=hook,
                hook_fail_fast=self.hook_fail_fast,
                per_interface=self.per_interface,
            )
            capture.bind()
            capture.listen()
            if capture.hook_error is not None:
                # --hook-fail-fast asked for this: say why it stopped, and do
                # not report success.
                print(
                    f"Capture stopped: hook failed ({capture.hook_error})",
                    file=sys.stderr,
                )
                sys.exit(1)
        except Exception as e:
            print(f"Error capturing packets: {e}", file=sys.stderr)
            sys.exit(1)
