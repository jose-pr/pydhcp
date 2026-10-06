"""A DHCP message for people: its client identity, summary text and log lines."""

from __future__ import annotations

import logging as _logging
import textwrap as _tw
import typing as _ty

from .. import _nvt as _nvt
from ..exceptions import NoClientIdentityError
from ..options._codes import BaseDHCPOptionCode, DHCPOptionCode
from ..options import _codecs as _type
from ..options._codecs._base import option_text as _option_text
from ._mapping import _MessageMapping

if _ty.TYPE_CHECKING:
    # Annotation only: the callback receives the public class, and importing
    # it at run time would be a cycle (_message.py builds on this module).
    from ._message import DHCPMessage

LOGGER = _logging.getLogger(__name__)


class _MessageDisplay(_MessageMapping):
    """`client_id`, `dumps`, `log_str`, `log` and `in`."""

    def client_id(
        self, func: _ty.Optional[_ty.Callable[["DHCPMessage"], bytearray]] = None
    ) -> str:
        """Stable identity for this client, used to key leases.

        Option 61 when present, else the hardware type and address. Raises
        `NoClientIdentityError` when the message carries neither: `hlen` may legally
        be 0 (RFC 4390 requires exactly that for IPoIB, which supplies option 61
        instead), and the old fallback then produced the hardware-type octet
        alone -- one identifier, `"01"`, shared by every such client. Two of them
        would take over each other's lease, and a RELEASE from either would free
        both.
        """
        cid = self.options.get(DHCPOptionCode.CLIENT_IDENTIFIER, decode=False)
        if not cid:
            if func:
                # The layers are private and only ever composed into
                # DHCPMessage, so every instance reaching here is one.
                cid = func(_ty.cast("DHCPMessage", self))
            if not cid:
                if not self.chaddr:
                    raise NoClientIdentityError(
                        "message has neither a client identifier (option 61) nor "
                        f"a hardware address (hlen=0, htype={self.htype.label()})"
                    )
                cid = bytearray([self.htype.value])
                cid.extend(self.chaddr)
        return cid.hex(":").upper()

    def dumps(self, codemap: _ty.Optional[type[BaseDHCPOptionCode]] = None) -> str:
        """A human-readable multi-line summary: header fields, then each option.

        What `log`/`log_str` and the CLI's ``--format summary`` print. Text fields go
        through `pydhcp._nvt.display`, so it is always safe for a terminal. `codemap`
        names the options; it defaults to the message's own.
        """
        lines = []
        for name, value in [
            ("OP", self.op.name),
            ("Time Since Boot", str(self.secs)),
            ("Hops", str(self.hops)),
            ("Transaction ID", str(self.xid)),
            ("Flags", self.flags.name),
            ("Client Current Address", str(self.ciaddr)),
            ("Allocated Address", str(self.yiaddr)),
            ("Gateway Address", str(self.giaddr)),
            ("Hardware Address", f"{self.htype.name}({self.htype.dumps(self.chaddr)})"),
            ("Next Server (siaddr)", str(self.siaddr)),
            ("Server Host Name", _nvt.display(self.sname)),
            ("Bootfile", _nvt.display(self.file)),
        ]:
            lines.append(f"{name: <40}: {value}")
        lines.append("OPTIONS:")
        _codemap = codemap or self.options._codemap
        for _code, _raw in self.options._options.items():
            # Render per option, never as a batch: an unregistered code (93 of 254 are
            # not enum members) or one malformed payload must not cost the whole dump.
            # Same fallback `to_mapping` uses.
            try:
                code = _codemap.from_code(_code)
                opt_val: _ty.Any = code.get_type()._dhcp_decode(_raw)
            except Exception:
                code = _code  # type: ignore[assignment]
                opt_val = _type.Bytes(_raw)
            decoded_str = _option_text(opt_val)
            decoded_lines = decoded_str.splitlines()
            SPACE = " " * 42
            if decoded_lines:
                first = _tw.fill(
                    decoded_lines[0],
                    width=100,
                    initial_indent="",
                    subsequent_indent=SPACE,
                )
            else:
                first = ""
            lines.append(f"  {repr(code): <38}: {first}")
            for line in decoded_lines[1:]:
                lines.append(
                    _tw.fill(
                        line, width=100, initial_indent=SPACE, subsequent_indent=SPACE
                    )
                )

        return "\n".join(lines)

    def log_str(self, src: _ty.Any, dst: _ty.Any) -> str:
        """`dumps()` under a one-line header naming the op, XID, source and destination."""
        return (
            f"{self.op.name} XID={self.xid:08X} Src: {src} Dst: {dst}\n"
            f"{self.dumps()}"
        )

    def __contains__(self, __key: object) -> bool:
        """Whether the message carries option `__key` (a code or `DHCPOptionCode`)."""
        return self.options.__contains__(__key)

    def log(self, src: _ty.Any, dst: _ty.Any, level: int) -> None:
        """Log the packet at `level`.

        Never raises and never does work the level does not call for: callers on the
        receive and send paths invoke this before handling or sending, so a failure
        here would silently cost a packet its handler or its reply.
        """
        if not LOGGER.isEnabledFor(level):
            return
        try:
            header = (
                f"{'#' * 10} {self.op.name} XID={self.xid:08X} "
                f"Src: {src} Dst: {dst} {'#' * 10}"
            )
            LOGGER.log(level, f"\n{header}\n{self.dumps()}\n{'#' * len(header)}")
        except Exception:  # pragma: no cover - defensive, dumps() is already tolerant
            LOGGER.log(level, "Could not format packet for logging", exc_info=True)
