"""`pydhcp packet`: encode or decode one message."""

from __future__ import annotations

import pathlib
import sys
import typing as _ty

from duho import Meta

from ..packet._message import DHCPMessage
from ._common import PACKET_FORMATS, _Command, _Failed, write_line


class Packet(_Command):
    """Encode or decode DHCP packets"""

    _parsername_ = "packet"

    decode: _ty.Annotated[
        bool,
        Meta(
            action="store_const",
            const=True,
            conflicts="mode",
            conflicts_required=True,
            kwargs={"dest": "mode"},
        ),
    ] = False
    "Read the message as hexadecimal text and print it in --format"
    ("--decode",)

    encode: _ty.Annotated[
        bool,
        Meta(
            action="store_const",
            const=False,
            conflicts="mode",
            conflicts_required=True,
            kwargs={"dest": "mode"},
        ),
    ] = False
    "Read the message as a --format document and print it as hexadecimal text"
    ("--encode",)

    input: _ty.Annotated[pathlib.Path, Meta(env="PYDHCP_PACKET_INPUT")] = pathlib.Path(
        "-"
    )
    "Input file path, or '-' for stdin"
    ("--input", "-i")

    output: _ty.Annotated[pathlib.Path, Meta(env="PYDHCP_PACKET_OUTPUT")] = (
        pathlib.Path("-")
    )
    "Output file path, or '-' for stdout"
    ("--output", "-o")

    packet_format: _ty.Annotated[
        str, Meta(choices=PACKET_FORMATS, env="PYDHCP_PACKET_FORMAT")
    ] = "json"
    "Packet text format; 'summary' is decode-only"
    ("--format", "-f")

    def __call__(self) -> None:
        if self.mode is not True and self.packet_format == "summary":
            raise ValueError("--format summary is only supported with --decode")
        try:
            if str(self.input) == "-":
                payload_text = sys.stdin.read()
            else:
                payload_text = self.input.read_text(encoding="utf-8")

            if self.mode:
                packet = DHCPMessage.from_hex(payload_text)
                if self.packet_format == "summary":
                    output = (
                        f"{packet.op.name} XID={packet.xid:08X}\n{packet.summary()}"
                    )
                else:
                    output = packet.to_text(self.packet_format)
            else:
                packet = DHCPMessage.from_text(payload_text, self.packet_format)
                output = packet.encode().hex()
        except (ValueError, OSError) as error:
            raise _Failed(f"cannot process the packet: {error}") from None

        if str(self.output) == "-":
            write_line(output)
        else:
            self.output.write_text(output, encoding="utf-8")
