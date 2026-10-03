"""`pydhcp packet`: encode or decode one message."""

from __future__ import annotations

import pathlib
import sys
import typing as _ty

from duho import Meta

from ..packet.message import DhcpMessage
from ..packet.structured import dump_message, load_message
from ._common import PACKET_FORMATS, _Command


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
    ("--encode",)

    input: str = "-"
    "Input file path, or '-' for stdin"
    ("--input", "-i")

    output: str = "-"
    "Output file path, or '-' for stdout"
    ("--output", "-o")

    packet_format: _ty.Annotated[str, Meta(choices=PACKET_FORMATS)] = "json"
    "Packet text format; 'summary' is decode-only"
    ("--format", "-f")

    def __call__(self) -> None:
        try:
            if self.input == "-":
                payload_text = sys.stdin.read()
            else:
                payload_text = pathlib.Path(self.input).read_text(encoding="utf-8")

            if self.mode:
                packet = DhcpMessage.decode(
                    bytearray.fromhex(
                        "".join(ch for ch in payload_text if ch not in " \t\r\n:")
                    )
                )
                if self.packet_format == "summary":
                    output = packet.log_str("capture", "decoded")
                else:
                    output = dump_message(packet, self.packet_format)
            else:
                if self.packet_format == "summary":
                    raise ValueError(
                        "summary output is only supported when decoding packets"
                    )
                packet = load_message(payload_text, self.packet_format)
                output = packet.encode().hex()

            if self.output == "-":
                sys.stdout.write(output)
                if not output.endswith("\n"):
                    sys.stdout.write("\n")
            else:
                pathlib.Path(self.output).write_text(output, encoding="utf-8")
        except Exception as e:
            print(f"Error processing packet: {e}", file=sys.stderr)
            sys.exit(1)
