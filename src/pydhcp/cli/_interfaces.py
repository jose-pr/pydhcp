"""`pydhcp interfaces`: list the host's addresses."""

from __future__ import annotations

import json as _json
import typing as _ty

from duho import Meta

from .._network import host_ip_interfaces
from ._common import _Command, write_line


class Interfaces(_Command):
    """List network interfaces"""

    _parsername_ = "interfaces"

    output_format: _ty.Annotated[
        str, Meta(choices=("text", "json"), env="PYDHCP_INTERFACES_FORMAT")
    ] = "text"
    "Output: 'text' is one tab-separated line per address (name, address, MAC or '-', network); 'json' is one array of objects"
    ("--format", "-f")

    def __call__(self) -> None:
        rows: "list[dict[str, _ty.Optional[str]]]" = []
        for interface in host_ip_interfaces():
            mac = interface.mac
            rows.append(
                {
                    "name": interface.name,
                    "ip": str(interface.ip),
                    "mac": mac.format("-", upper=True) if mac else None,
                    "network": str(interface.network),
                }
            )
        if self.output_format == "json":
            write_line(_json.dumps(rows))
            return
        for row in rows:
            write_line("\t".join(value or "-" for value in row.values()))
