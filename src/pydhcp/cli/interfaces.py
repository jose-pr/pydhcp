"""`pydhcp interfaces`: list the host's addresses."""

from __future__ import annotations


from ..network import host_ip_interfaces
from ._common import _Command


class Interfaces(_Command):
    """List network interfaces"""

    _parsername_ = "interfaces"

    def __call__(self) -> None:
        print("Available Network Interfaces:")
        for interface in host_ip_interfaces():
            print(f"Name: {interface.name}")
            print(f"  IP:   {interface.ip}")
            print(f"  MAC:  {interface.mac}")
            print(f"  Net:  {interface.network}")
